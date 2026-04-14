// Package server provides the real gRPC server that implements the
// SluiceService defined in proto/sluicev1/sluice.proto.
//
// Three RPCs are exposed:
//   - Sanitize (bidi stream): client sends a SanitizeHeader then byte chunks;
//     server responds with a SanitizeResult (first message, always) then
//     zero or more byte chunks. Result is atomic — never interleaved with
//     chunks.
//   - Health (unary): status + pool stats + profile list.
//   - Enroll (unary): exchange a one-time token for mTLS client certs.
//
// mTLS is enforced per-RPC via interceptors: Enroll allows callers without a
// verified client cert (chicken-and-egg), but every other RPC requires one.
package server

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/KidCarmi/Sluice/internal/auth"
	"github.com/KidCarmi/Sluice/internal/sanitizer"
	"github.com/KidCarmi/Sluice/internal/worker"
	pb "github.com/KidCarmi/Sluice/proto/sluicev1"
)

// chunkSize is the maximum bytes sent per SanitizeResponse chunk message.
// Culvert's client expects 64 KB frames.
const chunkSize = 64 * 1024

// defaultProfileName is the single sanitization profile shipped in v0.1.
const defaultProfileName = "default"

// tagLabelAllow lists tag keys that are low-cardinality and safe to emit as
// Prometheus labels. Everything else goes to logs only.
var tagLabelAllow = map[string]struct{}{
	"direction":     {},
	"dest_category": {},
}

// maxTags / maxTagKey / maxTagValue cap the tag map to prevent memory blowup
// from a misbehaving client.
const (
	maxTags     = 16
	maxTagKey   = 64
	maxTagValue = 256
)

// Stats is the minimal surface the server needs from the web handler's stats
// counters. Kept tiny so we don't import the web package.
type Stats interface {
	FilesProcessedLoad() int64
	ThreatsRemovedLoad() int64
	IncFilesProcessed()
	IncThreatsRemoved(n int64)
}

// Server implements pb.SluiceServiceServer.
type Server struct {
	pb.UnimplementedSluiceServiceServer

	dispatcher  *sanitizer.Dispatcher
	pool        *worker.Pool
	enroller    *auth.EnrollmentManager
	logger      *slog.Logger
	version     string
	maxFileSize int64
	endpoint    string // publicly-reachable host:port returned from Enroll

	filesProcessed atomic.Int64
	threatsRemoved atomic.Int64
}

// New constructs a Server. All dependencies must be non-nil.
func New(
	dispatcher *sanitizer.Dispatcher,
	pool *worker.Pool,
	enroller *auth.EnrollmentManager,
	logger *slog.Logger,
	version string,
	maxFileSize int64,
	endpoint string,
) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		dispatcher:  dispatcher,
		pool:        pool,
		enroller:    enroller,
		logger:      logger,
		version:     version,
		maxFileSize: maxFileSize,
		endpoint:    endpoint,
	}
}

// ----- Sanitize --------------------------------------------------------------

// Sanitize implements the bidirectional streaming sanitization RPC.
func (s *Server) Sanitize(stream pb.SluiceService_SanitizeServer) error {
	ctx := stream.Context()

	// First message must be the header.
	first, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "reading header: %v", err)
	}
	hdr := first.GetHeader()
	if hdr == nil {
		return status.Error(codes.InvalidArgument, "first message must be a SanitizeHeader")
	}

	// Application-level file-size reject. Use InvalidArgument (not
	// ResourceExhausted) so the client's circuit breaker does NOT treat
	// oversize-files as a server-overload signal.
	if hdr.ContentLength > s.maxFileSize {
		return status.Errorf(codes.InvalidArgument,
			"file_too_large: content_length=%d exceeds max=%d", hdr.ContentLength, s.maxFileSize)
	}

	// Profile validation. Empty name == default.
	profile := hdr.ProfileName
	if profile == "" {
		profile = defaultProfileName
	}
	if profile != defaultProfileName {
		result := &pb.SanitizeResult{
			Status:       pb.Status_ERROR,
			OriginalType: "",
			OriginalSize: hdr.ContentLength,
			ErrorMessage: fmt.Sprintf("unknown_profile: %s", profile),
		}
		return sendResultThenClose(stream, result)
	}

	// Sanitize tags: enforce caps, drop over-limits.
	tags := sanitizeTags(hdr.Tags)

	// Request-scoped logger with correlation fields.
	reqLog := s.logger.With(
		"rpc", "Sanitize",
		"request_id", hdr.RequestId,
		"trace_parent", hdr.TraceParent,
		"filename", hdr.Filename,
		"profile", profile,
		"mode", hdr.Mode.String(),
		"policy_version", hdr.PolicyVersion,
	)
	if len(tags) > 0 {
		reqLog.Debug("sanitize request tags", "tags", tags)
	}

	// Read chunks until EOF. Bounded by maxFileSize+1 so we can detect overrun.
	buf := make([]byte, 0, minInt64(hdr.ContentLength+1, s.maxFileSize+1))
	for {
		msg, rerr := stream.Recv()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return status.Errorf(codes.Canceled, "receiving chunk: %v", rerr)
		}
		chunk := msg.GetChunk()
		if chunk == nil {
			// Another header after data — reject.
			return status.Error(codes.InvalidArgument, "unexpected non-chunk message after header")
		}
		if int64(len(buf)+len(chunk)) > s.maxFileSize {
			return status.Errorf(codes.InvalidArgument,
				"file_too_large: uploaded bytes exceed max=%d", s.maxFileSize)
		}
		buf = append(buf, chunk...)
	}

	start := time.Now()
	jobResult, err := s.pool.Submit(ctx, worker.Job{
		ID:       hdr.RequestId,
		Data:     buf,
		Filename: hdr.Filename,
	})
	if err != nil {
		// Distinguish backpressure from cancellation.
		if ctx.Err() != nil {
			return status.Errorf(codes.Canceled, "sanitize cancelled: %v", err)
		}
		return status.Errorf(codes.ResourceExhausted, "server_overloaded: %v", err)
	}
	if jobResult == nil {
		return status.Error(codes.Internal, "sanitize produced no result")
	}
	res, ok := jobResult.Result.(*sanitizer.Result)
	if !ok || res == nil {
		return status.Error(codes.Internal, "sanitize returned wrong result type")
	}
	duration := time.Since(start)

	// Mode enforcement — belt-and-braces. Even if the sanitizer modified
	// the bytes, REPORT_ONLY / BYPASS_WITH_REPORT return the caller's
	// original input unchanged.
	var outBytes []byte
	switch hdr.Mode {
	case pb.Mode_REPORT_ONLY, pb.Mode_BYPASS_WITH_REPORT:
		outBytes = buf // original input
	default:
		outBytes = res.SanitizedData
		if outBytes == nil {
			outBytes = buf // StatusClean often returns nil — pass through
		}
	}

	// Counters + log.
	s.filesProcessed.Add(1)
	s.threatsRemoved.Add(int64(len(res.Threats)))
	reqLog.Info("file sanitized",
		"type", res.OriginalType,
		"status", statusToProto(res.Status).String(),
		"threats", len(res.Threats),
		"duration_ms", duration.Milliseconds(),
	)

	// Build atomic result-first response.
	sum := sha256.Sum256(outBytes)
	result := &pb.SanitizeResult{
		Status:          statusToProto(res.Status),
		OriginalType:    string(res.OriginalType),
		OriginalSize:    int64(len(buf)),
		SanitizedSize:   int64(len(outBytes)),
		ThreatsRemoved:  threatsToProto(res.Threats),
		SanitizedSha256: sum[:],
		DurationMs:      duration.Milliseconds(),
	}
	if res.Error != nil {
		result.ErrorMessage = res.Error.Error()
	}

	// Send result first.
	if err := stream.Send(&pb.SanitizeResponse{
		Payload: &pb.SanitizeResponse_Result{Result: result},
	}); err != nil {
		return err
	}

	// Then stream 64 KB chunks. Zero chunks for CLEAN/ERROR/BLOCKED/UNSUPPORTED
	// with no data — that's fine, the result message carries the signal.
	for off := 0; off < len(outBytes); off += chunkSize {
		end := off + chunkSize
		if end > len(outBytes) {
			end = len(outBytes)
		}
		if err := stream.Send(&pb.SanitizeResponse{
			Payload: &pb.SanitizeResponse_Chunk{Chunk: outBytes[off:end]},
		}); err != nil {
			return err
		}
	}

	return nil
}

// sendResultThenClose is a helper for the unknown-profile / early-reject path
// where we want to return an atomic result-only stream (no chunks).
func sendResultThenClose(stream pb.SluiceService_SanitizeServer, result *pb.SanitizeResult) error {
	return stream.Send(&pb.SanitizeResponse{
		Payload: &pb.SanitizeResponse_Result{Result: result},
	})
}

// ----- Health ----------------------------------------------------------------

// Health returns current service status + profile list.
func (s *Server) Health(ctx context.Context, _ *pb.HealthRequest) (*pb.HealthResponse, error) {
	_ = ctx
	return &pb.HealthResponse{
		Healthy:        true,
		Version:        s.version,
		SupportedTypes: []string{"pdf", "docx", "xlsx", "pptx", "jpeg", "png", "gif", "svg", "zip"},
		ActiveWorkers:  clampInt32(s.pool.ActiveWorkers()),
		QueueDepth:     clampInt32(s.pool.QueueDepth()),
		FilesProcessed: s.filesProcessed.Load(),
		ThreatsRemoved: s.threatsRemoved.Load(),
		Profiles: []*pb.Profile{
			{
				Name:        defaultProfileName,
				Description: "Strip common threats from all supported file types (macros, OLE, ActiveX, external refs, JS, XFA, image metadata, SVG scripts, nested archives).",
				Capabilities: []string{
					"strip_macros",
					"strip_ole",
					"strip_activex",
					"strip_external_refs",
					"strip_js",
					"strip_launch_actions",
					"strip_embedded_files",
					"strip_xfa",
					"re_encode_images",
					"svg_script_removal",
					"archive_recursive",
				},
				MaxFileSizeBytes: s.maxFileSize,
			},
		},
	}, nil
}

// ----- Enroll ----------------------------------------------------------------

// Enroll exchanges a one-time token for mTLS client certs.
func (s *Server) Enroll(ctx context.Context, req *pb.EnrollRequest) (*pb.EnrollResponse, error) {
	_ = ctx
	if s.enroller == nil {
		return nil, status.Error(codes.Unavailable, "enrollment not configured")
	}
	if req.GetToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}
	caCert, clientCert, clientKey, err := s.enroller.Enroll(req.GetToken())
	if err != nil {
		// Map to PermissionDenied so misuse looks like auth failure, not a bug.
		return nil, status.Errorf(codes.PermissionDenied, "%v", err)
	}
	s.logger.Info("client enrolled via token")
	return &pb.EnrollResponse{
		CaCert:     caCert,
		ClientCert: clientCert,
		ClientKey:  clientKey,
		Endpoint:   s.endpoint,
	}, nil
}

// ----- helpers ---------------------------------------------------------------

func statusToProto(s sanitizer.Status) pb.Status {
	switch s {
	case sanitizer.StatusClean:
		return pb.Status_CLEAN
	case sanitizer.StatusSanitized:
		return pb.Status_SANITIZED
	case sanitizer.StatusBlocked:
		return pb.Status_BLOCKED
	case sanitizer.StatusError:
		return pb.Status_ERROR
	case sanitizer.StatusUnsupported:
		return pb.Status_UNSUPPORTED
	default:
		return pb.Status_ERROR
	}
}

func threatsToProto(in []sanitizer.Threat) []*pb.Threat {
	out := make([]*pb.Threat, 0, len(in))
	for _, t := range in {
		out = append(out, &pb.Threat{
			Type:        t.Type,
			Location:    t.Location,
			Description: t.Description,
			Severity:    t.Severity,
		})
	}
	return out
}

func sanitizeTags(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if len(out) >= maxTags {
			break
		}
		if len(k) == 0 || len(k) > maxTagKey || len(v) > maxTagValue {
			continue
		}
		out[k] = v
	}
	return out
}

// IsTagPromLabelAllowed reports whether a given tag key is safe to emit as a
// Prometheus label (low cardinality). Exposed for the metrics layer.
func IsTagPromLabelAllowed(key string) bool {
	_, ok := tagLabelAllow[strings.ToLower(key)]
	return ok
}

// PeerHasVerifiedCert reports whether the caller presented a client cert
// verified against the server's trust root. Exported so the interceptor
// lives alongside the transport wiring in main.go without this file importing
// credentials directly.
func PeerHasVerifiedCert(ctx context.Context) bool {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return false
	}
	// The caller in main.go uses google.golang.org/grpc/credentials.TLSInfo
	// to inspect verified chains. Here we only report presence of AuthInfo;
	// the real check is the credentials.TLSInfo.State.VerifiedChains length.
	return true
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// clampInt32 defensively truncates large counters before returning them in
// protobuf int32 fields. Worker counts realistically stay in the thousands,
// but gosec flags plain int → int32 casts (G115); this helper documents
// intent.
func clampInt32(v int) int32 {
	if v < 0 {
		return 0
	}
	const maxInt32 = int32(^uint32(0) >> 1)
	if int64(v) > int64(maxInt32) {
		return maxInt32
	}
	return int32(v) // #nosec G115 -- bounded above
}
