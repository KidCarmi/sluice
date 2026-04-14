package server

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/KidCarmi/Sluice/internal/auth"
	"github.com/KidCarmi/Sluice/internal/sanitizer"
	"github.com/KidCarmi/Sluice/internal/worker"
	pb "github.com/KidCarmi/Sluice/proto/sluicev1"
)

// newTestServer wires up a server backed by an in-process bufconn listener.
// Returns a client and a teardown function.
func newTestServer(t *testing.T) (pb.SluiceServiceClient, *Server, func()) {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	dispatcher := sanitizer.NewDispatcher()
	dispatcher.Register(sanitizer.NewOfficeSanitizer(logger))
	dispatcher.Register(sanitizer.NewPDFSanitizer(logger))
	dispatcher.Register(sanitizer.NewImageSanitizer(logger))
	dispatcher.Register(sanitizer.NewSVGSanitizer(logger))
	dispatcher.Register(sanitizer.NewArchiveSanitizer(dispatcher, logger))

	pool := worker.NewPool(worker.PoolConfig{
		MaxWorkers: 4,
		QueueDepth: 8,
		JobTimeout: 10 * time.Second,
	}, func(ctx context.Context, job worker.Job) (interface{}, error) {
		return dispatcher.Dispatch(ctx, job.Data, job.Filename)
	})

	enroller, err := auth.NewEnrollmentManager(nil, nil, logger)
	if err != nil {
		t.Fatalf("enroller: %v", err)
	}

	srv := New(dispatcher, pool, enroller, logger, "test", 50*1024*1024, "127.0.0.1:8443")

	lis := bufconn.Listen(1024 * 1024)
	grpcSrv := grpc.NewServer()
	pb.RegisterSluiceServiceServer(grpcSrv, srv)

	go func() {
		_ = grpcSrv.Serve(lis)
	}()

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc client: %v", err)
	}

	client := pb.NewSluiceServiceClient(conn)
	teardown := func() {
		_ = conn.Close()
		grpcSrv.Stop()
		pool.Stop()
	}
	return client, srv, teardown
}

// makeCleanPDF returns a tiny but syntactically valid PDF with no threats.
func makeCleanPDF() []byte {
	return []byte("%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 1\ntrailer\n<< /Root 1 0 R >>\nstartxref\n0\n%%EOF")
}

// makeDocxWithMacro returns a minimal OOXML DOCX containing a macro entry.
func makeDocxWithMacro() []byte {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	files := map[string]string{
		"[Content_Types].xml":  `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/></Types>`,
		"_rels/.rels":          `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`,
		"word/document.xml":    `<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Hi</w:t></w:r></w:p></w:body></w:document>`,
		"word/vbaProject.bin":  "FAKE_MACRO",
	}
	for name, content := range files {
		f, _ := w.Create(name)
		_, _ = f.Write([]byte(content))
	}
	_ = w.Close()
	return buf.Bytes()
}

// streamUpload is a small helper that sends a header + chunks and returns the
// final result plus concatenated output bytes.
func streamUpload(t *testing.T, client pb.SluiceServiceClient, hdr *pb.SanitizeHeader, data []byte) (*pb.SanitizeResult, []byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := client.Sanitize(ctx)
	if err != nil {
		return nil, nil, err
	}
	if err := stream.Send(&pb.SanitizeRequest{Payload: &pb.SanitizeRequest_Header{Header: hdr}}); err != nil {
		return nil, nil, err
	}

	// Send in 32 KB pieces to exercise streaming.
	const piece = 32 * 1024
	for off := 0; off < len(data); off += piece {
		end := off + piece
		if end > len(data) {
			end = len(data)
		}
		if err := stream.Send(&pb.SanitizeRequest{Payload: &pb.SanitizeRequest_Chunk{Chunk: data[off:end]}}); err != nil {
			return nil, nil, err
		}
	}
	if err := stream.CloseSend(); err != nil {
		return nil, nil, err
	}

	// Result must be first message.
	first, err := stream.Recv()
	if err != nil {
		return nil, nil, err
	}
	result := first.GetResult()
	if result == nil {
		t.Fatalf("expected Result as first message, got %T", first.GetPayload())
	}

	var out bytes.Buffer
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return result, out.Bytes(), err
		}
		if r := msg.GetResult(); r != nil {
			t.Fatalf("unexpected Result after chunks started")
		}
		if c := msg.GetChunk(); c != nil {
			out.Write(c)
		}
	}
	return result, out.Bytes(), nil
}

func TestSanitize_CleanPDF_Streaming(t *testing.T) {
	client, _, done := newTestServer(t)
	defer done()

	data := makeCleanPDF()
	hdr := &pb.SanitizeHeader{
		Filename:      "clean.pdf",
		ContentType:   "application/pdf",
		ContentLength: int64(len(data)),
		RequestId:     "test-1",
		Mode:          pb.Mode_ENFORCE,
	}
	result, out, err := streamUpload(t, client, hdr, data)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	if result.Status != pb.Status_CLEAN {
		t.Errorf("expected CLEAN, got %v", result.Status)
	}
	if !bytes.Equal(out, data) {
		t.Errorf("expected clean bytes echoed, got len=%d", len(out))
	}
	sum := sha256.Sum256(data)
	if !bytes.Equal(result.SanitizedSha256, sum[:]) {
		t.Errorf("sanitized_sha256 mismatch")
	}
	if result.DurationMs < 0 {
		t.Errorf("duration_ms must be >= 0, got %d", result.DurationMs)
	}
}

func TestSanitize_DocxWithMacro_Sanitized(t *testing.T) {
	client, _, done := newTestServer(t)
	defer done()

	data := makeDocxWithMacro()
	hdr := &pb.SanitizeHeader{
		Filename:      "macro.docx",
		ContentLength: int64(len(data)),
		RequestId:     "test-2",
		Mode:          pb.Mode_ENFORCE,
	}
	result, out, err := streamUpload(t, client, hdr, data)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	if result.Status != pb.Status_SANITIZED {
		t.Errorf("expected SANITIZED, got %v", result.Status)
	}
	if len(result.ThreatsRemoved) == 0 {
		t.Errorf("expected threats, got 0")
	}
	// Verify every severity is in the allowed set.
	for _, th := range result.ThreatsRemoved {
		switch th.Severity {
		case "low", "medium", "high", "critical":
		default:
			t.Errorf("severity %q not in {low,medium,high,critical}", th.Severity)
		}
	}
	// Output should differ from input (macro was stripped).
	if bytes.Equal(out, data) {
		t.Errorf("expected sanitized bytes to differ from original")
	}
}

func TestSanitize_ReportOnly_ReturnsOriginalBytes(t *testing.T) {
	client, _, done := newTestServer(t)
	defer done()

	data := makeDocxWithMacro()
	hdr := &pb.SanitizeHeader{
		Filename:      "macro.docx",
		ContentLength: int64(len(data)),
		RequestId:     "test-3",
		Mode:          pb.Mode_REPORT_ONLY,
	}
	result, out, err := streamUpload(t, client, hdr, data)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	if len(result.ThreatsRemoved) == 0 {
		t.Errorf("expected threats detected, got 0")
	}
	if !bytes.Equal(out, data) {
		t.Errorf("REPORT_ONLY MUST return original bytes unchanged")
	}
	if result.OriginalSize != result.SanitizedSize {
		t.Errorf("REPORT_ONLY: original_size=%d sanitized_size=%d should match",
			result.OriginalSize, result.SanitizedSize)
	}
	sum := sha256.Sum256(data)
	if !bytes.Equal(result.SanitizedSha256, sum[:]) {
		t.Errorf("REPORT_ONLY: sanitized_sha256 must match original data hash")
	}
}

func TestSanitize_BypassWithReport_SameAsReportOnly(t *testing.T) {
	client, _, done := newTestServer(t)
	defer done()

	data := makeDocxWithMacro()
	hdr := &pb.SanitizeHeader{
		Filename:      "macro.docx",
		ContentLength: int64(len(data)),
		RequestId:     "test-4",
		Mode:          pb.Mode_BYPASS_WITH_REPORT,
	}
	_, out, err := streamUpload(t, client, hdr, data)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	if !bytes.Equal(out, data) {
		t.Errorf("BYPASS_WITH_REPORT must return original bytes unchanged")
	}
}

func TestSanitize_UnknownProfile_ReturnsError(t *testing.T) {
	client, _, done := newTestServer(t)
	defer done()

	data := makeCleanPDF()
	hdr := &pb.SanitizeHeader{
		Filename:      "x.pdf",
		ContentLength: int64(len(data)),
		ProfileName:   "nonexistent",
		Mode:          pb.Mode_ENFORCE,
	}
	// Send only header — we expect an early-reject result.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := client.Sanitize(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if err := stream.Send(&pb.SanitizeRequest{Payload: &pb.SanitizeRequest_Header{Header: hdr}}); err != nil {
		t.Fatalf("send header: %v", err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("close send: %v", err)
	}

	msg, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	result := msg.GetResult()
	if result == nil {
		t.Fatal("expected Result as first message")
	}
	if result.Status != pb.Status_ERROR {
		t.Errorf("expected ERROR, got %v", result.Status)
	}
	if result.ErrorMessage == "" || !bytes.Contains([]byte(result.ErrorMessage), []byte("unknown_profile")) {
		t.Errorf("expected error_message prefixed with unknown_profile:, got %q", result.ErrorMessage)
	}
}

func TestSanitize_EmptyProfile_TreatedAsDefault(t *testing.T) {
	client, _, done := newTestServer(t)
	defer done()

	data := makeCleanPDF()
	hdr := &pb.SanitizeHeader{
		Filename:      "x.pdf",
		ContentLength: int64(len(data)),
		ProfileName:   "", // empty -> default
		Mode:          pb.Mode_ENFORCE,
	}
	result, _, err := streamUpload(t, client, hdr, data)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	if result.Status == pb.Status_ERROR {
		t.Errorf("empty profile_name should be treated as 'default', got error: %s", result.ErrorMessage)
	}
}

func TestSanitize_ContentLengthExceeds_InvalidArgument(t *testing.T) {
	client, _, done := newTestServer(t)
	defer done()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := client.Sanitize(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	hdr := &pb.SanitizeHeader{
		Filename:      "huge.bin",
		ContentLength: 100 * 1024 * 1024, // 100MB > 50MB cap
		RequestId:     "test-huge",
	}
	if err := stream.Send(&pb.SanitizeRequest{Payload: &pb.SanitizeRequest_Header{Header: hdr}}); err != nil {
		t.Fatalf("send: %v", err)
	}
	_, err = stream.Recv()
	if err == nil {
		t.Fatal("expected error for oversize file")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument (NOT ResourceExhausted), got %v", st.Code())
	}
	if !bytes.Contains([]byte(st.Message()), []byte("file_too_large:")) {
		t.Errorf("expected message to start with 'file_too_large:', got %q", st.Message())
	}
}

func TestHealth_IncludesDefaultProfile(t *testing.T) {
	client, _, done := newTestServer(t)
	defer done()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := client.Health(ctx, &pb.HealthRequest{})
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	if !resp.Healthy {
		t.Errorf("expected healthy=true")
	}
	if len(resp.Profiles) != 1 {
		t.Fatalf("expected exactly 1 profile, got %d", len(resp.Profiles))
	}
	if resp.Profiles[0].Name != "default" {
		t.Errorf("expected default profile, got %q", resp.Profiles[0].Name)
	}
	if len(resp.Profiles[0].Capabilities) == 0 {
		t.Errorf("default profile must advertise capabilities")
	}
}

func TestEnroll_HappyPath(t *testing.T) {
	client, srv, done := newTestServer(t)
	defer done()

	token, err := srv.enroller.GenerateToken()
	if err != nil {
		t.Fatalf("gen token: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := client.Enroll(ctx, &pb.EnrollRequest{Token: token})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if len(resp.CaCert) == 0 || len(resp.ClientCert) == 0 || len(resp.ClientKey) == 0 {
		t.Fatalf("enroll response missing material")
	}
}

func TestEnroll_ConsumedToken_Fails(t *testing.T) {
	client, srv, done := newTestServer(t)
	defer done()

	token, _ := srv.enroller.GenerateToken()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := client.Enroll(ctx, &pb.EnrollRequest{Token: token}); err != nil {
		t.Fatalf("first enroll: %v", err)
	}
	_, err := client.Enroll(ctx, &pb.EnrollRequest{Token: token})
	if err == nil {
		t.Fatal("expected error on reused token")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.PermissionDenied {
		t.Errorf("expected PermissionDenied, got %v", st.Code())
	}
}

func TestEnroll_EmptyToken_Rejected(t *testing.T) {
	client, _, done := newTestServer(t)
	defer done()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := client.Enroll(ctx, &pb.EnrollRequest{Token: ""})
	if err == nil {
		t.Fatal("expected error for empty token")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument, got %v", st.Code())
	}
}

func TestSanitize_ResultIsFirstMessage(t *testing.T) {
	// Wire contract: result is ALWAYS the first SanitizeResponse, before any chunks.
	client, _, done := newTestServer(t)
	defer done()

	data := makeDocxWithMacro()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, _ := client.Sanitize(ctx)
	_ = stream.Send(&pb.SanitizeRequest{Payload: &pb.SanitizeRequest_Header{Header: &pb.SanitizeHeader{
		Filename: "m.docx", ContentLength: int64(len(data)), Mode: pb.Mode_ENFORCE,
	}}})
	// send data in one chunk
	_ = stream.Send(&pb.SanitizeRequest{Payload: &pb.SanitizeRequest_Chunk{Chunk: data}})
	_ = stream.CloseSend()

	first, err := stream.Recv()
	if err != nil {
		t.Fatalf("first recv: %v", err)
	}
	if first.GetResult() == nil {
		t.Errorf("first message must be Result, got chunk")
	}
	// subsequent messages must all be chunks
	for {
		m, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("recv: %v", err)
		}
		if m.GetResult() != nil {
			t.Errorf("result appeared after first message — must be atomic")
		}
	}
}
