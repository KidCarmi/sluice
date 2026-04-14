package sanitizer

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"log/slog"
)

// maxImageSize is the maximum number of bytes we read from an image. 50 MB.
const maxImageSize = 50 * 1024 * 1024

// ImageSanitizer strips metadata and embedded payloads from images by
// decoding them to raw pixels and re-encoding. This destroys all EXIF,
// XMP, ICC profiles, comments, steganographic payloads, and any other
// non-pixel data.
type ImageSanitizer struct {
	logger *slog.Logger
}

// NewImageSanitizer creates a new ImageSanitizer.
func NewImageSanitizer(logger *slog.Logger) *ImageSanitizer {
	return &ImageSanitizer{logger: logger}
}

// SupportedTypes returns the image types this sanitizer handles.
func (s *ImageSanitizer) SupportedTypes() []FileType {
	return []FileType{FileTypeJPEG, FileTypePNG, FileTypeGIF}
}

// Sanitize decodes the image to raw pixels, scans for metadata threats,
// then re-encodes a clean version with no metadata.
func (s *ImageSanitizer) Sanitize(ctx context.Context, data []byte, filename string) (*Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("image sanitize: %w", err)
	}

	ft := DetectType(data, filename)
	result := &Result{
		OriginalType: ft,
		OriginalSize: int64(len(data)),
	}

	if len(data) == 0 {
		result.Status = StatusError
		result.Error = fmt.Errorf("empty file")
		return result, nil
	}

	// Scan for metadata threats before re-encoding (for reporting).
	threats := s.scanThreats(data, ft)

	// Decode image to raw pixels. This strips ALL metadata.
	reader := io.LimitReader(bytes.NewReader(data), maxImageSize)
	img, format, err := image.Decode(reader)
	if err != nil {
		result.Status = StatusError
		result.Error = fmt.Errorf("decoding %s image: %w", ft, err)
		return result, nil
	}

	bounds := img.Bounds()
	pixelCount := int64(bounds.Dx()) * int64(bounds.Dy())
	const maxPixels = 100_000_000 // 100 megapixels
	if pixelCount > maxPixels {
		result.Status = StatusError
		result.Error = fmt.Errorf("decoded image exceeds pixel limit (%d pixels, max %d)", pixelCount, maxPixels)
		return result, nil
	}

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("image sanitize: %w", err)
	}

	// Re-encode the image — produces a clean file with only pixel data.
	var buf bytes.Buffer
	switch format {
	case "jpeg":
		err = jpeg.Encode(&buf, img, &jpeg.Options{Quality: 95})
	case "png":
		err = png.Encode(&buf, img)
	case "gif":
		err = gif.Encode(&buf, img, nil)
	default:
		result.Status = StatusError
		result.Error = fmt.Errorf("unsupported image format for re-encoding: %s", format)
		return result, nil
	}
	if err != nil {
		result.Status = StatusError
		result.Error = fmt.Errorf("re-encoding %s image: %w", format, err)
		return result, nil
	}

	if int64(buf.Len()) > maxImageSize {
		result.Status = StatusError
		result.Error = fmt.Errorf("re-encoded image exceeds maximum size (%d bytes)", buf.Len())
		return result, nil
	}

	result.SanitizedData = buf.Bytes()
	result.SanitizedSize = int64(len(result.SanitizedData))
	result.Threats = threats

	if len(threats) > 0 {
		result.Status = StatusSanitized
		s.logger.Info("image sanitized",
			"filename", filename,
			"type", ft,
			"threats", len(threats),
			"original_size", result.OriginalSize,
			"sanitized_size", result.SanitizedSize,
		)
	} else {
		// Even with no detected metadata, we still re-encoded to be safe.
		// But report as clean since nothing suspicious was found.
		result.Status = StatusClean
	}

	return result, nil
}

// scanThreats inspects raw image bytes for metadata that will be stripped
// during re-encoding. This is purely for reporting — the re-encode removes
// everything regardless.
func (s *ImageSanitizer) scanThreats(data []byte, ft FileType) []Threat {
	switch ft {
	case FileTypeJPEG:
		return s.scanJPEGThreats(data)
	case FileTypePNG:
		return s.scanPNGThreats(data)
	case FileTypeGIF:
		return s.scanGIFThreats(data)
	default:
		return nil
	}
}

// scanJPEGThreats scans JPEG markers for EXIF, XMP, and other APP segments.
// JPEG structure: FF D8 (SOI), then marker segments FF xx (length) (data).
func (s *ImageSanitizer) scanJPEGThreats(data []byte) []Threat {
	var threats []Threat
	if len(data) < 4 {
		return nil
	}

	i := 2 // skip FF D8 (SOI)
	for i+3 < len(data) {
		if data[i] != 0xFF {
			break
		}
		marker := data[i+1]

		// Markers without length (standalone markers)
		if marker == 0xD8 || marker == 0xD9 || (marker >= 0xD0 && marker <= 0xD7) {
			i += 2
			continue
		}

		// SOS (Start of Scan) — image data follows, stop scanning markers.
		if marker == 0xDA {
			break
		}

		if i+4 > len(data) {
			break
		}
		segLen := int(binary.BigEndian.Uint16(data[i+2 : i+4]))
		if segLen < 2 {
			break
		}
		segStart := i + 4
		segEnd := i + 2 + segLen
		if segEnd > len(data) {
			break
		}

		switch {
		case marker == 0xE1: // APP1 — EXIF or XMP
			if segEnd-segStart >= 6 && string(data[segStart:segStart+4]) == "Exif" {
				threats = append(threats, Threat{
					Type:        "exif",
					Location:    fmt.Sprintf("APP1 marker at offset %d", i),
					Description: "EXIF metadata stripped (may contain GPS, device info, timestamps)",
					Severity:    "medium",
				})
				// Check for GPS data specifically
				if containsGPS(data[segStart:segEnd]) {
					threats = append(threats, Threat{
						Type:        "gps_location",
						Location:    fmt.Sprintf("EXIF GPS data at offset %d", i),
						Description: "GPS geolocation coordinates stripped",
						Severity:    "high",
					})
				}
			} else if segEnd-segStart >= 29 && bytes.Contains(data[segStart:segEnd], []byte("http://ns.adobe.com/xap/")) {
				threats = append(threats, Threat{
					Type:        "xmp",
					Location:    fmt.Sprintf("APP1 XMP marker at offset %d", i),
					Description: "XMP metadata stripped (Adobe extensible metadata)",
					Severity:    "low",
				})
			}
		case marker == 0xE0: // APP0 — JFIF (benign, but noting)
			// JFIF is standard, not a threat
		case marker >= 0xE2 && marker <= 0xEF: // APP2-APP15
			threats = append(threats, Threat{
				Type:        "app_marker",
				Location:    fmt.Sprintf("APP%d marker at offset %d", marker-0xE0, i),
				Description: fmt.Sprintf("APP%d application marker stripped", marker-0xE0),
				Severity:    "low",
			})
		case marker == 0xFE: // COM — Comment
			threats = append(threats, Threat{
				Type:        "comment",
				Location:    fmt.Sprintf("COM marker at offset %d", i),
				Description: "JPEG comment stripped",
				Severity:    "low",
			})
		}

		i = segEnd
	}

	return threats
}

// containsGPS checks if EXIF data contains GPS IFD tags. Looks for the GPS
// IFD pointer tag (0x8825) in the TIFF header.
func containsGPS(exifData []byte) bool {
	// GPS tag IDs in big-endian and little-endian
	gpsTagBE := []byte{0x88, 0x25}
	gpsTagLE := []byte{0x25, 0x88}
	return bytes.Contains(exifData, gpsTagBE) || bytes.Contains(exifData, gpsTagLE)
}

// scanPNGThreats scans PNG chunks for metadata. PNG structure:
// 8-byte signature, then chunks: [4-byte length][4-byte type][data][4-byte CRC]
func (s *ImageSanitizer) scanPNGThreats(data []byte) []Threat {
	var threats []Threat
	if len(data) < 8 {
		return nil
	}

	i := 8 // skip PNG signature
	for i+8 <= len(data) {
		chunkLen := int(binary.BigEndian.Uint32(data[i : i+4]))
		chunkType := string(data[i+4 : i+8])

		// Protect against corrupt chunk lengths
		if chunkLen < 0 || i+12+chunkLen > len(data) {
			break
		}

		switch chunkType {
		case "tEXt", "zTXt", "iTXt":
			threats = append(threats, Threat{
				Type:        "text_metadata",
				Location:    fmt.Sprintf("%s chunk at offset %d", chunkType, i),
				Description: fmt.Sprintf("%s text metadata chunk stripped", chunkType),
				Severity:    "low",
			})
		case "eXIf":
			threats = append(threats, Threat{
				Type:        "exif",
				Location:    fmt.Sprintf("eXIf chunk at offset %d", i),
				Description: "EXIF metadata stripped from PNG",
				Severity:    "medium",
			})
		case "iCCP":
			threats = append(threats, Threat{
				Type:        "icc_profile",
				Location:    fmt.Sprintf("iCCP chunk at offset %d", i),
				Description: "ICC color profile stripped (can contain embedded payloads)",
				Severity:    "low",
			})
		case "tIME":
			threats = append(threats, Threat{
				Type:        "timestamp",
				Location:    fmt.Sprintf("tIME chunk at offset %d", i),
				Description: "Modification timestamp stripped",
				Severity:    "low",
			})
		}

		// Move to next chunk: 4 (length) + 4 (type) + data + 4 (CRC)
		i += 12 + chunkLen
	}

	return threats
}

// scanGIFThreats scans GIF for comment extensions and application extensions.
func (s *ImageSanitizer) scanGIFThreats(data []byte) []Threat {
	var threats []Threat
	if len(data) < 13 {
		return nil
	}

	// Scan for extension blocks. GIF extensions start with 0x21.
	for i := 13; i+1 < len(data); i++ {
		if data[i] != 0x21 {
			continue
		}
		switch data[i+1] {
		case 0xFE: // Comment extension
			threats = append(threats, Threat{
				Type:        "comment",
				Location:    fmt.Sprintf("comment extension at offset %d", i),
				Description: "GIF comment extension stripped",
				Severity:    "low",
			})
		case 0xFF: // Application extension
			if i+14 < len(data) {
				appID := string(data[i+3 : i+11])
				threats = append(threats, Threat{
					Type:        "app_extension",
					Location:    fmt.Sprintf("application extension '%s' at offset %d", appID, i),
					Description: fmt.Sprintf("GIF application extension '%s' stripped", appID),
					Severity:    "low",
				})
			}
		}
	}

	return threats
}
