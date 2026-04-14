package sanitizer

import (
	"bytes"
	"context"
	"encoding/binary"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"testing"
)

// makeTestJPEG creates a minimal valid JPEG with no metadata.
func makeTestJPEG() []byte {
	img := image.NewRGBA(image.Rect(0, 0, 10, 10))
	for y := 0; y < 10; y++ {
		for x := 0; x < 10; x++ {
			img.Set(x, y, color.RGBA{R: uint8(x * 25), G: uint8(y * 25), B: 128, A: 255})
		}
	}
	var buf bytes.Buffer
	_ = jpeg.Encode(&buf, img, &jpeg.Options{Quality: 90})
	return buf.Bytes()
}

// makeTestPNG creates a minimal valid PNG with no metadata.
func makeTestPNG() []byte {
	img := image.NewRGBA(image.Rect(0, 0, 10, 10))
	for y := 0; y < 10; y++ {
		for x := 0; x < 10; x++ {
			img.Set(x, y, color.RGBA{R: uint8(x * 25), G: uint8(y * 25), B: 128, A: 255})
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

// makeTestGIF creates a minimal valid GIF with no metadata.
func makeTestGIF() []byte {
	img := image.NewPaletted(image.Rect(0, 0, 10, 10), color.Palette{color.White, color.Black})
	var buf bytes.Buffer
	_ = gif.Encode(&buf, img, nil)
	return buf.Bytes()
}

// injectJPEGMarker inserts a JPEG marker segment right after the SOI (FF D8).
func injectJPEGMarker(jpegData []byte, marker byte, payload []byte) []byte {
	// JPEG starts with FF D8. Insert marker segment right after.
	segLen := uint16(len(payload) + 2) // +2 for the length field itself
	var seg bytes.Buffer
	seg.Write([]byte{0xFF, marker})
	_ = binary.Write(&seg, binary.BigEndian, segLen)
	seg.Write(payload)

	var result bytes.Buffer
	result.Write(jpegData[:2]) // FF D8
	result.Write(seg.Bytes())
	result.Write(jpegData[2:]) // rest of JPEG
	return result.Bytes()
}

func TestImageSanitizer_SupportedTypes(t *testing.T) {
	s := NewImageSanitizer(testLogger())
	types := s.SupportedTypes()

	expected := map[FileType]bool{
		FileTypeJPEG: false,
		FileTypePNG:  false,
		FileTypeGIF:  false,
	}

	if len(types) != len(expected) {
		t.Fatalf("expected %d supported types, got %d", len(expected), len(types))
	}

	for _, ft := range types {
		if _, ok := expected[ft]; !ok {
			t.Errorf("unexpected supported type: %s", ft)
		}
		expected[ft] = true
	}

	for ft, found := range expected {
		if !found {
			t.Errorf("missing expected supported type: %s", ft)
		}
	}
}

func TestImageSanitizer_CleanJPEG(t *testing.T) {
	s := NewImageSanitizer(testLogger())
	data := makeTestJPEG()

	result, err := s.Sanitize(context.Background(), data, "clean.jpg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusClean {
		t.Errorf("expected StatusClean, got %d", result.Status)
	}
	if len(result.SanitizedData) == 0 {
		t.Fatal("sanitized data is empty")
	}
	// Verify the output is valid JPEG by checking magic bytes.
	if !bytes.HasPrefix(result.SanitizedData, []byte{0xFF, 0xD8, 0xFF}) {
		t.Error("sanitized output does not start with JPEG magic bytes")
	}
	if len(result.Threats) != 0 {
		t.Errorf("expected no threats for clean JPEG, got %d", len(result.Threats))
	}
}

func TestImageSanitizer_JPEGWithEXIF(t *testing.T) {
	s := NewImageSanitizer(testLogger())
	base := makeTestJPEG()

	// Build an EXIF payload: "Exif\x00\x00" followed by some dummy TIFF data.
	exifPayload := append([]byte("Exif\x00\x00"), []byte("II*\x00dummy exif data here")...)
	data := injectJPEGMarker(base, 0xE1, exifPayload)

	result, err := s.Sanitize(context.Background(), data, "exif.jpg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusSanitized {
		t.Errorf("expected StatusSanitized, got %d", result.Status)
	}

	foundEXIF := false
	for _, threat := range result.Threats {
		if threat.Type == "exif" {
			foundEXIF = true
		}
	}
	if !foundEXIF {
		t.Error("expected 'exif' threat to be detected")
	}
}

func TestImageSanitizer_JPEGWithGPS(t *testing.T) {
	s := NewImageSanitizer(testLogger())
	base := makeTestJPEG()

	// Build EXIF payload with GPS tag bytes (0x88, 0x25) embedded in the data.
	exifPayload := append([]byte("Exif\x00\x00"), []byte("II*\x00")...)
	exifPayload = append(exifPayload, 0x88, 0x25) // GPS IFD pointer tag (big-endian)
	exifPayload = append(exifPayload, []byte("more dummy data")...)
	data := injectJPEGMarker(base, 0xE1, exifPayload)

	result, err := s.Sanitize(context.Background(), data, "gps.jpg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusSanitized {
		t.Errorf("expected StatusSanitized, got %d", result.Status)
	}

	foundEXIF := false
	foundGPS := false
	for _, threat := range result.Threats {
		if threat.Type == "exif" {
			foundEXIF = true
		}
		if threat.Type == "gps_location" {
			foundGPS = true
		}
	}
	if !foundEXIF {
		t.Error("expected 'exif' threat to be detected")
	}
	if !foundGPS {
		t.Error("expected 'gps_location' threat to be detected")
	}
}

func TestImageSanitizer_JPEGWithComment(t *testing.T) {
	s := NewImageSanitizer(testLogger())
	base := makeTestJPEG()

	// Inject a COM marker (0xFE) with a comment payload.
	commentPayload := []byte("This is a secret comment")
	data := injectJPEGMarker(base, 0xFE, commentPayload)

	result, err := s.Sanitize(context.Background(), data, "comment.jpg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusSanitized {
		t.Errorf("expected StatusSanitized, got %d", result.Status)
	}

	foundComment := false
	for _, threat := range result.Threats {
		if threat.Type == "comment" {
			foundComment = true
		}
	}
	if !foundComment {
		t.Error("expected 'comment' threat to be detected")
	}
}

func TestImageSanitizer_CleanPNG(t *testing.T) {
	s := NewImageSanitizer(testLogger())
	data := makeTestPNG()

	result, err := s.Sanitize(context.Background(), data, "clean.png")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusClean {
		t.Errorf("expected StatusClean, got %d", result.Status)
	}
	if len(result.SanitizedData) == 0 {
		t.Fatal("sanitized data is empty")
	}
	// Verify PNG signature in output.
	pngSig := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	if !bytes.HasPrefix(result.SanitizedData, pngSig) {
		t.Error("sanitized output does not start with PNG signature")
	}
	if len(result.Threats) != 0 {
		t.Errorf("expected no threats for clean PNG, got %d", len(result.Threats))
	}
}

func TestImageSanitizer_PNGWithTextChunk(t *testing.T) {
	s := NewImageSanitizer(testLogger())
	base := makeTestPNG()

	// Inject a tEXt chunk before the IEND chunk. PNG chunk format:
	// [4-byte big-endian length][4-byte type][data][4-byte CRC]
	// The IEND chunk is the last 12 bytes of a valid PNG (length=0, "IEND", CRC).
	textKey := []byte("Comment\x00This is metadata")
	chunkType := []byte("tEXt")

	var chunk bytes.Buffer
	_ = binary.Write(&chunk, binary.BigEndian, uint32(len(textKey)))
	chunk.Write(chunkType)
	chunk.Write(textKey)
	// CRC covers chunk type + data. Use a dummy CRC; the Go PNG decoder
	// will still parse the image data before this chunk, and the sanitizer
	// scans raw bytes for chunk types independently.
	// Compute a simple CRC32 for correctness.
	crc := crc32PNG(chunkType, textKey)
	_ = binary.Write(&chunk, binary.BigEndian, crc)

	// Insert the tEXt chunk just before IEND (last 12 bytes).
	iendOffset := len(base) - 12
	var modified bytes.Buffer
	modified.Write(base[:iendOffset])
	modified.Write(chunk.Bytes())
	modified.Write(base[iendOffset:])

	data := modified.Bytes()

	result, err := s.Sanitize(context.Background(), data, "text.png")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusSanitized {
		t.Errorf("expected StatusSanitized, got %d", result.Status)
	}

	foundText := false
	for _, threat := range result.Threats {
		if threat.Type == "text_metadata" {
			foundText = true
		}
	}
	if !foundText {
		t.Error("expected 'text_metadata' threat to be detected")
	}
}

// crc32PNG computes the CRC32 used in PNG chunks (over type + data).
func crc32PNG(chunkType, data []byte) uint32 {
	// PNG uses CRC-32 with the standard polynomial.
	// Use a simple table-based implementation.
	crc := uint32(0xFFFFFFFF)
	table := makeCRC32Table()
	for _, b := range chunkType {
		crc = table[(crc^uint32(b))&0xFF] ^ (crc >> 8)
	}
	for _, b := range data {
		crc = table[(crc^uint32(b))&0xFF] ^ (crc >> 8)
	}
	return crc ^ 0xFFFFFFFF
}

func makeCRC32Table() [256]uint32 {
	var table [256]uint32
	for i := 0; i < 256; i++ {
		c := uint32(i)
		for j := 0; j < 8; j++ {
			if c&1 != 0 {
				c = 0xEDB88320 ^ (c >> 1)
			} else {
				c >>= 1
			}
		}
		table[i] = c
	}
	return table
}

func TestImageSanitizer_CleanGIF(t *testing.T) {
	s := NewImageSanitizer(testLogger())
	data := makeTestGIF()

	result, err := s.Sanitize(context.Background(), data, "clean.gif")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusClean {
		t.Errorf("expected StatusClean, got %d", result.Status)
	}
	if len(result.SanitizedData) == 0 {
		t.Fatal("sanitized data is empty")
	}
	// Verify GIF signature in output.
	if !bytes.HasPrefix(result.SanitizedData, []byte("GIF")) {
		t.Error("sanitized output does not start with GIF signature")
	}
	if len(result.Threats) != 0 {
		t.Errorf("expected no threats for clean GIF, got %d", len(result.Threats))
	}
}

func TestImageSanitizer_EmptyFile(t *testing.T) {
	s := NewImageSanitizer(testLogger())

	result, err := s.Sanitize(context.Background(), []byte{}, "empty.jpg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusError {
		t.Errorf("expected StatusError, got %d", result.Status)
	}
	if result.Error == nil {
		t.Error("expected a non-nil Result.Error for empty input")
	}
}

func TestImageSanitizer_InvalidData(t *testing.T) {
	s := NewImageSanitizer(testLogger())

	// Random bytes that are not a valid image.
	garbage := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}

	result, err := s.Sanitize(context.Background(), garbage, "garbage.jpg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusError {
		t.Errorf("expected StatusError, got %d", result.Status)
	}
	if result.Error == nil {
		t.Error("expected a non-nil Result.Error for invalid data")
	}
}

func TestImageSanitizer_ContextCancellation(t *testing.T) {
	s := NewImageSanitizer(testLogger())
	data := makeTestJPEG()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := s.Sanitize(ctx, data, "cancelled.jpg")
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

func TestImageSanitizer_ReEncodedIsValid(t *testing.T) {
	s := NewImageSanitizer(testLogger())

	// Start with a JPEG that has EXIF metadata so it goes through sanitization.
	base := makeTestJPEG()
	exifPayload := append([]byte("Exif\x00\x00"), []byte("II*\x00dummy exif data")...)
	data := injectJPEGMarker(base, 0xE1, exifPayload)

	result, err := s.Sanitize(context.Background(), data, "reencode.jpg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusSanitized {
		t.Errorf("expected StatusSanitized, got %d", result.Status)
	}

	// Verify the re-encoded output is a valid JPEG by decoding it.
	_, format, decErr := image.Decode(bytes.NewReader(result.SanitizedData))
	if decErr != nil {
		t.Fatalf("failed to decode sanitized JPEG: %v", decErr)
	}
	if format != "jpeg" {
		t.Errorf("expected format 'jpeg', got %q", format)
	}
}

func TestImageSanitizer_OutputSmallerWhenMetadataStripped(t *testing.T) {
	s := NewImageSanitizer(testLogger())

	base := makeTestJPEG()

	// Inject a large EXIF block so the input is definitely bigger.
	bigPayload := make([]byte, 4096)
	copy(bigPayload, []byte("Exif\x00\x00II*\x00"))
	for i := 10; i < len(bigPayload); i++ {
		bigPayload[i] = byte(i % 256)
	}
	data := injectJPEGMarker(base, 0xE1, bigPayload)

	result, err := s.Sanitize(context.Background(), data, "big_exif.jpg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != StatusSanitized {
		t.Errorf("expected StatusSanitized, got %d", result.Status)
	}
	if result.SanitizedSize >= result.OriginalSize {
		t.Errorf("expected sanitized output (%d bytes) to be smaller than input (%d bytes)",
			result.SanitizedSize, result.OriginalSize)
	}
}

func FuzzImageSanitizer(f *testing.F) {
	// Seed the corpus with valid images and edge cases.
	f.Add(makeTestJPEG())
	f.Add(makeTestPNG())
	f.Add(makeTestGIF())
	f.Add([]byte{})
	f.Add([]byte{0xFF, 0xD8, 0xFF})
	f.Add([]byte{0x89, 0x50, 0x4E, 0x47})

	s := NewImageSanitizer(testLogger())

	f.Fuzz(func(t *testing.T, data []byte) {
		// The sanitizer must never panic on arbitrary input.
		_, _ = s.Sanitize(context.Background(), data, "fuzz.bin")
	})
}
