package testdata_test

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"os"
	"testing"
)

// TestGenerateImageTestData creates image test files with embedded metadata.
// Run with: go test -run TestGenerateImageTestData ./testdata/ -v
func TestGenerateImageTestData(t *testing.T) {
	t.Run("exif.jpg", func(t *testing.T) {
		// Create a JPEG with EXIF metadata (including GPS tag)
		img := makeColorImage()
		var buf bytes.Buffer
		if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 90}); err != nil {
			t.Fatal(err)
		}
		jpegData := buf.Bytes()

		// Build a fake EXIF APP1 segment with GPS tag marker
		exifPayload := buildFakeEXIF()
		data := injectJPEGMarker(jpegData, 0xE1, exifPayload)

		// Also inject a comment
		comment := []byte("Secret metadata: do not distribute")
		data = injectJPEGMarker(data, 0xFE, comment)

		writeImageFile(t, "exif.jpg", data)
	})

	t.Run("clean.png", func(t *testing.T) {
		img := makeColorImage()
		var buf bytes.Buffer
		if err := png.Encode(&buf, img); err != nil {
			t.Fatal(err)
		}
		writeImageFile(t, "clean.png", buf.Bytes())
	})
}

func makeColorImage() image.Image {
	img := image.NewRGBA(image.Rect(0, 0, 100, 100))
	for y := 0; y < 100; y++ {
		for x := 0; x < 100; x++ {
			img.Set(x, y, color.RGBA{
				R: uint8(x * 2),
				G: uint8(y * 2),
				B: uint8((x + y) % 256),
				A: 255,
			})
		}
	}
	return img
}

func buildFakeEXIF() []byte {
	var buf bytes.Buffer
	// EXIF header
	buf.WriteString("Exif\x00\x00")
	// TIFF header (little-endian)
	buf.Write([]byte("II"))                       // little-endian
	_ = binary.Write(&buf, binary.LittleEndian, uint16(42)) // TIFF magic
	_ = binary.Write(&buf, binary.LittleEndian, uint32(8))  // offset to IFD0
	// Fake IFD0 with GPS pointer tag
	_ = binary.Write(&buf, binary.LittleEndian, uint16(1))    // 1 entry
	_ = binary.Write(&buf, binary.LittleEndian, uint16(0x8825)) // GPS IFD tag
	_ = binary.Write(&buf, binary.LittleEndian, uint16(4))    // LONG type
	_ = binary.Write(&buf, binary.LittleEndian, uint32(1))    // count
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))    // value (offset)
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))    // next IFD
	return buf.Bytes()
}

func injectJPEGMarker(jpegData []byte, marker byte, payload []byte) []byte {
	segLen := uint16(len(payload) + 2)
	var seg bytes.Buffer
	seg.Write([]byte{0xFF, marker})
	_ = binary.Write(&seg, binary.BigEndian, segLen)
	seg.Write(payload)

	var result bytes.Buffer
	result.Write(jpegData[:2]) // FF D8 (SOI)
	result.Write(seg.Bytes())
	result.Write(jpegData[2:]) // rest of JPEG
	return result.Bytes()
}

func writeImageFile(t *testing.T, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(name, data, 0644); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	t.Logf("wrote %s (%d bytes)", name, len(data))
}
