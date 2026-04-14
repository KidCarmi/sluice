package sanitizer

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"io"
	"log/slog"
	"testing"
)

// ---------------------------------------------------------------------------
// PDF benchmark helpers
// ---------------------------------------------------------------------------

func makeCleanPDF() []byte {
	return []byte("%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\ntrailer<</Size 4/Root 1 0 R>>\n%%EOF")
}

func makeThreatPDF() []byte {
	return []byte("%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R/OpenAction 4 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n4 0 obj<</S/JavaScript/JS(alert('xss'))/Launch/XFA 5 0 R>>endobj\ntrailer<</Size 5/Root 1 0 R>>\n%%EOF")
}

func makeLargePDF() []byte {
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n")
	// Pad with comment lines to reach ~1MB.
	line := "% padding padding padding padding padding padding padding padding\n"
	for buf.Len() < 1024*1024 {
		buf.WriteString(line)
	}
	buf.WriteString("trailer<</Size 4/Root 1 0 R>>\n%%EOF")
	return buf.Bytes()
}

// ---------------------------------------------------------------------------
// Office (DOCX) benchmark helpers
// ---------------------------------------------------------------------------

func benchmarkDocx(entries map[string]string) []byte {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range entries {
		f, _ := w.Create(name)
		_, _ = f.Write([]byte(content))
	}
	_ = w.Close()
	return buf.Bytes()
}

func makeCleanDocxBench() []byte {
	return benchmarkDocx(map[string]string{
		"[Content_Types].xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
</Types>`,
		"_rels/.rels": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`,
		"word/document.xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>Hello World</w:t></w:r></w:p></w:body>
</w:document>`,
	})
}

func makeMacroDocxBench() []byte {
	return benchmarkDocx(map[string]string{
		"[Content_Types].xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
</Types>`,
		"_rels/.rels": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`,
		"word/document.xml": `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>Macro Document</w:t></w:r></w:p></w:body>
</w:document>`,
		"word/vbaProject.bin": "FAKE_VBA_MACRO_BINARY_DATA_PAYLOAD",
	})
}

// ---------------------------------------------------------------------------
// Image benchmark helpers
// ---------------------------------------------------------------------------

func makeBenchJPEG(width, height int) []byte {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{
				R: uint8((x * 7) % 256),
				G: uint8((y * 13) % 256),
				B: uint8(((x + y) * 3) % 256),
				A: 255,
			})
		}
	}
	var buf bytes.Buffer
	_ = jpeg.Encode(&buf, img, &jpeg.Options{Quality: 90})
	return buf.Bytes()
}

func makeBenchPNGImage(width, height int) []byte {
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{
				R: uint8((x * 7) % 256),
				G: uint8((y * 13) % 256),
				B: uint8(((x + y) * 3) % 256),
				A: 255,
			})
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

// ---------------------------------------------------------------------------
// SVG benchmark helpers
// ---------------------------------------------------------------------------

func makeCleanSVG(elements int) []byte {
	var buf bytes.Buffer
	buf.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">`)
	for i := 0; i < elements; i++ {
		if i%2 == 0 {
			fmt.Fprintf(&buf, `<circle cx="%d" cy="%d" r="5" fill="red"/>`, i*10%500, i*7%500)
		} else {
			fmt.Fprintf(&buf, `<rect x="%d" y="%d" width="10" height="10" fill="blue"/>`, i*10%500, i*7%500)
		}
	}
	buf.WriteString(`</svg>`)
	return buf.Bytes()
}

func makeThreatSVG() []byte {
	return []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
  <circle cx="50" cy="50" r="40" fill="red" onclick="alert(1)"/>
  <rect x="10" y="10" width="30" height="30" fill="blue" onmouseover="evil()"/>
  <script>alert('xss')</script>
  <a href="javascript:alert(2)"><text>Click me</text></a>
  <circle cx="100" cy="100" r="20" fill="green"/>
</svg>`)
}

func makeLargeSVG(elements int) []byte {
	var buf bytes.Buffer
	buf.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" width="2000" height="2000">`)
	for i := 0; i < elements; i++ {
		fmt.Fprintf(&buf, `<circle cx="%d" cy="%d" r="5"/>`, i%2000, (i*3)%2000)
	}
	buf.WriteString(`</svg>`)
	return buf.Bytes()
}

// ---------------------------------------------------------------------------
// Archive benchmark helpers
// ---------------------------------------------------------------------------

func makeBenchZIPArchive(entries map[string][]byte) []byte {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, data := range entries {
		f, _ := w.Create(name)
		_, _ = f.Write(data)
	}
	_ = w.Close()
	return buf.Bytes()
}

func makeCleanZIPBench() []byte {
	entries := map[string][]byte{
		"file1.txt": []byte("Hello world from file 1"),
		"file2.txt": []byte("Hello world from file 2"),
		"file3.txt": []byte("Hello world from file 3"),
		"file4.txt": []byte("Hello world from file 4"),
		"file5.txt": []byte("Hello world from file 5"),
	}
	return makeBenchZIPArchive(entries)
}

func makeThreatZIPBench() []byte {
	// Create a DOCX with a macro to embed inside the ZIP.
	docxData := benchmarkDocx(map[string]string{
		"[Content_Types].xml": `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/></Types>`,
		"_rels/.rels":         `<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`,
		"word/document.xml":   `<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Macro</w:t></w:r></w:p></w:body></w:document>`,
		"word/vbaProject.bin": "FAKE_VBA_MACRO_DATA",
	})
	entries := map[string][]byte{
		"readme.txt": []byte("Archive with a macro document"),
		"macro.docx": docxData,
	}
	return makeBenchZIPArchive(entries)
}

// ---------------------------------------------------------------------------
// Shared benchmark logger
// ---------------------------------------------------------------------------

func benchLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ---------------------------------------------------------------------------
// PDF Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkPDFSanitize_Clean(b *testing.B) {
	logger := benchLogger()
	s := NewPDFSanitizer(logger)
	data := makeCleanPDF()
	ctx := context.Background()

	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = s.Sanitize(ctx, data, "bench.pdf")
	}
}

func BenchmarkPDFSanitize_WithThreats(b *testing.B) {
	logger := benchLogger()
	s := NewPDFSanitizer(logger)
	data := makeThreatPDF()
	ctx := context.Background()

	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = s.Sanitize(ctx, data, "bench.pdf")
	}
}

func BenchmarkPDFSanitize_Large(b *testing.B) {
	logger := benchLogger()
	s := NewPDFSanitizer(logger)
	data := makeLargePDF()
	ctx := context.Background()

	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = s.Sanitize(ctx, data, "bench.pdf")
	}
}

// ---------------------------------------------------------------------------
// Office Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkOfficeSanitize_CleanDocx(b *testing.B) {
	logger := benchLogger()
	s := NewOfficeSanitizer(logger)
	data := makeCleanDocxBench()
	ctx := context.Background()

	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = s.Sanitize(ctx, data, "bench.docx")
	}
}

func BenchmarkOfficeSanitize_WithMacro(b *testing.B) {
	logger := benchLogger()
	s := NewOfficeSanitizer(logger)
	data := makeMacroDocxBench()
	ctx := context.Background()

	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = s.Sanitize(ctx, data, "bench.docx")
	}
}

// ---------------------------------------------------------------------------
// Image Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkImageSanitize_JPEG(b *testing.B) {
	logger := benchLogger()
	s := NewImageSanitizer(logger)
	data := makeBenchJPEG(100, 100)
	ctx := context.Background()

	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = s.Sanitize(ctx, data, "bench.jpg")
	}
}

func BenchmarkImageSanitize_PNG(b *testing.B) {
	logger := benchLogger()
	s := NewImageSanitizer(logger)
	data := makeBenchPNGImage(100, 100)
	ctx := context.Background()

	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = s.Sanitize(ctx, data, "bench.png")
	}
}

func BenchmarkImageSanitize_LargeJPEG(b *testing.B) {
	logger := benchLogger()
	s := NewImageSanitizer(logger)
	data := makeBenchJPEG(1000, 1000)
	ctx := context.Background()

	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = s.Sanitize(ctx, data, "bench.jpg")
	}
}

// ---------------------------------------------------------------------------
// SVG Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkSVGSanitize_Clean(b *testing.B) {
	logger := benchLogger()
	s := NewSVGSanitizer(logger)
	data := makeCleanSVG(10)
	ctx := context.Background()

	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = s.Sanitize(ctx, data, "bench.svg")
	}
}

func BenchmarkSVGSanitize_WithThreats(b *testing.B) {
	logger := benchLogger()
	s := NewSVGSanitizer(logger)
	data := makeThreatSVG()
	ctx := context.Background()

	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = s.Sanitize(ctx, data, "bench.svg")
	}
}

func BenchmarkSVGSanitize_Large(b *testing.B) {
	logger := benchLogger()
	s := NewSVGSanitizer(logger)
	data := makeLargeSVG(1000)
	ctx := context.Background()

	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = s.Sanitize(ctx, data, "bench.svg")
	}
}

// ---------------------------------------------------------------------------
// Archive Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkArchiveSanitize_CleanZIP(b *testing.B) {
	logger := benchLogger()
	d := NewDispatcher()
	d.Register(NewPDFSanitizer(logger))
	d.Register(NewOfficeSanitizer(logger))
	d.Register(NewImageSanitizer(logger))
	d.Register(NewSVGSanitizer(logger))
	s := NewArchiveSanitizer(d, logger)
	d.Register(s)

	data := makeCleanZIPBench()
	ctx := context.Background()

	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = s.Sanitize(ctx, data, "bench.zip")
	}
}

func BenchmarkArchiveSanitize_WithThreats(b *testing.B) {
	logger := benchLogger()
	d := NewDispatcher()
	d.Register(NewPDFSanitizer(logger))
	d.Register(NewOfficeSanitizer(logger))
	d.Register(NewImageSanitizer(logger))
	d.Register(NewSVGSanitizer(logger))
	s := NewArchiveSanitizer(d, logger)
	d.Register(s)

	data := makeThreatZIPBench()
	ctx := context.Background()

	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = s.Sanitize(ctx, data, "bench.zip")
	}
}

// ---------------------------------------------------------------------------
// Dispatcher Benchmark
// ---------------------------------------------------------------------------

func BenchmarkDispatch(b *testing.B) {
	logger := benchLogger()
	d := NewDispatcher()
	d.Register(NewPDFSanitizer(logger))
	d.Register(NewOfficeSanitizer(logger))
	d.Register(NewImageSanitizer(logger))
	d.Register(NewSVGSanitizer(logger))
	d.Register(NewArchiveSanitizer(d, logger))

	cases := []struct {
		name     string
		data     []byte
		filename string
	}{
		{"PDF", makeCleanPDF(), "dispatch.pdf"},
		{"DOCX", makeCleanDocxBench(), "dispatch.docx"},
		{"JPEG", makeBenchJPEG(100, 100), "dispatch.jpg"},
		{"PNG", makeBenchPNGImage(100, 100), "dispatch.png"},
		{"SVG", makeCleanSVG(10), "dispatch.svg"},
		{"ZIP", makeCleanZIPBench(), "dispatch.zip"},
	}

	ctx := context.Background()

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.SetBytes(int64(len(tc.data)))
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, _ = d.Dispatch(ctx, tc.data, tc.filename)
			}
		})
	}
}

