package crypto;

import myxfc.App.View.Modules.Tools.CTF.Engine.Archive.ZipAnalysisService;
import myxfc.App.View.Modules.Tools.CTF.Engine.Document.OfficeAnalysisService;
import myxfc.App.View.Modules.Tools.CTF.Engine.Document.PdfAnalysisService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.zip.Deflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ArchiveDocumentServiceTest {
    @TempDir
    Path temp;

    @Test
    void zipInspectionExtractionAndTrailingWork() throws Exception {
        Path zip = temp.resolve("sample.zip");
        try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(zip))) {
            output.setComment("archive-comment");
            output.putNextEntry(new ZipEntry("hidden/flag.txt"));
            output.write("flag{zip}".getBytes(StandardCharsets.UTF_8));
            output.closeEntry();
        }
        Files.write(zip, "tail".getBytes(StandardCharsets.UTF_8), java.nio.file.StandardOpenOption.APPEND);
        var entries = ZipAnalysisService.inspect(zip);
        assertEquals("hidden/flag.txt", entries.get(0).name());
        assertTrue(ZipAnalysisService.trailingReport(zip).contains("Trailing bytes: 4"));
        Path output = temp.resolve("out");
        ZipAnalysisService.extractAll(zip, output);
        assertEquals("flag{zip}", Files.readString(output.resolve("hidden/flag.txt")));
    }

    @Test
    void officeHiddenContentAndEmbeddedFilesWork() throws Exception {
        Path office = temp.resolve("sample.docx");
        try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(office))) {
            output.putNextEntry(new ZipEntry("word/document.xml"));
            output.write("<w:p><w:t>flag{office}</w:t></w:p>".getBytes(StandardCharsets.UTF_8));
            output.closeEntry();
            output.putNextEntry(new ZipEntry("word/vbaProject.bin"));
            output.write(new byte[]{1, 2, 3});
            output.closeEntry();
            output.putNextEntry(new ZipEntry("word/embeddings/payload.bin"));
            output.write(new byte[]{4, 5, 6});
            output.closeEntry();
        }
        assertTrue(OfficeAnalysisService.inspect(office).contains("flag{office}"));
        assertEquals(2, OfficeAnalysisService.embedded(office).size());
    }

    @Test
    void pdfEmbeddedDeflateStreamIsExtracted() throws Exception {
        byte[] plaintext = "flag{pdf_stream}".getBytes(StandardCharsets.UTF_8);
        byte[] compressed = deflate(plaintext);
        String header = "%PDF-1.7\n1 0 obj\n<< /Length " + compressed.length
                + " /Filter /FlateDecode /EmbeddedFile /F (flag.txt) >>\nstream\n";
        String footer = "\nendstream\nendobj\n%%EOF";
        ByteArrayOutputStream pdf = new ByteArrayOutputStream();
        pdf.write(header.getBytes(StandardCharsets.ISO_8859_1));
        pdf.write(compressed);
        pdf.write(footer.getBytes(StandardCharsets.ISO_8859_1));
        Path path = temp.resolve("sample.pdf");
        Files.write(path, pdf.toByteArray());
        assertTrue(PdfAnalysisService.inspect(path).contains("/EmbeddedFile"));
        var extracted = PdfAnalysisService.extract(path);
        assertEquals(1, extracted.size());
        assertArrayEquals(plaintext, extracted.get(0).data());
    }

    private static byte[] deflate(byte[] input) {
        Deflater deflater = new Deflater();
        deflater.setInput(input);
        deflater.finish();
        byte[] buffer = new byte[1024];
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        while (!deflater.finished()) {
            int count = deflater.deflate(buffer);
            output.write(buffer, 0, count);
        }
        deflater.end();
        return output.toByteArray();
    }
}
