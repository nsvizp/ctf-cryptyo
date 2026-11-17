package crypto;

import myxfc.App.View.Modules.Tools.CTF.Engine.Analysis.DocumentAnomalyService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertTrue;

class DocumentAnomalyServiceTest {
    @TempDir
    Path temp;

    @Test
    void encryptedAndDamagedPdfIsReportedAndRepaired() throws Exception {
        Path pdf = temp.resolve("damaged.pdf");
        Files.writeString(pdf, "%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
                + "2 0 obj\n<< /Filter /Standard /R 4 /P -4 /Encrypt >>\nendobj\nstartxref\n999999\n");
        String findings = DocumentAnomalyService.analyze(pdf).toString();
        assertTrue(findings.contains("Encrypted PDF"), findings);
        assertTrue(findings.contains("Invalid xref offset"), findings);
        assertTrue(findings.contains("Missing EOF"), findings);

        Path repaired = temp.resolve("repaired.pdf");
        DocumentAnomalyService.repair(pdf, repaired);
        String content = Files.readString(repaired);
        assertTrue(content.contains("xref"));
        assertTrue(content.endsWith("%%EOF\n"));
    }

    @Test
    void macroAndExternalLinksAreReported() throws Exception {
        Path office = temp.resolve("macro.docx");
        try (var output = new java.util.zip.ZipOutputStream(Files.newOutputStream(office))) {
            output.putNextEntry(new java.util.zip.ZipEntry("[Content_Types].xml"));
            output.write("<Types/>".getBytes());
            output.closeEntry();
            output.putNextEntry(new java.util.zip.ZipEntry("_rels/.rels"));
            output.write("<Relationships><Relationship TargetMode=\"External\" Target=\"http://evil\"/></Relationships>".getBytes());
            output.closeEntry();
            output.putNextEntry(new java.util.zip.ZipEntry("word/document.xml"));
            output.write("<w:p/>".getBytes());
            output.closeEntry();
            output.putNextEntry(new java.util.zip.ZipEntry("word/vbaProject.bin"));
            output.write("powershell Document_Open".getBytes());
            output.closeEntry();
        }
        String findings = DocumentAnomalyService.analyze(office).toString();
        assertTrue(findings.contains("External relationship"), findings);
        assertTrue(findings.contains("Suspicious macro keyword"), findings);
    }
}
