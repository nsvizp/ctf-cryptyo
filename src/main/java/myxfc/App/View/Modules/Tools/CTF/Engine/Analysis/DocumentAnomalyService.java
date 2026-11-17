package myxfc.App.View.Modules.Tools.CTF.Engine.Analysis;

import myxfc.App.View.Modules.Tools.CTF.Engine.Document.OfficeAnalysisService;
import myxfc.App.View.Modules.Tools.CTF.Engine.Document.PdfAnalysisService;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public class DocumentAnomalyService {
    public static List<AutoAnalysisService.Finding> analyze(Path path) {
        List<AutoAnalysisService.Finding> result = new ArrayList<>();
        try {
            byte[] bytes = Files.readAllBytes(path);
            if (matches(bytes, 0, 0xD0, 0xCF, 0x11, 0xE0)) {
                add(result, "Office", "Legacy OLE/encrypted document",
                        "OLE compound file detected. It may be an encrypted Office document or legacy .doc/.xls. "
                                + cryptoStatus("msoffcrypto-tool"), 110);
            } else if (matches(bytes, 0, 0x50, 0x4B, 0x03, 0x04)) {
                analyzeOffice(path, result);
            } else {
                analyzePdf(path, bytes, result);
            }
        } catch (Exception e) {
            add(result, "Document", "Analysis failure", e.getMessage(), 80);
        }
        return result;
    }

    private static void analyzePdf(Path path, byte[] bytes, List<AutoAnalysisService.Finding> result) {
        String text = new String(bytes, StandardCharsets.ISO_8859_1);
        if (!text.startsWith("%PDF-")) {
            add(result, "PDF", "Damaged PDF header", "File does not start with %PDF-", 100);
        }
        int lastEof = text.lastIndexOf("%%EOF");
        if (lastEof < 0) {
            add(result, "PDF", "Missing EOF", "Document may be truncated or corrupted", 90);
        } else if (lastEof + 5 < text.length()) {
            add(result, "PDF", "Data after EOF", (text.length() - lastEof - 5) + " trailing bytes", 45);
        }
        int startXref = text.lastIndexOf("startxref");
        if (startXref >= 0) {
            Matcher offset = Pattern.compile("startxref\\s+(\\d+)").matcher(text.substring(startXref));
            if (offset.find()) {
                long position = Long.parseLong(offset.group(1));
                if (position < 0 || position >= bytes.length) {
                    add(result, "PDF", "Invalid xref offset", String.valueOf(position), 85);
                }
            }
        }
        int objects = count(text, " obj");
        int endObjects = count(text, "endobj");
        if (objects != endObjects) {
            add(result, "PDF", "Object boundary mismatch", "obj=" + objects + " endobj=" + endObjects, 80);
        }
        if (text.contains("/Encrypt")) {
            add(result, "PDF", "Encrypted PDF", snippet(text, text.indexOf("/Encrypt"), 600)
                    + "\n" + cryptoStatus("qpdf"), 130);
            Matcher permission = Pattern.compile("/P\\s+(-?\\d+)").matcher(text);
            if (permission.find()) {
                add(result, "PDF", "Permission flags", permission.group(1), 45);
            }
            Matcher revision = Pattern.compile("/R\\s+(\\d+)").matcher(text);
            if (revision.find()) {
                add(result, "PDF", "Encryption revision", revision.group(1), 45);
            }
        }
        for (String token : List.of("/JavaScript", "/JS", "/OpenAction", "/AA", "/Launch", "/SubmitForm",
                "/GoToR", "/URI", "/XFA", "/RichMedia")) {
            if (text.contains(token)) {
                add(result, "PDF", "Suspicious active content", token, token.equals("/JavaScript")
                        || token.equals("/Launch") || token.equals("/OpenAction") ? 90 : 50);
            }
        }
        try {
            add(result, "PDF", "Structure", PdfAnalysisService.inspect(path), 15);
            for (PdfAnalysisService.PdfStream stream : PdfAnalysisService.extract(path)) {
                add(result, "PDF", "Extracted " + stream.kind(), stream.name() + " bytes=" + stream.data().length, 60);
            }
        } catch (Exception e) {
            add(result, "PDF", "Damaged stream or unsupported encryption", e.getMessage(), 90);
        }
    }

    private static void analyzeOffice(Path path, List<AutoAnalysisService.Finding> result) {
        Set<String> names = new HashSet<>();
        try (ZipFile zip = new ZipFile(path.toFile())) {
            var entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();
                if (!names.add(name)) {
                    add(result, "Office", "Duplicate ZIP entry", name, 70);
                }
                if (name.contains("..") || name.startsWith("/") || name.matches("^[A-Za-z]:.*")) {
                    add(result, "Office", "Unsafe ZIP path", name, 110);
                }
                if (entry.getSize() > 10_000_000 && entry.getCompressedSize() > 0
                        && entry.getSize() / entry.getCompressedSize() > 200) {
                    add(result, "Office", "Possible ZIP bomb", name + " ratio=" + entry.getSize() / entry.getCompressedSize(), 100);
                }
                if (name.contains("vbaProject") || name.contains("macros") || name.contains("DDE")
                        || name.contains("oleObject") || name.contains("activeX")) {
                    add(result, "Office", "Macro/OLE/active content", name, 75);
                }
                if (name.endsWith(".rels")) {
                    String xml = new String(zip.getInputStream(entry).readAllBytes(), StandardCharsets.UTF_8);
                    if (xml.contains("TargetMode=\"External\"")) {
                        add(result, "Office", "External relationship", snippet(xml, 0, 800), 85);
                    }
                }
                if (name.equals("word/vbaProject.bin") || name.equals("xl/vbaProject.bin")) {
                    String macro = new String(zip.getInputStream(entry).readAllBytes(), StandardCharsets.ISO_8859_1);
                    for (String keyword : List.of("powershell", "cmd.exe", "URLDownloadToFile", "Shell", "CreateObject",
                            "Document_Open", "AutoOpen", "Workbook_Open")) {
                        if (macro.toLowerCase().contains(keyword.toLowerCase())) {
                            add(result, "Office", "Suspicious macro keyword", keyword, 100);
                        }
                    }
                }
            }
            for (String required : List.of("[Content_Types].xml", "_rels/.rels")) {
                if (!names.contains(required)) {
                    add(result, "Office", "Missing required package part", required, 90);
                }
            }
            if (!names.contains("word/document.xml") && !names.contains("xl/workbook.xml")
                    && !names.contains("ppt/presentation.xml")) {
                add(result, "Office", "Missing main document part", "DOCX/XLSX/PPTX main XML not found", 90);
            }
            add(result, "Office", "Metadata and hidden content", OfficeAnalysisService.inspect(path), 15);
        } catch (Exception e) {
            add(result, "Office", "Corrupted or encrypted package", e.getMessage(), 100);
        }
    }

    public static Path repair(Path path, Path output) throws IOException {
        byte[] bytes = Files.readAllBytes(path);
        if (matches(bytes, 0, 0x50, 0x4B, 0x03, 0x04)) {
            repairZip(path, output);
        } else {
            repairPdf(bytes, output);
        }
        return output;
    }

    private static void repairZip(Path path, Path output) throws IOException {
        try (ZipInputStream input = new ZipInputStream(Files.newInputStream(path));
             ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(output))) {
            ZipEntry entry;
            while ((entry = input.getNextEntry()) != null) {
                if (entry.getName().contains("..") || entry.getName().startsWith("/")) {
                    continue;
                }
                zip.putNextEntry(new ZipEntry(entry.getName()));
                input.transferTo(zip);
                zip.closeEntry();
            }
        }
    }

    private static void repairPdf(byte[] bytes, Path output) throws IOException {
        String text = new String(bytes, StandardCharsets.ISO_8859_1);
        List<String> objects = new ArrayList<>();
        Matcher matcher = Pattern.compile("(?s)(\\d+)\\s+(\\d+)\\s+obj.*?endobj").matcher(text);
        while (matcher.find()) {
            objects.add(matcher.group());
        }
        if (objects.isEmpty()) {
            throw new IOException("No complete PDF objects available for repair");
        }
        StringBuilder repaired = new StringBuilder("%PDF-1.7\n");
        List<Integer> offsets = new ArrayList<>();
        for (String object : objects) {
            offsets.add(repaired.length());
            repaired.append(object).append('\n');
        }
        int xref = repaired.length();
        repaired.append("xref\n0 ").append(objects.size() + 1).append("\n0000000000 65535 f \n");
        for (int offset : offsets) {
            repaired.append(String.format("%010d 00000 n \n", offset));
        }
        repaired.append("trailer\n<< /Size ").append(objects.size() + 1).append(" >>\nstartxref\n")
                .append(xref).append("\n%%EOF\n");
        Files.write(output, repaired.toString().getBytes(StandardCharsets.ISO_8859_1));
    }

    private static String cryptoStatus(String tool) {
        String executable = findTool(tool);
        return executable == null ? tool + " not installed; encrypted content was not decrypted"
                : tool + " available at " + executable;
    }

    public static String decryptEmptyPassword(Path path, Path output) {
        String qpdf = findTool("qpdf");
        if (qpdf == null) {
            return "qpdf is not installed; empty-password decryption was not attempted";
        }
        try {
            Process process = new ProcessBuilder(qpdf, "--decrypt", "--password=", path.toString(), output.toString())
                    .redirectErrorStream(true).start();
            if (!process.waitFor(60, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                return "qpdf timed out";
            }
            String message = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            return process.exitValue() == 0 ? "Decrypted: " + output : "Decryption failed: " + message;
        } catch (Exception e) {
            return "Decryption failed: " + e.getMessage();
        }
    }

    private static String findTool(String tool) {
        for (String directory : List.of("/opt/homebrew/bin", "/Volumes/safe/Homebrew/bin", "/usr/local/bin", "/usr/bin")) {
            Path candidate = Path.of(directory, tool);
            if (Files.isRegularFile(candidate) && Files.isExecutable(candidate)) {
                return candidate.toString();
            }
        }
        return null;
    }

    private static String snippet(String text, int start, int length) {
        int safeStart = Math.max(0, start);
        return text.substring(safeStart, Math.min(text.length(), safeStart + length));
    }

    private static int count(String text, String target) {
        int result = 0;
        int offset = 0;
        while ((offset = text.indexOf(target, offset)) >= 0) {
            result++;
            offset += target.length();
        }
        return result;
    }

    private static void add(List<AutoAnalysisService.Finding> result, String source, String method,
                            String evidence, double score) {
        result.add(new AutoAnalysisService.Finding(source, method, evidence, score));
    }

    private static boolean matches(byte[] bytes, int offset, int... values) {
        if (offset + values.length > bytes.length) {
            return false;
        }
        for (int i = 0; i < values.length; i++) {
            if ((bytes[offset + i] & 0xFF) != values[i]) {
                return false;
            }
        }
        return true;
    }
}
