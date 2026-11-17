package myxfc.App.View.Modules.Tools.CTF.Engine.Document;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class OfficeAnalysisService {
    public record EmbeddedEntry(String name, byte[] data) {
    }

    public static String inspect(Path path) throws IOException {
        StringBuilder report = new StringBuilder();
        try (ZipFile zip = new ZipFile(path.toFile())) {
            var entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();
                if (interesting(name)) {
                    report.append(name).append(" (").append(entry.getSize()).append(" bytes)\n");
                }
                if (name.equals("docProps/core.xml") || name.equals("docProps/app.xml")
                        || name.equals("docProps/custom.xml") || name.equals("xl/workbook.xml")
                        || name.equals("word/document.xml") || name.endsWith("comments.xml")) {
                    String xml = new String(zip.getInputStream(entry).readAllBytes(), StandardCharsets.UTF_8);
                    if (name.equals("xl/workbook.xml")) {
                        report.append(hiddenSheets(xml));
                    } else if (name.equals("word/document.xml")) {
                        report.append("Document text:\n").append(xmlText(xml)).append('\n');
                    } else {
                        report.append(name).append(":\n").append(xml).append('\n');
                    }
                }
            }
        }
        return report.isEmpty() ? "No Office metadata or hidden objects found" : report.toString();
    }

    public static List<EmbeddedEntry> embedded(Path path) throws IOException {
        List<EmbeddedEntry> result = new ArrayList<>();
        try (ZipFile zip = new ZipFile(path.toFile())) {
            var entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();
                if (entry.isDirectory()) {
                    continue;
                }
                if (name.contains("/embeddings/") || name.equals("word/vbaProject.bin")
                        || name.equals("xl/vbaProject.bin") || name.equals("ppt/vbaProject.bin")
                        || name.startsWith("customXml/") || name.endsWith("comments.xml")) {
                    result.add(new EmbeddedEntry(name, zip.getInputStream(entry).readAllBytes()));
                }
            }
        }
        return result;
    }

    private static boolean interesting(String name) {
        return name.contains("hidden") || name.contains("vba") || name.contains("macro")
                || name.contains("/embeddings/") || name.contains("comments") || name.startsWith("customXml/")
                || name.startsWith("docProps/") || name.equals("word/document.xml") || name.equals("xl/workbook.xml");
    }

    private static String hiddenSheets(String xml) {
        StringBuilder result = new StringBuilder();
        java.util.regex.Matcher matcher = java.util.regex.Pattern.compile("<sheet[^>]+>").matcher(xml);
        while (matcher.find()) {
            String sheet = matcher.group();
            if (sheet.contains("hidden") || sheet.contains("veryHidden")) {
                result.append("Hidden sheet: ").append(sheet).append('\n');
            }
        }
        return result.toString();
    }

    private static String xmlText(String xml) {
        return xml.replaceAll("</w:p>", "\n").replaceAll("<w:tab[^>]*/>", "\t")
                .replaceAll("<[^>]+>", "").replace("&amp;", "&").replace("&lt;", "<")
                .replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").trim();
    }

    public static void extract(Path path, Path outputDirectory) throws IOException {
        Path root = outputDirectory.toAbsolutePath().normalize();
        Files.createDirectories(root);
        for (EmbeddedEntry entry : embedded(path)) {
            Path output = root.resolve(entry.name()).normalize();
            if (!output.startsWith(root)) {
                throw new IOException("Unsafe embedded path: " + entry.name());
            }
            Files.createDirectories(output.getParent());
            Files.write(output, entry.data());
        }
    }
}
