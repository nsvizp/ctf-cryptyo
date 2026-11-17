package myxfc.App.View.Modules.Tools.CTF.Engine.Document;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.Inflater;

public class PdfAnalysisService {
    private static final Pattern OBJECT = Pattern.compile("(?s)(\\d+)\\s+(\\d+)\\s+obj(.*?)endobj");
    private static final Pattern STREAM = Pattern.compile("(?s)^(.*?)stream(?:\\r\\n|\\n|\\r)(.*?)endstream");

    public record PdfStream(String name, int objectNumber, String kind, byte[] data) {
    }

    public static String inspect(Path path) throws IOException {
        byte[] bytes = Files.readAllBytes(path);
        String text = new String(bytes, StandardCharsets.ISO_8859_1);
        StringBuilder report = new StringBuilder();
        int objects = 0;
        int streams = 0;
        Matcher matcher = OBJECT.matcher(text);
        while (matcher.find()) {
            objects++;
            if (matcher.group(3).contains("stream")) {
                streams++;
            }
        }
        report.append("Objects: ").append(objects).append('\n');
        report.append("Streams: ").append(streams).append('\n');
        report.append("EOF markers: ").append(count(text, "%%EOF")).append('\n');
        report.append("startxref markers: ").append(count(text, "startxref")).append('\n');
        for (String token : List.of("/EmbeddedFile", "/Filespec", "/JavaScript", "/JS", "/OpenAction",
                "/Launch", "/Annots", "/Metadata", "/AcroForm", "/XFA", "/ObjStm")) {
            int count = count(text, token);
            if (count > 0) {
                report.append(token).append(": ").append(count).append('\n');
            }
        }
        for (String name : List.of("Title", "Author", "Subject", "Creator", "Producer", "CreationDate", "ModDate")) {
            Matcher metadata = Pattern.compile("/" + name + "\\s*\\(([^)]*)\\)").matcher(text);
            while (metadata.find()) {
                report.append(name).append(": ").append(metadata.group(1)).append('\n');
            }
        }
        return report.toString();
    }

    public static List<PdfStream> extract(Path path) throws IOException {
        byte[] bytes = Files.readAllBytes(path);
        String text = new String(bytes, StandardCharsets.ISO_8859_1);
        Map<Integer, String> embeddedNames = new HashMap<>();
        Matcher matcher = OBJECT.matcher(text);
        List<PdfStream> result = new ArrayList<>();
        while (matcher.find()) {
            int objectNumber = Integer.parseInt(matcher.group(1));
            String body = matcher.group(3);
            if (body.contains("/Filespec")) {
                Matcher reference = Pattern.compile("/EF.*?/(?:F|UF)\\s+(\\d+)\\s+\\d+\\s+R").matcher(body);
                if (reference.find()) {
                    embeddedNames.put(Integer.parseInt(reference.group(1)), fileName(body));
                }
            }
        }
        matcher = OBJECT.matcher(text);
        while (matcher.find()) {
            int objectNumber = Integer.parseInt(matcher.group(1));
            String body = matcher.group(3);
            Matcher streamMatcher = STREAM.matcher(body);
            if (!streamMatcher.find()) {
                continue;
            }
            String dictionary = streamMatcher.group(1);
            byte[] data = streamMatcher.group(2).getBytes(StandardCharsets.ISO_8859_1);
            if (dictionary.contains("/FlateDecode")) {
                data = inflate(data);
            }
            if (body.contains("/EmbeddedFile")) {
                String name = embeddedNames.getOrDefault(objectNumber, fileName(body));
                result.add(new PdfStream(name, objectNumber, "EmbeddedFile", data));
            } else if (body.contains("/JavaScript") || body.contains("/JS")) {
                result.add(new PdfStream("javascript_" + objectNumber + ".js", objectNumber, "JavaScript", data));
            }
        }
        return result;
    }

    public static void extract(Path path, Path outputDirectory) throws IOException {
        Files.createDirectories(outputDirectory);
        for (PdfStream stream : extract(path)) {
            String safeName = stream.name().replaceAll("[^A-Za-z0-9._-]", "_");
            Files.write(outputDirectory.resolve(stream.objectNumber() + "_" + safeName), stream.data());
        }
    }

    private static String fileName(String body) {
        Matcher matcher = Pattern.compile("/(?:UF|F)\\s*(?:\\(([^)]*)\\)|<([0-9A-Fa-f]+)>)").matcher(body);
        if (matcher.find()) {
            if (matcher.group(1) != null) {
                return matcher.group(1);
            }
            byte[] encoded = java.util.HexFormat.of().parseHex(matcher.group(2));
            boolean unicode = encoded.length >= 2 && (encoded[0] & 0xFF) == 0xFE && (encoded[1] & 0xFF) == 0xFF;
            return new String(encoded, unicode ? StandardCharsets.UTF_16BE : StandardCharsets.ISO_8859_1);
        }
        return "embedded.bin";
    }

    private static byte[] inflate(byte[] input) throws IOException {
        Inflater inflater = new Inflater();
        inflater.setInput(input);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        try {
            while (!inflater.finished()) {
                int count = inflater.inflate(buffer);
                if (count == 0) {
                    if (inflater.needsDictionary() || inflater.needsInput()) {
                        throw new IOException("Invalid or truncated deflate stream");
                    }
                }
                output.write(buffer, 0, count);
            }
        } catch (java.util.zip.DataFormatException e) {
            throw new IOException("Invalid deflate stream", e);
        } finally {
            inflater.end();
        }
        return output.toByteArray();
    }

    private static int count(String value, String target) {
        int result = 0;
        int offset = 0;
        while ((offset = value.indexOf(target, offset)) >= 0) {
            result++;
            offset += target.length();
        }
        return result;
    }
}
