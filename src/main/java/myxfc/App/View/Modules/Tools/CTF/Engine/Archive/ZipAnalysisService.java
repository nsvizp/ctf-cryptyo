package myxfc.App.View.Modules.Tools.CTF.Engine.Archive;

import myxfc.App.View.Modules.Tools.Image.Steganography.Engine.ImageStructureService;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

public class ZipAnalysisService {
    public record ZipEntryInfo(String name, long size, long compressedSize, int method, boolean encrypted,
                               String comment, String extraHex, long localOffset) {
        public String summary() {
            return String.format("%s size=%d compressed=%d method=%d encrypted=%s%s%s", name, size, compressedSize,
                    method, encrypted, comment.isEmpty() ? "" : " comment=" + comment,
                    extraHex.isEmpty() ? "" : " extra=" + extraHex);
        }
    }

    public static List<ZipEntryInfo> inspect(Path path) throws IOException {
        byte[] bytes = Files.readAllBytes(path);
        int eocd = findEndOfCentralDirectory(bytes);
        if (eocd < 0) {
            throw new IOException("ZIP end of central directory not found");
        }
        int count = u16(bytes, eocd + 10);
        int offset = (int) u32(bytes, eocd + 16);
        List<ZipEntryInfo> result = new ArrayList<>();
        for (int index = 0; index < count; index++) {
            if (offset + 46 > bytes.length || u32(bytes, offset) != 0x02014B50) {
                throw new IOException("Invalid ZIP central directory");
            }
            int flags = u16(bytes, offset + 8);
            int method = u16(bytes, offset + 10);
            long compressed = u32(bytes, offset + 20);
            long size = u32(bytes, offset + 24);
            int nameLength = u16(bytes, offset + 28);
            int extraLength = u16(bytes, offset + 30);
            int commentLength = u16(bytes, offset + 32);
            long localOffset = u32(bytes, offset + 42);
            int end = offset + 46 + nameLength + extraLength + commentLength;
            if (end > bytes.length) {
                throw new IOException("Truncated ZIP central directory");
            }
            String encoding = (flags & 0x800) != 0 ? "UTF-8" : "ISO-8859-1";
            String name = new String(bytes, offset + 46, nameLength, encoding);
            String comment = new String(bytes, offset + 46 + nameLength + extraLength, commentLength, encoding);
            String extra = extraLength == 0 ? "" : HexFormat.of().formatHex(bytes, offset + 46 + nameLength,
                    offset + 46 + nameLength + Math.min(extraLength, 256));
            result.add(new ZipEntryInfo(name, size, compressed, method, (flags & 1) != 0, comment, extra, localOffset));
            offset = end;
        }
        return result;
    }

    public static byte[] readEntry(Path path, String name) throws IOException {
        try (ZipFile zip = new ZipFile(path.toFile())) {
            ZipEntry entry = zip.getEntry(name);
            if (entry == null) {
                throw new IOException("ZIP entry not found: " + name);
            }
            try (var input = zip.getInputStream(entry)) {
                return input.readAllBytes();
            }
        }
    }

    public static List<Path> extractAll(Path path, Path outputDirectory) throws IOException {
        Path root = outputDirectory.toAbsolutePath().normalize();
        Files.createDirectories(root);
        List<Path> outputs = new ArrayList<>();
        try (ZipFile zip = new ZipFile(path.toFile())) {
            var entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                Path output = root.resolve(entry.getName()).normalize();
                if (!output.startsWith(root)) {
                    throw new IOException("Unsafe ZIP entry path: " + entry.getName());
                }
                if (entry.isDirectory()) {
                    Files.createDirectories(output);
                    continue;
                }
                Files.createDirectories(output.getParent());
                try (var input = zip.getInputStream(entry)) {
                    Files.write(output, input.readAllBytes());
                }
                outputs.add(output);
            }
        }
        return outputs;
    }

    public static String trailingReport(Path path) throws IOException {
        ImageStructureService.TrailingData trailing = ImageStructureService.trailingData(Files.readAllBytes(path));
        return "End offset: " + trailing.endOffset() + "\nTrailing bytes: " + trailing.data().length
                + "\n" + HexFormat.of().formatHex(trailing.data(), 0, Math.min(512, trailing.data().length));
    }

    private static int findEndOfCentralDirectory(byte[] bytes) {
        for (int i = bytes.length - 22; i >= 0; i--) {
            if (u32(bytes, i) == 0x06054B50) {
                return i;
            }
        }
        return -1;
    }

    private static int u16(byte[] bytes, int offset) {
        if (offset < 0 || offset + 2 > bytes.length) {
            return 0;
        }
        return (bytes[offset] & 0xFF) | (bytes[offset + 1] & 0xFF) << 8;
    }

    private static long u32(byte[] bytes, int offset) {
        if (offset < 0 || offset + 4 > bytes.length) {
            return 0;
        }
        return (bytes[offset] & 0xFFL) | (bytes[offset + 1] & 0xFFL) << 8
                | (bytes[offset + 2] & 0xFFL) << 16 | (bytes[offset + 3] & 0xFFL) << 24;
    }
}
