package myxfc.App.View.Modules.Tools.Image.Steganography.Engine;

import java.awt.image.BufferedImage;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.zip.CRC32;

public class ImageStructureService {
    private static final byte[] PNG_SIGNATURE = {(byte) 0x89, 'P', 'N', 'G', 13, 10, 26, 10};
    private static final List<String> KNOWN_CHUNKS = List.of(
            "IHDR", "PLTE", "IDAT", "IEND", "tRNS", "cHRM", "gAMA", "iCCP", "sBIT", "sRGB",
            "bKGD", "hIST", "pHYs", "sPLT", "tIME", "iTXt", "tEXt", "zTXt");

    public record PNGChunk(int offset, int length, String type, boolean crcValid, String flags) {
        @Override
        public String toString() {
            return String.format(Locale.ROOT, "@%08x %-4s length=%d crc=%s %s",
                    offset, type, length, crcValid ? "OK" : "BAD", flags);
        }
    }

    public record TrailingData(int endOffset, byte[] data) {
    }

    public record CarvedFile(String extension, int offset, byte[] data) {
    }

    public static String metadata(Path path) throws IOException {
        StringBuilder result = new StringBuilder();
        BufferedImage image = ImageStegoUtils.read(path.toFile());
        result.append("Width: ").append(image.getWidth()).append('\n');
        result.append("Height: ").append(image.getHeight()).append('\n');
        result.append("Color model: ").append(image.getColorModel()).append('\n');
        result.append("Raster: ").append(image.getRaster()).append('\n');
        String exif = ExifService.readExif(path);
        if (!exif.isBlank()) {
            result.append("\nEXIF/TIFF:\n").append(exif);
        }
        byte[] bytes = Files.readAllBytes(path);
        if (isPng(bytes)) {
            result.append("\nPNG textual chunks:\n");
            for (PNGChunk chunk : parsePng(bytes)) {
                if (chunk.type.equals("tEXt") || chunk.type.equals("zTXt") || chunk.type.equals("iTXt")) {
                    int start = chunk.offset + 8;
                    result.append(chunk.type).append(": ")
                            .append(new String(bytes, start, chunk.length, StandardCharsets.ISO_8859_1))
                            .append('\n');
                }
            }
        }
        return result.toString();
    }

    public static List<PNGChunk> parsePng(byte[] bytes) {
        if (!isPng(bytes)) {
            throw new IllegalArgumentException("Not a PNG file");
        }
        List<PNGChunk> result = new ArrayList<>();
        List<String> seen = new ArrayList<>();
        int offset = 8;
        boolean ended = false;
        while (offset + 12 <= bytes.length && !ended) {
            int length = (int) u32(bytes, offset);
            if (length < 0 || offset + 12L + length > bytes.length) {
                result.add(new PNGChunk(offset, length, "<truncated>", false, "Invalid chunk length"));
                break;
            }
            String type = new String(bytes, offset + 4, 4, StandardCharsets.ISO_8859_1);
            CRC32 crc = new CRC32();
            crc.update(bytes, offset + 4, length + 4);
            long expected = u32(bytes, offset + 8 + length);
            boolean valid = crc.getValue() == expected;
            StringBuilder flags = new StringBuilder();
            if (!KNOWN_CHUNKS.contains(type) && Character.isUpperCase(type.charAt(0))) {
                flags.append("Unknown-critical ");
            }
            if (Character.isLowerCase(type.charAt(2))) {
                flags.append("Invalid-reserved-bit ");
            }
            if (seen.contains(type) && List.of("IHDR", "PLTE", "IEND").contains(type)) {
                flags.append("Duplicate-critical ");
            }
            seen.add(type);
            result.add(new PNGChunk(offset, length, type, valid, flags.toString().trim()));
            offset += 12 + length;
            ended = type.equals("IEND");
        }
        return result;
    }

    public static TrailingData trailingData(byte[] bytes) {
        int end = fileEnd(bytes);
        if (end < 0 || end >= bytes.length) {
            return new TrailingData(end, new byte[0]);
        }
        return new TrailingData(end, Arrays.copyOfRange(bytes, end, bytes.length));
    }

    public static List<CarvedFile> carve(byte[] bytes) {
        List<CarvedFile> result = new ArrayList<>();
        for (int offset = 0; offset + 8 <= bytes.length; offset++) {
            String extension = extensionAt(bytes, offset);
            if (extension.isEmpty()) {
                continue;
            }
            int end = switch (extension) {
                case "png" -> pngEnd(bytes, offset);
                case "jpg" -> findBytes(bytes, offset + 2, new byte[]{(byte) 0xFF, (byte) 0xD9});
                case "gif" -> findByte(bytes, offset + 6, (byte) 0x3B);
                case "pdf" -> findBytes(bytes, offset + 4, "%%EOF".getBytes(StandardCharsets.US_ASCII));
                case "zip" -> zipEnd(bytes, offset);
                default -> -1;
            };
            if (end < 0) {
                continue;
            }
            int actualEnd = switch (extension) {
                case "jpg", "gif" -> end + 1;
                case "pdf" -> end + 1;
                default -> end;
            };
            if (actualEnd <= bytes.length && actualEnd > offset) {
                result.add(new CarvedFile(extension, offset, Arrays.copyOfRange(bytes, offset, actualEnd)));
                offset = actualEnd - 1;
            }
        }
        return result;
    }

    private static int fileEnd(byte[] bytes) {
        String extension = extensionAt(bytes, 0);
        return switch (extension) {
            case "png" -> pngEnd(bytes, 0);
            case "jpg" -> {
                int end = findBytes(bytes, 2, new byte[]{(byte) 0xFF, (byte) 0xD9});
                yield end < 0 ? -1 : end + 1;
            }
            case "gif" -> {
                int end = findByte(bytes, 6, (byte) 0x3B);
                yield end < 0 ? -1 : end + 1;
            }
            case "pdf" -> {
                int end = findBytes(bytes, 4, "%%EOF".getBytes(StandardCharsets.US_ASCII));
                yield end < 0 ? -1 : end + 1;
            }
            case "zip" -> zipEnd(bytes, 0);
            default -> -1;
        };
    }

    private static int pngEnd(byte[] bytes, int start) {
        if (!matches(bytes, start, PNG_SIGNATURE)) {
            return -1;
        }
        int offset = start + 8;
        while (offset + 12 <= bytes.length) {
            int length = (int) u32(bytes, offset);
            if (length < 0 || offset + 12L + length > bytes.length) {
                return -1;
            }
            String type = new String(bytes, offset + 4, 4, StandardCharsets.ISO_8859_1);
            offset += 12 + length;
            if (type.equals("IEND")) {
                return offset;
            }
        }
        return -1;
    }

    private static int zipEnd(byte[] bytes, int start) {
        byte[] signature = {'P', 'K', 5, 6};
        for (int i = bytes.length - 22; i >= start; i--) {
            if (matches(bytes, i, signature) && i + 22 <= bytes.length) {
                int commentLength = (bytes[i + 20] & 0xFF) | (bytes[i + 21] & 0xFF) << 8;
                int end = i + 22 + commentLength;
                if (end <= bytes.length) {
                    return end;
                }
            }
        }
        return -1;
    }

    private static String extensionAt(byte[] bytes, int offset) {
        if (matches(bytes, offset, PNG_SIGNATURE)) {
            return "png";
        }
        if (matches(bytes, offset, new byte[]{(byte) 0xFF, (byte) 0xD8, (byte) 0xFF})) {
            return "jpg";
        }
        if (matches(bytes, offset, "GIF87a".getBytes(StandardCharsets.US_ASCII))
                || matches(bytes, offset, "GIF89a".getBytes(StandardCharsets.US_ASCII))) {
            return "gif";
        }
        if (matches(bytes, offset, "%PDF".getBytes(StandardCharsets.US_ASCII))) {
            return "pdf";
        }
        if (matches(bytes, offset, new byte[]{'P', 'K', 3, 4})) {
            return "zip";
        }
        return "";
    }

    private static int findBytes(byte[] bytes, int start, byte[] target) {
        for (int i = Math.max(0, start); i + target.length <= bytes.length; i++) {
            if (matches(bytes, i, target)) {
                return i + target.length - 1;
            }
        }
        return -1;
    }

    private static int findByte(byte[] bytes, int start, byte target) {
        for (int i = Math.max(0, start); i < bytes.length; i++) {
            if (bytes[i] == target) {
                return i;
            }
        }
        return -1;
    }

    private static boolean matches(byte[] bytes, int offset, byte[] target) {
        if (offset < 0 || offset + target.length > bytes.length) {
            return false;
        }
        for (int i = 0; i < target.length; i++) {
            if (bytes[offset + i] != target[i]) {
                return false;
            }
        }
        return true;
    }

    private static boolean isPng(byte[] bytes) {
        return matches(bytes, 0, PNG_SIGNATURE);
    }

    private static long u32(byte[] bytes, int offset) {
        if (offset < 0 || offset + 4 > bytes.length) {
            return 0;
        }
        return (bytes[offset] & 0xFFL) << 24 | (bytes[offset + 1] & 0xFFL) << 16
                | (bytes[offset + 2] & 0xFFL) << 8 | (bytes[offset + 3] & 0xFFL);
    }
}
