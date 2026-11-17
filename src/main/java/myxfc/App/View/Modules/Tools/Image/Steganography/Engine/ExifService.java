package myxfc.App.View.Modules.Tools.Image.Steganography.Engine;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

public class ExifService {
    private static final int[] TYPE_SIZES = {0, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8};
    private static final Map<Integer, String> TAGS = Map.ofEntries(
            Map.entry(0x010F, "Make"), Map.entry(0x0110, "Model"),
            Map.entry(0x0112, "Orientation"), Map.entry(0x011A, "XResolution"),
            Map.entry(0x011B, "YResolution"), Map.entry(0x0131, "Software"),
            Map.entry(0x0132, "DateTime"), Map.entry(0x013B, "Artist"),
            Map.entry(0x8298, "Copyright"), Map.entry(0x829A, "ExposureTime"),
            Map.entry(0x829D, "FNumber"), Map.entry(0x8827, "ISO"),
            Map.entry(0x9003, "DateTimeOriginal"), Map.entry(0x9004, "DateTimeDigitized"),
            Map.entry(0x9101, "ComponentsConfiguration"), Map.entry(0x9201, "ShutterSpeed"),
            Map.entry(0x9202, "Aperture"), Map.entry(0x9204, "ExposureBias"),
            Map.entry(0x9207, "MeteringMode"), Map.entry(0x9209, "Flash"),
            Map.entry(0x920A, "FocalLength"), Map.entry(0x9286, "UserComment"),
            Map.entry(0xA002, "PixelXDimension"), Map.entry(0xA003, "PixelYDimension"),
            Map.entry(0xA405, "FocalLengthIn35mmFilm"));

    public static String readExif(Path path) throws IOException {
        byte[] jpeg = Files.readAllBytes(path);
        if (jpeg.length < 4 || (jpeg[0] & 0xFF) != 0xFF || (jpeg[1] & 0xFF) != 0xD8) {
            return "";
        }
        int offset = 2;
        StringBuilder result = new StringBuilder();
        while (offset + 4 <= jpeg.length && (jpeg[offset] & 0xFF) == 0xFF) {
            int marker = jpeg[offset + 1] & 0xFF;
            offset += 2;
            if (marker == 0xD9 || marker == 0xDA) {
                break;
            }
            if (marker == 0x00 || marker >= 0xD0 && marker <= 0xD7) {
                continue;
            }
            int length = u16(jpeg, offset, false);
            if (length < 2 || offset + length > jpeg.length) {
                break;
            }
            if (marker == 0xE1 && length >= 8
                    && new String(jpeg, offset + 2, 6, StandardCharsets.US_ASCII).equals("Exif\0\0")) {
                int tiff = offset + 8;
                parseTiff(jpeg, tiff, result);
            }
            offset += length;
        }
        return result.toString();
    }

    private static void parseTiff(byte[] data, int tiff, StringBuilder result) {
        if (tiff + 8 > data.length) {
            return;
        }
        boolean little = data[tiff] == 'I' && data[tiff + 1] == 'I';
        if (!little && !(data[tiff] == 'M' && data[tiff + 1] == 'M')) {
            return;
        }
        if (u16(data, tiff + 2, little) != 42) {
            return;
        }
        int ifd0 = (int) u32(data, tiff + 4, little);
        parseIfd(data, tiff, ifd0, "IFD0", little, result);
    }

    private static void parseIfd(byte[] data, int tiff, int offset, String name,
                                 boolean little, StringBuilder result) {
        if (offset < 0 || tiff + offset + 2 > data.length) {
            return;
        }
        int entries = u16(data, tiff + offset, little);
        for (int i = 0; i < entries; i++) {
            int entry = tiff + offset + 2 + i * 12;
            if (entry + 12 > data.length) {
                return;
            }
            int tag = u16(data, entry, little);
            int type = u16(data, entry + 2, little);
            long count = u32(data, entry + 4, little);
            if (type <= 0 || type >= TYPE_SIZES.length || count < 0 || count > 1_000_000) {
                continue;
            }
            long byteCountLong = count * TYPE_SIZES[type];
            if (byteCountLong > Integer.MAX_VALUE) {
                continue;
            }
            int byteCount = (int) byteCountLong;
            int valueOffset = byteCount <= 4 ? entry + 8 : tiff + (int) u32(data, entry + 8, little);
            if (tag == 0x8769 || tag == 0x8825) {
                parseIfd(data, tiff, (int) u32(data, entry + 8, little),
                        tag == 0x8769 ? "ExifIFD" : "GPS", little, result);
                continue;
            }
            String value = value(data, valueOffset, type, (int) count, byteCount, little);
            result.append(name).append(' ').append(TAGS.getOrDefault(tag, String.format("Tag_0x%04X", tag)))
                    .append(" = ").append(value).append('\n');
        }
        int nextOffset = tiff + offset + 2 + entries * 12;
        if (nextOffset + 4 <= data.length) {
            int next = (int) u32(data, nextOffset, little);
            if (next > 0) {
                parseIfd(data, tiff, next, "IFD1", little, result);
            }
        }
    }

    private static String value(byte[] data, int offset, int type, int count, int byteCount, boolean little) {
        if (offset < 0 || offset + byteCount > data.length) {
            return "<invalid>";
        }
        if (type == 2) {
            int length = 0;
            while (length < byteCount && data[offset + length] != 0) {
                length++;
            }
            return new String(data, offset, length, StandardCharsets.UTF_8).trim();
        }
        if (type == 7) {
            StringBuilder text = new StringBuilder();
            for (int i = 0; i < byteCount; i++) {
                int value = data[offset + i] & 0xFF;
                text.append(value >= 32 && value < 127 ? (char) value : '.');
            }
            return text.toString();
        }
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < count; i++) {
            if (i > 0) {
                result.append(", ");
            }
            int item = offset + i * TYPE_SIZES[type];
            result.append(switch (type) {
                case 1, 6 -> data[item] & 0xFF;
                case 3 -> u16(data, item, little);
                case 4 -> u32(data, item, little);
                case 8 -> (short) u16(data, item, little);
                case 9 -> (int) u32(data, item, little);
                case 5, 10 -> rational(data, item, little, type == 10);
                case 11 -> Float.intBitsToFloat((int) u32(data, item, little));
                case 12 -> Double.longBitsToDouble(u64(data, item, little));
                default -> data[item];
            });
        }
        return result.toString();
    }

    private static String rational(byte[] data, int offset, boolean little, boolean signed) {
        long numerator = signed ? (int) u32(data, offset, little) : u32(data, offset, little);
        long denominator = signed ? (int) u32(data, offset + 4, little) : u32(data, offset + 4, little);
        return denominator == 0 ? numerator + "/0" : numerator + "/" + denominator;
    }

    private static int u16(byte[] data, int offset, boolean little) {
        if (offset < 0 || offset + 2 > data.length) {
            return 0;
        }
        return little ? (data[offset] & 0xFF) | (data[offset + 1] & 0xFF) << 8
                : (data[offset] & 0xFF) << 8 | (data[offset + 1] & 0xFF);
    }

    private static long u32(byte[] data, int offset, boolean little) {
        if (offset < 0 || offset + 4 > data.length) {
            return 0;
        }
        return little ? (data[offset] & 0xFFL) | (data[offset + 1] & 0xFFL) << 8
                | (data[offset + 2] & 0xFFL) << 16 | (data[offset + 3] & 0xFFL) << 24
                : (data[offset] & 0xFFL) << 24 | (data[offset + 1] & 0xFFL) << 16
                | (data[offset + 2] & 0xFFL) << 8 | (data[offset + 3] & 0xFFL);
    }

    private static long u64(byte[] data, int offset, boolean little) {
        return little ? u32(data, offset, true) | u32(data, offset + 4, true) << 32
                : u32(data, offset, false) << 32 | u32(data, offset + 4, false);
    }
}
