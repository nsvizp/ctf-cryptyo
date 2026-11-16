package myxfc.Kit.Utils;

import java.io.UnsupportedEncodingException;
import java.util.Base64;
import java.util.HexFormat;

public class CryptoTextUtils {
    public static byte[] parse(String input, String format, String charset) throws UnsupportedEncodingException {
        if (input == null) {
            throw new IllegalArgumentException("Input must not be null");
        }
        return switch (format) {
            case "Text" -> input.getBytes(charset);
            case "HEX" -> HexFormat.of().parseHex(input.replaceAll("\\s", ""));
            case "Base64" -> Base64.getMimeDecoder().decode(input);
            default -> throw new IllegalArgumentException("Unsupported format: " + format);
        };
    }

    public static String format(byte[] input, String format, String charset) throws UnsupportedEncodingException {
        return switch (format) {
            case "Text" -> new String(input, charset);
            case "HEX" -> HexFormat.of().formatHex(input);
            case "Base64" -> Base64.getEncoder().encodeToString(input);
            default -> throw new IllegalArgumentException("Unsupported format: " + format);
        };
    }
}
