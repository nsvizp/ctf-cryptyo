package myxfc.App.View.Modules.Tools.CTF.Engine.Decode;

import myxfc.App.View.Modules.Encryption.Coding.BaseEncoding.CustomBase.CustomBaseImpl;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

public class MultiDecodeService {
    private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final Pattern BASE64 = Pattern.compile("[A-Za-z0-9+/]*={0,2}");
    private static final Pattern BASE32 = Pattern.compile("[A-Z2-7]*={0,6}");
    private static final Pattern DECIMAL = Pattern.compile("\\d{1,3}");

    public record Step(String format, String preview) {
        @Override
        public String toString() {
            return format + " -> " + preview;
        }
    }

    public record Result(String output, List<Step> steps, double score) {
        public String chain() {
            return steps.isEmpty() ? "Plain text" : steps.stream().map(Step::format).reduce((a, b) -> a + " -> " + b).orElse("");
        }
    }

    public static List<Result> decode(String input, int maxDepth) {
        if (input == null || input.isBlank()) {
            throw new IllegalArgumentException("Input must not be empty");
        }
        List<String> items = batchItems(input);
        if (items.size() > 1) {
            List<Result> bestResults = new ArrayList<>();
            int decodedItems = 0;
            for (String item : items) {
                List<Result> itemResults = decodeSingle(item, maxDepth);
                Result best = itemResults.stream().filter(result -> !result.steps().isEmpty())
                        .findFirst().orElse(itemResults.get(0));
                bestResults.add(best);
                if (!best.steps().isEmpty()) {
                    decodedItems++;
                }
            }
            boolean separatedByWhitespace = !input.contains("\n") && !input.contains("\r")
                    && !input.contains(",") && !input.contains(";");
            if (decodedItems >= 2 || decodedItems >= 1 && !separatedByWhitespace) {
                StringBuilder output = new StringBuilder();
                for (int i = 0; i < bestResults.size(); i++) {
                    Result result = bestResults.get(i);
                    output.append('[').append(i + 1).append('/').append(bestResults.size()).append("] ")
                            .append(result.chain()).append('\n').append(result.output());
                    if (i + 1 < bestResults.size()) {
                        output.append("\n\n");
                    }
                }
                double bestScore = bestResults.stream().mapToDouble(Result::score).max().orElse(0);
                return List.of(new Result(output.toString(),
                        List.of(new Step("Batch", items.size() + " items")), bestScore + 1000));
            }
        }
        return decodeSingle(input, maxDepth);
    }

    private static List<String> batchItems(String input) {
        String[] separated = input.trim().split("[\\r\\n,;]+");
        if (separated.length == 1) {
            separated = input.trim().split("\\s+");
        }
        List<String> items = new ArrayList<>();
        for (String item : separated) {
            if (!item.isBlank()) {
                items.add(item.trim());
            }
        }
        return items;
    }

    private static List<Result> decodeSingle(String input, int maxDepth) {
        List<Result> results = new ArrayList<>();
        Deque<Result> queue = new ArrayDeque<>();
        Set<String> visited = new HashSet<>();
        queue.add(new Result(input, List.of(), score(input)));
        visited.add(input);
        int attempts = 0;
        while (!queue.isEmpty() && attempts++ < 300) {
            if (Thread.currentThread().isInterrupted()) {
                throw new java.util.concurrent.CancellationException("Decoding cancelled");
            }
            Result current = queue.remove();
            results.add(current);
            if (current.steps().size() >= maxDepth) {
                continue;
            }
            for (String format : List.of("Base64", "Base64URL", "Base32", "Base58", "Base62", "Base85", "Base91", "Base92", "HEX", "URL", "Unicode", "HTML", "Binary", "Decimal", "JWT")) {
                String decoded = tryDecode(current.output(), format);
                if (decoded == null || decoded.equals(current.output()) || visited.contains(decoded)) {
                    continue;
                }
                visited.add(decoded);
                List<Step> steps = new ArrayList<>(current.steps());
                steps.add(new Step(format, preview(decoded)));
                double structureBonus = format.equals("JWT") ? 200 : format.startsWith("Base") ? 3 : 5;
                queue.add(new Result(decoded, List.copyOf(steps), score(decoded) + structureBonus - steps.size() * 0.5));
            }
        }
        results.sort(Comparator.comparingDouble(Result::score).reversed()
                .thenComparingInt(result -> result.steps().size()));
        return List.copyOf(results);
    }

    public static String identify(String input) {
        StringBuilder output = new StringBuilder();
        for (String format : List.of("Base64", "Base64URL", "Base32", "Base58", "Base62", "Base85", "Base91", "Base92", "HEX", "URL", "Unicode", "HTML", "Binary", "Decimal", "JWT")) {
            String decoded = tryDecode(input, format);
            if (decoded != null) {
                output.append(format).append(" (").append(preview(decoded)).append(")\n");
            }
        }
        return output.isEmpty() ? "No supported encoding detected" : output.toString().trim();
    }

    private static String tryDecode(String input, String format) {
        String value = input.trim();
        if (value.length() < 2) {
            return null;
        }
        try {
            String decoded = switch (format) {
                case "Base64" -> decodeBase64(value);
                case "Base64URL" -> decodeBase64Url(value);
                case "Base32" -> decodeBase32(value);
                case "Base58" -> decodeBase58(value);
                case "Base62" -> decodeBase62(value);
                case "Base85" -> decodeBase85(value);
                case "Base91" -> decodeBase91(value);
                case "Base92" -> decodeBase92(value);
                case "JWT" -> decodeJwt(value);
                case "HEX" -> decodeHex(value);
                case "URL" -> decodeUrl(value);
                case "Unicode" -> decodeUnicode(value);
                case "HTML" -> decodeHtml(value);
                case "Binary" -> decodeBinary(value);
                case "Decimal" -> decodeDecimal(value);
                default -> null;
            };
            if (decoded == null || decoded.isEmpty()) {
                return null;
            }
            double threshold = format.equals("Base58") || format.equals("Base62") || format.equals("Base85")
                    || format.equals("Base91") || format.equals("Base92") ? 0.85 : 0.65;
            return printableRatio(decoded) >= threshold ? decoded : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    private static String decodeBase64(String value) {
        String normalized = value.replaceAll("\\s", "");
        if (normalized.length() < 8 || normalized.length() % 4 != 0 || !BASE64.matcher(normalized).matches()) {
            return null;
        }
        return new String(Base64.getDecoder().decode(normalized), StandardCharsets.UTF_8);
    }

    private static String decodeBase64Url(String value) {
        String normalized = value.replaceAll("\\s", "");
        if (normalized.length() < 8 || !normalized.matches("[A-Za-z0-9_-]+={0,2}")) {
            return null;
        }
        return new String(Base64.getUrlDecoder().decode(normalized), StandardCharsets.UTF_8);
    }

    private static String decodeBase58(String value) throws java.io.UnsupportedEncodingException {
        if (value.length() < 8 || !value.matches("[1-9A-HJ-NP-Za-km-z]+")) {
            return null;
        }
        return myxfc.App.View.Modules.Encryption.Coding.BaseEncoding.Base58.Base58Impl.decodeToString(value, "UTF-8");
    }

    private static String decodeBase62(String value) throws java.io.UnsupportedEncodingException {
        if (value.length() < 8 || !value.matches("[A-Za-z0-9]+")) {
            return null;
        }
        return myxfc.App.View.Modules.Encryption.Coding.BaseEncoding.Base62.Base62Impl.decodeToString(value, "UTF-8");
    }

    private static String decodeBase85(String value) throws java.io.UnsupportedEncodingException {
        if (value.length() < 10 || !value.matches("[!-z~ <>]+")) {
            return null;
        }
        return myxfc.App.View.Modules.Encryption.Coding.BaseEncoding.Base85.Base85Impl.decodeAscii85ToString(value, "UTF-8");
    }

    private static String decodeBase91(String value) throws java.io.UnsupportedEncodingException {
        if (value.length() < 10) {
            return null;
        }
        return myxfc.App.View.Modules.Encryption.Coding.BaseEncoding.Base91.Base91Impl.decodeToString(value, "UTF-8");
    }

    private static String decodeBase92(String value) throws java.io.UnsupportedEncodingException {
        if (value.length() < 10 || value.contains(" ")) {
            return null;
        }
        return myxfc.App.View.Modules.Encryption.Coding.BaseEncoding.Base92.Base92Impl.decodeToString(value, "UTF-8");
    }

    private static String decodeJwt(String value) {
        java.util.regex.Matcher matcher = Pattern.compile("(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*").matcher(value);
        if (!matcher.find()) {
            return null;
        }
        String token = matcher.group();
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3 || parts[0].isEmpty() || parts[1].isEmpty()) {
            return null;
        }
        String header = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        if (!header.trim().startsWith("{") || !payload.trim().startsWith("{")) {
            return null;
        }
        return "Header: " + header + "\nPayload: " + payload;
    }

    private static String decodeBase32(String value) {
        String normalized = value.toUpperCase().replaceAll("\\s", "");
        if (normalized.length() < 8 || normalized.length() % 8 != 0 || !BASE32.matcher(normalized).matches()) {
            return null;
        }
        return new String(CustomBaseImpl.decode(normalized, BASE32_ALPHABET, '=', true), StandardCharsets.UTF_8);
    }

    private static String decodeHex(String value) {
        String normalized = value.replaceAll("\\s", "").replace("0x", "").replace("0X", "");
        if (normalized.length() < 8 || normalized.length() % 2 != 0 || !normalized.matches("[0-9a-fA-F]+")) {
            return null;
        }
        return new String(HexFormat.of().parseHex(normalized), StandardCharsets.UTF_8);
    }

    private static String decodeUrl(String value) {
        if (!value.matches(".*%[0-9a-fA-F]{2}.*") && !value.contains("+")) {
            return null;
        }
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    private static String decodeUnicode(String value) {
        if (!value.matches(".*\\\\u[0-9a-fA-F]{4}.*")) {
            return null;
        }
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            if (i + 6 <= value.length() && value.charAt(i) == '\\' && value.charAt(i + 1) == 'u') {
                result.append((char) Integer.parseInt(value.substring(i + 2, i + 6), 16));
                i += 5;
            } else {
                result.append(value.charAt(i));
            }
        }
        return result.toString();
    }

    private static String decodeHtml(String value) {
        if (!value.matches(".*&(?:#\\d+|#x[0-9a-fA-F]+|[A-Za-z]+);.*")) {
            return null;
        }
        java.util.regex.Matcher matcher = Pattern.compile("&#(x?[0-9a-fA-F]+);").matcher(value);
        StringBuffer output = new StringBuffer();
        while (matcher.find()) {
            String entity = matcher.group(1);
            int codePoint = Integer.parseInt(entity.startsWith("x") ? entity.substring(1) : entity,
                    entity.startsWith("x") ? 16 : 10);
            matcher.appendReplacement(output, new String(Character.toChars(codePoint)));
        }
        matcher.appendTail(output);
        return output.toString().replace("&amp;", "&").replace("&lt;", "<")
                .replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'");
    }

    private static String decodeBinary(String value) {
        String normalized = value.replaceAll("\\s", "");
        if (normalized.length() < 16 || normalized.length() % 8 != 0 || !normalized.matches("[01]+")) {
            return null;
        }
        byte[] bytes = new byte[normalized.length() / 8];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(normalized.substring(i * 8, i * 8 + 8), 2);
        }
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private static String decodeDecimal(String value) {
        String normalized = value.trim();
        if (!normalized.matches("\\d+(?:[ ,;]+\\d+)+")) {
            return null;
        }
        String[] parts = normalized.split("[ ,;]+");
        if (parts.length < 2) {
            return null;
        }
        ByteArrayOutput output = new ByteArrayOutput(parts.length);
        for (String part : parts) {
            if (!DECIMAL.matcher(part).matches()) {
                return null;
            }
            int number = Integer.parseInt(part);
            if (number > 255) {
                return null;
            }
            output.write(number);
        }
        return new String(output.bytes, StandardCharsets.UTF_8);
    }

    private static double score(String value) {
        double score = printableRatio(value) * 100;
        String lower = value.toLowerCase();
        if (lower.contains("flag{") || lower.contains("ctf{")) {
            score += 200;
        }
        if (value.matches("(?s)^[\\x20-\\x7E\\r\\n\\t]+$")) {
            score += 20;
        }
        return score;
    }

    private static double printableRatio(String value) {
        if (value.isEmpty()) {
            return 0;
        }
        int printable = 0;
        for (char c : value.toCharArray()) {
            if (c == 9 || c == 10 || c == 13 || c >= 32 && c < 127
                    || c >= 160 && c != '\uFFFD' && !Character.isISOControl(c)) {
                printable++;
            }
        }
        return (double) printable / value.length();
    }

    private static String preview(String value) {
        String normalized = value.replace("\r", "\\r").replace("\n", "\\n");
        return normalized.length() <= 70 ? normalized : normalized.substring(0, 70) + "...";
    }

    private static final class ByteArrayOutput {
        private final byte[] bytes;
        private int offset;

        private ByteArrayOutput(int length) {
            bytes = new byte[length];
        }

        private void write(int value) {
            bytes[offset++] = (byte) value;
        }
    }
}
