package myxfc.App.View.Modules.Tools.CTF.Engine.Decode;

import myxfc.App.View.Modules.Encryption.Coding.XOR.XORImpl;
import myxfc.App.View.Modules.Encryption.Modern.SymmetricEncryption.StreamCipher.RC4.RC4Impl;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class CryptoDecodeService {
    private static final List<String> COMMON_KEYS = List.of("key", "flag", "ctf", "admin", "password", "123456");

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public record Candidate(String algorithm, String key, String output, double score) {
    }

    public static List<Candidate> decode(String input, String key, String iv) {
        List<Candidate> candidates = new ArrayList<>();
        if (input == null || input.isBlank()) {
            throw new IllegalArgumentException("Input must not be empty");
        }
        java.util.regex.Matcher jwtMatcher = java.util.regex.Pattern
                .compile("[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*").matcher(input.trim());
        if (jwtMatcher.find()) {
            candidates.add(jwt(jwtMatcher.group(), key));
        }
        for (EncodedInput encoded : inputs(input)) {
            if (key == null || key.isBlank()) {
                candidates.addAll(xorBruteForce(encoded));
            } else {
                byte[] output = XORImpl.encrypt(encoded.data, parseSecret(key));
                addCandidate(candidates, "XOR", key, output);
            }
            for (String candidateKey : keys(key)) {
                try {
                    addCandidate(candidates, "RC4", candidateKey, RC4Impl.crypt(encoded.data,
                            parseSecret(candidateKey)));
                } catch (Exception ignored) {
                }
                for (String algorithm : List.of("SM4", "AES", "DES", "DESede")) {
                    for (String mode : modes(iv)) {
                        try {
                            byte[] output = decrypt(algorithm, mode, encoded.data,
                                    normalizeKey(candidateKey, algorithm), ivBytes(iv, algorithm));
                            addCandidate(candidates, algorithm + "/" + mode, candidateKey, output);
                        } catch (Exception ignored) {
                        }
                    }
                }
            }
        }
        candidates.sort(Comparator.comparingDouble(Candidate::score).reversed());
        return List.copyOf(candidates);
    }

    private static List<EncodedInput> inputs(String input) {
        List<EncodedInput> result = new ArrayList<>();
        String normalized = input.replaceAll("\\s", "");
        if (normalized.length() % 2 == 0 && normalized.matches("[0-9a-fA-F]+")) {
            try {
                result.add(new EncodedInput("HEX", HexFormat.of().parseHex(normalized)));
            } catch (Exception ignored) {
            }
        }
        if (normalized.length() % 4 == 0 && normalized.matches("[A-Za-z0-9+/]*={0,2}")) {
            try {
                result.add(new EncodedInput("Base64", Base64.getDecoder().decode(normalized)));
            } catch (Exception ignored) {
            }
        }
        result.add(new EncodedInput("Text", input.getBytes(StandardCharsets.UTF_8)));
        return result;
    }

    private static List<Candidate> xorBruteForce(EncodedInput input) {
        List<Candidate> result = new ArrayList<>();
        for (XORImpl.BruteForceResult brute : XORImpl.bruteForceSingleByte(input.data).stream().limit(3).toList()) {
            String key = String.format("0x%02X", brute.key());
            result.add(new Candidate("XOR/" + input.encoding, key, printable(brute.plaintext()), brute.score() + 40));
        }
        return result;
    }

    private static byte[] decrypt(String algorithm, String mode, byte[] input, byte[] key, byte[] iv) throws Exception {
        String padding = "PKCS5Padding";
        Cipher cipher = Cipher.getInstance(algorithm + "/" + mode + "/" + padding);
        SecretKeySpec keySpec = new SecretKeySpec(key, algorithm);
        if (mode.equals("ECB")) {
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
        } else {
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
        }
        return cipher.doFinal(input);
    }

    private static List<String> keys(String supplied) {
        Set<String> result = new LinkedHashSet<>();
        if (supplied != null && !supplied.isBlank()) {
            result.add(supplied);
        } else {
            result.addAll(COMMON_KEYS);
        }
        return List.copyOf(result);
    }

    private static List<String> modes(String iv) {
        return iv == null || iv.isBlank() ? List.of("ECB", "CBC") : List.of("CBC");
    }

    private static byte[] normalizeKey(String text, String algorithm) {
        int length = switch (algorithm) {
            case "DES" -> 8;
            case "DESede" -> 24;
            default -> 16;
        };
        byte[] source = parseSecret(text);
        byte[] result = new byte[length];
        System.arraycopy(source, 0, result, 0, Math.min(source.length, length));
        return result;
    }

    private static byte[] ivBytes(String iv, String algorithm) {
        if (iv == null || iv.isBlank()) {
            return new byte["DES".equals(algorithm) || "DESede".equals(algorithm) ? 8 : 16];
        }
        byte[] source = parseSecret(iv);
        byte[] result = new byte["DES".equals(algorithm) || "DESede".equals(algorithm) ? 8 : 16];
        System.arraycopy(source, 0, result, 0, Math.min(source.length, result.length));
        return result;
    }

    private static byte[] parseSecret(String value) {
        if (value.startsWith("hex:")) {
            return HexFormat.of().parseHex(value.substring(4));
        }
        if (value.startsWith("base64:")) {
            return Base64.getDecoder().decode(value.substring(7));
        }
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static Candidate jwt(String token, String key) {
        try {
            String[] parts = token.split("\\.", -1);
            String header = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            String algorithm = header.replaceAll(".*\\\"alg\\\"\\s*:\\s*\\\"([^\\\"]+)\\\".*", "$1");
            String verification = "not verified";
            if (key != null && !key.isBlank() && algorithm.startsWith("HS")) {
                Mac mac = Mac.getInstance("HmacSHA" + algorithm.substring(2));
                mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA" + algorithm.substring(2)));
                String expected = Base64.getUrlEncoder().withoutPadding().encodeToString(
                        mac.doFinal((parts[0] + "." + parts[1]).getBytes(StandardCharsets.UTF_8)));
                verification = expected.equals(parts[2]) ? "signature valid" : "signature invalid";
            }
            var analysis = JwtAnalysisService.analyze(token);
            return new Candidate("JWT/" + algorithm, key == null ? "" : key,
                    "Header: " + header + "\nPayload: " + payload + "\n" + verification
                            + "\nIssues: " + analysis.issues(), 300);
        } catch (Exception e) {
            return new Candidate("JWT", "", "Invalid JWT: " + e.getMessage(), -100);
        }
    }

    private static void addCandidate(List<Candidate> candidates, String algorithm, String key, byte[] output) {
        String text = printable(output);
        double score = score(text);
        if (score >= 45) {
            candidates.add(new Candidate(algorithm, key, text, score));
        }
    }

    private static double score(String text) {
        if (text.isEmpty()) {
            return 0;
        }
        int printable = 0;
        for (char c : text.toCharArray()) {
            if (c == 9 || c == 10 || c == 13 || c >= 32 && c < 127) {
                printable++;
            }
        }
        double score = printable * 100.0 / text.length();
        String lower = text.toLowerCase();
        if (lower.contains("flag{") || lower.contains("ctf{")) {
            score += 150;
        }
        if (lower.matches(".*\\b(the|this|is|hello|key|password)\\b.*")) {
            score += 20;
        }
        return score;
    }

    private static String printable(byte[] data) {
        StringBuilder result = new StringBuilder();
        for (byte value : data) {
            int c = value & 0xFF;
            result.append(c == 9 || c == 10 || c == 13 || c >= 32 && c < 127 ? (char) c : '.');
        }
        return result.toString();
    }

    private record EncodedInput(String encoding, byte[] data) {
    }
}
