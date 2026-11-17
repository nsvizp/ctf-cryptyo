package myxfc.App.View.Modules.Tools.CTF.Engine.Crypto;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

public class ClassicalAttackService {
    private static final double[] FREQUENCIES = {
            8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772,
            4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978,
            2.360, 0.150, 1.974, 0.074
    };

    public record Result(String key, String plaintext, double score, int keyLength) {
    }

    public static List<Result> crackVigenere(String ciphertext, int maximumKeyLength) {
        String normalized = letters(ciphertext);
        if (normalized.length() < 4) {
            throw new IllegalArgumentException("At least four letters are required");
        }
        List<int[]> lengths = new ArrayList<>();
        for (int length = 1; length <= Math.min(maximumKeyLength, 40); length++) {
            double score = 0;
            int groups = 0;
            for (int offset = 0; offset < length; offset++) {
                String group = group(normalized, offset, length);
                if (group.length() > 1) {
                    score += indexOfCoincidence(group);
                    groups++;
                }
            }
            lengths.add(new int[]{length, (int) Math.abs(score / groups - 0.066) * 100000});
        }
        lengths.sort(Comparator.comparingInt(value -> value[1]));
        List<Result> results = new ArrayList<>();
        for (int i = 0; i < Math.min(6, lengths.size()); i++) {
            int length = lengths.get(i)[0];
            StringBuilder key = new StringBuilder();
            for (int offset = 0; offset < length; offset++) {
                key.append(bestShift(group(normalized, offset, length)));
            }
            String plaintext = vigenere(ciphertext, key.toString(), false);
            results.add(new Result(key.toString(), plaintext, englishScore(plaintext), length));
        }
        results.sort(Comparator.comparingDouble(Result::score));
        return results;
    }

    public static String vigenere(String input, String key, boolean encrypt) {
        String normalizedKey = letters(key);
        if (normalizedKey.isEmpty()) {
            throw new IllegalArgumentException("Vigenere key must contain letters");
        }
        StringBuilder result = new StringBuilder();
        int keyIndex = 0;
        for (char c : input.toCharArray()) {
            if (!Character.isLetter(c)) {
                result.append(c);
                continue;
            }
            int shift = normalizedKey.charAt(keyIndex++ % normalizedKey.length()) - 'A';
            if (!encrypt) {
                shift = -shift;
            }
            char base = Character.isUpperCase(c) ? 'A' : 'a';
            result.append((char) (base + Math.floorMod(c - base + shift, 26)));
        }
        return result.toString();
    }

    public static List<Result> crackRepeatingXor(byte[] ciphertext, int maximumKeyLength) {
        if (ciphertext.length < 8) {
            throw new IllegalArgumentException("At least eight ciphertext bytes are required");
        }
        List<int[]> lengths = new ArrayList<>();
        for (int length = 1; length <= Math.min(maximumKeyLength, 40); length++) {
            double distance = 0;
            int pairs = 0;
            for (int block = 0; block < 8 && (block + 2) * length <= ciphertext.length; block++) {
                distance += hamming(ciphertext, block * length, (block + 1) * length, length) / (double) length;
                pairs++;
            }
            lengths.add(new int[]{length, pairs == 0 ? Integer.MAX_VALUE : (int) (distance / pairs * 1000)});
        }
        lengths.sort(Comparator.comparingInt(value -> value[1]));
        List<Result> results = new ArrayList<>();
        for (int i = 0; i < Math.min(6, lengths.size()); i++) {
            int length = lengths.get(i)[0];
            byte[] key = new byte[length];
            for (int offset = 0; offset < length; offset++) {
                key[offset] = bestXorByte(ciphertext, offset, length);
            }
            byte[] plaintext = xor(ciphertext, key);
            String keyText = java.util.HexFormat.of().formatHex(key);
            results.add(new Result(keyText, printable(plaintext), englishScore(printable(plaintext)), length));
        }
        results.sort(Comparator.comparingDouble(Result::score));
        return results;
    }

    public static byte[] recoverXorKey(byte[] ciphertext, byte[] knownPlaintext) {
        int length = Math.min(ciphertext.length, knownPlaintext.length);
        byte[] key = new byte[length];
        for (int i = 0; i < length; i++) {
            key[i] = (byte) (ciphertext[i] ^ knownPlaintext[i]);
        }
        return key;
    }

    private static byte bestXorByte(byte[] ciphertext, int offset, int length) {
        byte best = 0;
        double bestScore = Double.MAX_VALUE;
        for (int candidate = 0; candidate < 256; candidate++) {
            double score = 0;
            for (int i = offset; i < ciphertext.length; i += length) {
                int value = (ciphertext[i] ^ candidate) & 0xFF;
                score += characterCost(value);
            }
            if (score < bestScore) {
                bestScore = score;
                best = (byte) candidate;
            }
        }
        return best;
    }

    private static double characterCost(int value) {
        if (value == ' ') return -2;
        if (value >= 'a' && value <= 'z') return -FREQUENCIES[value - 'a'];
        if (value >= 'A' && value <= 'Z') return -FREQUENCIES[value - 'A'] * 0.8;
        if (value >= '0' && value <= '9' || value == '{' || value == '}' || value == '_' || value == '-') return 0;
        if (value == 10 || value == 13 || value == 9 || value >= 32 && value < 127) return 1;
        return 12;
    }

    private static char bestShift(String group) {
        char best = 'A';
        double bestScore = Double.MAX_VALUE;
        for (int shift = 0; shift < 26; shift++) {
            int[] counts = new int[26];
            for (char c : group.toCharArray()) {
                counts[Math.floorMod(c - 'A' - shift, 26)]++;
            }
            double score = 0;
            for (int i = 0; i < 26; i++) {
                double expected = group.length() * FREQUENCIES[i] / 100;
                score += Math.pow(counts[i] - expected, 2) / Math.max(0.01, expected);
            }
            if (score < bestScore) {
                bestScore = score;
                best = (char) ('A' + shift);
            }
        }
        return best;
    }

    private static double englishScore(String value) {
        double score = 0;
        String upper = value.toUpperCase();
        for (char c : upper.toCharArray()) {
            if (c >= 'A' && c <= 'Z') {
                score -= FREQUENCIES[c - 'A'];
            } else if (c == ' ') {
                score -= 3;
            } else if (!Character.isLetterOrDigit(c) && !Character.isWhitespace(c)) {
                score += 0.2;
            }
        }
        for (String word : List.of(" THE ", "FLAG{", "CTF{", " AND ", " IS ", " TO ")) {
            if (upper.contains(word)) {
                score -= 30;
            }
        }
        return score;
    }

    private static double indexOfCoincidence(String value) {
        int[] counts = new int[26];
        for (char c : value.toCharArray()) {
            counts[c - 'A']++;
        }
        double sum = 0;
        for (int count : counts) {
            sum += (double) count * (count - 1);
        }
        return sum / ((double) value.length() * (value.length() - 1));
    }

    private static String group(String value, int offset, int length) {
        StringBuilder result = new StringBuilder();
        for (int i = offset; i < value.length(); i += length) {
            result.append(value.charAt(i));
        }
        return result.toString();
    }

    private static String letters(String value) {
        return value.toUpperCase(Locale.ROOT).replaceAll("[^A-Z]", "");
    }

    private static int hamming(byte[] data, int first, int second, int length) {
        int result = 0;
        for (int i = 0; i < length; i++) {
            result += Integer.bitCount((data[first + i] ^ data[second + i]) & 0xFF);
        }
        return result;
    }

    private static byte[] xor(byte[] data, byte[] key) {
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ key[i % key.length]);
        }
        return result;
    }

    private static String printable(byte[] data) {
        StringBuilder result = new StringBuilder();
        for (byte value : data) {
            int c = value & 0xFF;
            result.append(c == 10 || c == 13 || c == 9 || c >= 32 && c < 127 ? (char) c : '.');
        }
        return result.toString();
    }
}
