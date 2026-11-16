package myxfc.App.View.Modules.Encryption.Coding.XOR;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class XORImpl {
    public static byte[] encrypt(byte[] data, byte[] key) {
        if (data == null) {
            throw new IllegalArgumentException("Input must not be null");
        }
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("Key must not be empty");
        }
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ key[i % key.length]);
        }
        return result;
    }

    public static List<BruteForceResult> bruteForceSingleByte(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Input must not be null");
        }
        List<BruteForceResult> results = new ArrayList<>(256);
        for (int key = 0; key < 256; key++) {
            byte[] plaintext = encrypt(data, new byte[]{(byte) key});
            results.add(new BruteForceResult(key, plaintext, score(plaintext)));
        }
        results.sort(Comparator.comparingDouble(BruteForceResult::score).reversed()
                .thenComparingInt(BruteForceResult::key));
        return results;
    }

    private static double score(byte[] data) {
        if (data.length == 0) {
            return 0;
        }
        String text = new String(data, StandardCharsets.ISO_8859_1).toLowerCase();
        double score = 0;
        for (int i = 0; i < data.length; i++) {
            int value = data[i] & 0xFF;
            char c = (char) value;
            if (value == 10 || value == 13 || value == 9) {
                score += 0.4;
            } else if (value >= 32 && value <= 126) {
                score += 1;
            } else {
                score -= 5;
            }
            if ("etaoin shrdlu".indexOf(c) >= 0) {
                score += 0.35;
            }
            if ("{}_:-".indexOf(c) >= 0) {
                score += 0.15;
            }
        }
        if (text.contains("flag{") || text.contains("ctf{")) {
            score += 20;
        }
        return score / data.length;
    }

    public record BruteForceResult(int key, byte[] plaintext, double score) {
    }
}
