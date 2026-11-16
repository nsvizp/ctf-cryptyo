package myxfc.App.View.Modules.Encryption.Classical.Affine;

public class AffineImpl {
    public static String encrypt(String input, int a, int b) {
        return transform(input, a, b);
    }

    public static String decrypt(String input, int a, int b) {
        int inverse = modularInverse(a, 26);
        return transform(input, inverse, -inverse * b);
    }

    private static String transform(String input, int multiplier, int offset) {
        if (input == null) {
            throw new IllegalArgumentException("Input must not be null");
        }
        int a = Math.floorMod(multiplier, 26);
        modularInverse(a, 26);
        int b = Math.floorMod(offset, 26);
        StringBuilder result = new StringBuilder(input.length());
        for (char c : input.toCharArray()) {
            if (c >= 'A' && c <= 'Z') {
                result.append((char) ('A' + (a * (c - 'A') + b) % 26));
            } else if (c >= 'a' && c <= 'z') {
                result.append((char) ('a' + (a * (c - 'a') + b) % 26));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    private static int modularInverse(int value, int modulus) {
        int a = Math.floorMod(value, modulus);
        if (gcd(a, modulus) != 1) {
            throw new IllegalArgumentException("Affine parameter 'a' must be coprime to 26");
        }
        for (int candidate = 1; candidate < modulus; candidate++) {
            if (a * candidate % modulus == 1) {
                return candidate;
            }
        }
        throw new IllegalArgumentException("No modular inverse");
    }

    private static int gcd(int a, int b) {
        while (b != 0) {
            int remainder = a % b;
            a = b;
            b = remainder;
        }
        return Math.abs(a);
    }
}
