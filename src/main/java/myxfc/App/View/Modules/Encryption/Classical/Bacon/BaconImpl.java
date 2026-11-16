package myxfc.App.View.Modules.Encryption.Classical.Bacon;

public class BaconImpl {
    private static final String ALPHABET_24 = "ABCDEFGHIKLMNOPQRSTUWXYZ";
    private static final String ALPHABET_26 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    public static String encrypt(String input, boolean use26Letters) {
        if (input == null) {
            throw new IllegalArgumentException("Input must not be null");
        }
        String alphabet = use26Letters ? ALPHABET_26 : ALPHABET_24;
        StringBuilder result = new StringBuilder();
        for (char original : input.toUpperCase().toCharArray()) {
            char c = normalize(original, use26Letters);
            if (c == 0) {
                continue;
            }
            int index = alphabet.indexOf(c);
            if (index < 0) {
                throw new IllegalArgumentException("Unsupported Bacon character: " + original);
            }
            for (int bit = 4; bit >= 0; bit--) {
                result.append((index & (1 << bit)) == 0 ? 'A' : 'B');
            }
        }
        return result.toString();
    }

    public static String decrypt(String input, boolean use26Letters) {
        if (input == null) {
            throw new IllegalArgumentException("Input must not be null");
        }
        String normalized = input.toUpperCase().replaceAll("\\s", "");
        if (normalized.length() % 5 != 0) {
            throw new IllegalArgumentException("Bacon ciphertext length must be divisible by 5");
        }
        String alphabet = use26Letters ? ALPHABET_26 : ALPHABET_24;
        StringBuilder result = new StringBuilder(normalized.length() / 5);
        for (int offset = 0; offset < normalized.length(); offset += 5) {
            int value = 0;
            for (int i = 0; i < 5; i++) {
                char c = normalized.charAt(offset + i);
                if (c != 'A' && c != 'B') {
                    throw new IllegalArgumentException("Bacon ciphertext must contain only A and B");
                }
                value = (value << 1) | (c == 'B' ? 1 : 0);
            }
            if (value >= alphabet.length()) {
                throw new IllegalArgumentException("Invalid Bacon group: " + normalized.substring(offset, offset + 5));
            }
            result.append(alphabet.charAt(value));
        }
        return result.toString();
    }

    private static char normalize(char c, boolean use26Letters) {
        if (c < 'A' || c > 'Z') {
            return 0;
        }
        if (!use26Letters) {
            if (c == 'J') {
                return 'I';
            }
            if (c == 'V') {
                return 'U';
            }
        }
        return c;
    }
}
