package myxfc.App.View.Modules.Encryption.Coding.BaseEncoding.CustomBase;

import java.util.HashMap;
import java.util.Map;

public class CustomBaseImpl {
    public static String encode(byte[] input, String alphabet, char padding, boolean usePadding) {
        validateAlphabet(alphabet, padding);
        if (input == null) {
            throw new IllegalArgumentException("Input must not be null");
        }
        int bitsPerCharacter = bitsPerCharacter(alphabet.length());
        int mask = alphabet.length() - 1;
        StringBuilder result = new StringBuilder();
        int buffer = 0;
        int availableBits = 0;
        for (byte value : input) {
            buffer = (buffer << 8) | (value & 0xFF);
            availableBits += 8;
            while (availableBits >= bitsPerCharacter) {
                availableBits -= bitsPerCharacter;
                result.append(alphabet.charAt((buffer >>> availableBits) & mask));
            }
            buffer &= availableBits == 0 ? 0 : (1 << availableBits) - 1;
        }
        if (availableBits > 0) {
            result.append(alphabet.charAt((buffer << (bitsPerCharacter - availableBits)) & mask));
        }
        if (usePadding) {
            int blockLength = blockLength(bitsPerCharacter);
            while (result.length() % blockLength != 0) {
                result.append(padding);
            }
        }
        return result.toString();
    }

    public static byte[] decode(String input, String alphabet, char padding, boolean usePadding) {
        validateAlphabet(alphabet, padding);
        if (input == null) {
            throw new IllegalArgumentException("Input must not be null");
        }
        String normalized = input.replaceAll("\\s", "");
        int bitsPerCharacter = bitsPerCharacter(alphabet.length());
        int firstPadding = normalized.indexOf(padding);
        String data = firstPadding < 0 ? normalized : normalized.substring(0, firstPadding);
        String paddingText = firstPadding < 0 ? "" : normalized.substring(firstPadding);
        for (int i = 0; i < paddingText.length(); i++) {
            if (paddingText.charAt(i) != padding) {
                throw new IllegalArgumentException("Padding is only allowed at the end");
            }
        }
        if (usePadding) {
            if (normalized.length() % blockLength(bitsPerCharacter) != 0) {
                throw new IllegalArgumentException("Invalid padded input length");
            }
        } else if (!paddingText.isEmpty()) {
            throw new IllegalArgumentException("Padding is disabled");
        }

        Map<Character, Integer> indexes = indexMap(alphabet);
        byte[] output = new byte[data.length() * bitsPerCharacter / 8];
        int outputIndex = 0;
        int buffer = 0;
        int availableBits = 0;
        int mask = 0xFF;
        for (char c : data.toCharArray()) {
            Integer value = indexes.get(c);
            if (value == null) {
                throw new IllegalArgumentException("Character is not in the custom alphabet: " + c);
            }
            buffer = (buffer << bitsPerCharacter) | value;
            availableBits += bitsPerCharacter;
            if (availableBits >= 8) {
                availableBits -= 8;
                output[outputIndex++] = (byte) ((buffer >>> availableBits) & mask);
            }
            buffer &= availableBits == 0 ? 0 : (1 << availableBits) - 1;
        }
        if (availableBits > 0 && buffer != 0) {
            throw new IllegalArgumentException("Non-zero trailing bits in encoded input");
        }
        byte[] result = java.util.Arrays.copyOf(output, outputIndex);
        if (!encode(result, alphabet, padding, usePadding).equals(normalized)) {
            throw new IllegalArgumentException("Non-canonical encoding or invalid padding");
        }
        return result;
    }

    private static void validateAlphabet(String alphabet, char padding) {
        if (alphabet == null) {
            throw new IllegalArgumentException("Alphabet must not be null");
        }
        int length = alphabet.length();
        if (length != 16 && length != 32 && length != 64) {
            throw new IllegalArgumentException("Alphabet length must be 16, 32 or 64");
        }
        if (indexMap(alphabet).size() != length) {
            throw new IllegalArgumentException("Alphabet characters must be unique");
        }
        if (alphabet.indexOf(padding) >= 0) {
            throw new IllegalArgumentException("Padding character must not occur in the alphabet");
        }
        for (int i = 0; i < alphabet.length(); i++) {
            if (Character.isWhitespace(alphabet.charAt(i))) {
                throw new IllegalArgumentException("Alphabet must not contain whitespace");
            }
        }
    }

    private static Map<Character, Integer> indexMap(String alphabet) {
        Map<Character, Integer> indexes = new HashMap<>();
        for (int i = 0; i < alphabet.length(); i++) {
            indexes.put(alphabet.charAt(i), i);
        }
        return indexes;
    }

    private static int bitsPerCharacter(int alphabetLength) {
        return Integer.numberOfTrailingZeros(alphabetLength);
    }

    private static int blockLength(int bitsPerCharacter) {
        int gcd = gcd(bitsPerCharacter, 8);
        return 8 / gcd;
    }

    private static int gcd(int a, int b) {
        while (b != 0) {
            int remainder = a % b;
            a = b;
            b = remainder;
        }
        return a;
    }
}
