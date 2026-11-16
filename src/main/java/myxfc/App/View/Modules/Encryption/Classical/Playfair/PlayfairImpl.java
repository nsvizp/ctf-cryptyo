package myxfc.App.View.Modules.Encryption.Classical.Playfair;

public class PlayfairImpl {
    public static String encrypt(String input, String key) {
        char[] square = createSquare(key);
        String plaintext = preparePlaintext(input);
        return transformPairs(plaintext, square, true);
    }

    public static String decrypt(String input, String key) {
        char[] square = createSquare(key);
        String ciphertext = normalize(input);
        if (ciphertext.length() % 2 != 0) {
            throw new IllegalArgumentException("Playfair ciphertext length must be even");
        }
        return transformPairs(ciphertext, square, false);
    }

    public static String createSquareText(String key) {
        return new String(createSquare(key));
    }

    private static String transformPairs(String input, char[] square, boolean encrypt) {
        StringBuilder result = new StringBuilder(input.length());
        int shift = encrypt ? 1 : -1;
        for (int offset = 0; offset < input.length(); offset += 2) {
            char first = input.charAt(offset);
            char second = input.charAt(offset + 1);
            int firstIndex = indexOf(square, first);
            int secondIndex = indexOf(square, second);
            int firstRow = firstIndex / 5;
            int firstColumn = firstIndex % 5;
            int secondRow = secondIndex / 5;
            int secondColumn = secondIndex % 5;
            if (firstRow == secondRow) {
                result.append(square[firstRow * 5 + Math.floorMod(firstColumn + shift, 5)]);
                result.append(square[secondRow * 5 + Math.floorMod(secondColumn + shift, 5)]);
            } else if (firstColumn == secondColumn) {
                result.append(square[Math.floorMod(firstRow + shift, 5) * 5 + firstColumn]);
                result.append(square[Math.floorMod(secondRow + shift, 5) * 5 + secondColumn]);
            } else {
                result.append(square[firstRow * 5 + secondColumn]);
                result.append(square[secondRow * 5 + firstColumn]);
            }
        }
        return result.toString();
    }

    private static String preparePlaintext(String input) {
        String normalized = normalize(input);
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < normalized.length(); i++) {
            char first = normalized.charAt(i);
            result.append(first);
            if (i + 1 >= normalized.length()) {
                result.append(first == 'X' ? 'Q' : 'X');
            } else {
                char second = normalized.charAt(i + 1);
                if (first == second) {
                    result.append(first == 'X' ? 'Q' : 'X');
                } else {
                    result.append(second);
                    i++;
                }
            }
        }
        return result.toString();
    }

    private static String normalize(String input) {
        if (input == null) {
            throw new IllegalArgumentException("Input must not be null");
        }
        return input.toUpperCase().replace('J', 'I').replaceAll("[^A-Z]", "");
    }

    private static char[] createSquare(String key) {
        String source = normalize(key) + "ABCDEFGHIKLMNOPQRSTUVWXYZ";
        StringBuilder square = new StringBuilder(25);
        for (char c : source.toCharArray()) {
            if (square.indexOf(String.valueOf(c)) < 0) {
                square.append(c);
            }
        }
        return square.toString().toCharArray();
    }

    private static int indexOf(char[] square, char value) {
        for (int i = 0; i < square.length; i++) {
            if (square[i] == value) {
                return i;
            }
        }
        throw new IllegalArgumentException("Character not present in Playfair square: " + value);
    }
}
