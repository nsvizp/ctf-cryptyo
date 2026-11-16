package myxfc.App.View.Modules.Encryption.Classical.Hill;

public class HillImpl {
    public static String encrypt(String input, int[][] key) {
        validateMatrix(key);
        return transform(input, key);
    }

    public static String decrypt(String input, int[][] key) {
        validateMatrix(key);
        return transform(input, inverseMatrix(key));
    }

    public static int[][] parseMatrix(String input) {
        if (input == null || input.isBlank()) {
            throw new IllegalArgumentException("Hill key matrix must not be empty");
        }
        String[] rows = input.trim().split("\\s*[;\\n]\\s*");
        int[][] matrix = new int[rows.length][];
        for (int row = 0; row < rows.length; row++) {
            String[] values = rows[row].trim().split("[,\\s]+");
            matrix[row] = new int[values.length];
            for (int column = 0; column < values.length; column++) {
                matrix[row][column] = Integer.parseInt(values[column]);
            }
        }
        validateMatrix(matrix);
        return matrix;
    }

    private static String transform(String input, int[][] matrix) {
        if (input == null) {
            throw new IllegalArgumentException("Input must not be null");
        }
        int size = matrix.length;
        String normalized = input.toUpperCase().replaceAll("[^A-Z]", "");
        StringBuilder padded = new StringBuilder(normalized);
        while (padded.length() % size != 0) {
            padded.append('X');
        }
        StringBuilder result = new StringBuilder(padded.length());
        for (int offset = 0; offset < padded.length(); offset += size) {
            for (int row = 0; row < size; row++) {
                int value = 0;
                for (int column = 0; column < size; column++) {
                    value += matrix[row][column] * (padded.charAt(offset + column) - 'A');
                }
                result.append((char) ('A' + Math.floorMod(value, 26)));
            }
        }
        return result.toString();
    }

    private static int[][] inverseMatrix(int[][] matrix) {
        int size = matrix.length;
        int determinant = Math.floorMod(determinant(matrix), 26);
        int inverseDeterminant = modularInverse(determinant, 26);
        int[][] inverse = new int[size][size];
        for (int row = 0; row < size; row++) {
            for (int column = 0; column < size; column++) {
                int cofactor = cofactor(matrix, column, row);
                inverse[row][column] = Math.floorMod(cofactor * inverseDeterminant, 26);
            }
        }
        return inverse;
    }

    private static int cofactor(int[][] matrix, int rowToRemove, int columnToRemove) {
        int size = matrix.length;
        if (size == 1) {
            return 1;
        }
        int[][] minor = new int[size - 1][size - 1];
        int targetRow = 0;
        for (int row = 0; row < size; row++) {
            if (row == rowToRemove) {
                continue;
            }
            int targetColumn = 0;
            for (int column = 0; column < size; column++) {
                if (column != columnToRemove) {
                    minor[targetRow][targetColumn++] = matrix[row][column];
                }
            }
            targetRow++;
        }
        int sign = (rowToRemove + columnToRemove) % 2 == 0 ? 1 : -1;
        return sign * determinant(minor);
    }

    private static int determinant(int[][] matrix) {
        if (matrix.length == 1) {
            return matrix[0][0];
        }
        if (matrix.length == 2) {
            return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0];
        }
        int result = 0;
        for (int column = 0; column < matrix.length; column++) {
            result += matrix[0][column] * cofactor(matrix, 0, column);
        }
        return result;
    }

    private static void validateMatrix(int[][] matrix) {
        if (matrix == null || matrix.length < 2 || matrix.length > 3) {
            throw new IllegalArgumentException("Hill key matrix must be 2x2 or 3x3");
        }
        for (int[] row : matrix) {
            if (row == null || row.length != matrix.length) {
                throw new IllegalArgumentException("Hill key matrix must be square");
            }
        }
        if (modularInverse(Math.floorMod(determinant(matrix), 26), 26) == -1) {
            throw new IllegalArgumentException("Hill key matrix is not invertible modulo 26");
        }
    }

    private static int modularInverse(int value, int modulus) {
        for (int candidate = 1; candidate < modulus; candidate++) {
            if (Math.floorMod(value * candidate, modulus) == 1) {
                return candidate;
            }
        }
        throw new IllegalArgumentException("Hill key matrix determinant must be coprime to 26");
    }
}
