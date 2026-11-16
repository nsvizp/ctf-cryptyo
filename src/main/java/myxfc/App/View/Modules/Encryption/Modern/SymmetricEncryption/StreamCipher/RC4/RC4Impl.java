package myxfc.App.View.Modules.Encryption.Modern.SymmetricEncryption.StreamCipher.RC4;

public class RC4Impl {
    public static byte[] crypt(byte[] data, byte[] key) {
        if (data == null) {
            throw new IllegalArgumentException("Input must not be null");
        }
        if (key == null || key.length == 0 || key.length > 256) {
            throw new IllegalArgumentException("RC4 key length must be between 1 and 256 bytes");
        }
        int[] state = new int[256];
        for (int i = 0; i < 256; i++) {
            state[i] = i;
        }
        int j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + state[i] + (key[i % key.length] & 0xFF)) & 0xFF;
            swap(state, i, j);
        }
        byte[] output = new byte[data.length];
        int i = 0;
        j = 0;
        for (int offset = 0; offset < data.length; offset++) {
            i = (i + 1) & 0xFF;
            j = (j + state[i]) & 0xFF;
            swap(state, i, j);
            int keyStream = state[(state[i] + state[j]) & 0xFF];
            output[offset] = (byte) (data[offset] ^ keyStream);
        }
        return output;
    }

    private static void swap(int[] state, int first, int second) {
        int value = state[first];
        state[first] = state[second];
        state[second] = value;
    }
}
