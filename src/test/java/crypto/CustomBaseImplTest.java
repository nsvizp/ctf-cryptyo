package crypto;

import myxfc.App.View.Modules.Encryption.Coding.BaseEncoding.CustomBase.CustomBaseImpl;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CustomBaseImplTest {
    private static final String BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    private static final String BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final String BASE16 = "0123456789ABCDEF";

    @Test
    void standardAlphabetsMatchRfcVectors() {
        byte[] input = "foobar".getBytes(StandardCharsets.UTF_8);
        assertEquals("Zm9vYmFy", CustomBaseImpl.encode(input, BASE64, '=', true));
        assertEquals("MZXW6YTBOI======", CustomBaseImpl.encode(input, BASE32, '=', true));
        assertEquals("666F6F626172", CustomBaseImpl.encode(input, BASE16, '=', true));
        assertArrayEquals(input, CustomBaseImpl.decode("Zm9vYmFy", BASE64, '=', true));
        assertArrayEquals(input, CustomBaseImpl.decode("MZXW6YTBOI======", BASE32, '=', true));
        assertArrayEquals(input, CustomBaseImpl.decode("666F6F626172", BASE16, '=', true));
    }

    @Test
    void customAlphabetRoundTripsArbitraryBytes() {
        String reversed = new StringBuilder(BASE64).reverse().toString();
        byte[] input = new byte[]{0, 1, 2, 3, 127, -128, -1};
        String encoded = CustomBaseImpl.encode(input, reversed, '=', true);
        assertArrayEquals(input, CustomBaseImpl.decode(encoded, reversed, '=', true));
    }

    @Test
    void unpaddedModeMatchesJdk() {
        byte[] input = "myxfc".getBytes(StandardCharsets.UTF_8);
        String expected = Base64.getEncoder().withoutPadding().encodeToString(input);
        assertEquals(expected, CustomBaseImpl.encode(input, BASE64, '=', false));
        assertArrayEquals(input, CustomBaseImpl.decode(expected, BASE64, '=', false));
    }

    @Test
    void invalidAlphabetAndPaddingAreRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> CustomBaseImpl.encode(new byte[0], "ABC", '=', true));
        assertThrows(IllegalArgumentException.class,
                () -> CustomBaseImpl.decode("Zg===", BASE64, '=', true));
        assertThrows(IllegalArgumentException.class,
                () -> CustomBaseImpl.decode("Zh==", BASE64, '=', true));
    }
}
