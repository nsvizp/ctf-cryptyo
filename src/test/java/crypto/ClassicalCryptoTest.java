package crypto;

import myxfc.App.View.Modules.Encryption.Classical.Affine.AffineImpl;
import myxfc.App.View.Modules.Encryption.Classical.Bacon.BaconImpl;
import myxfc.App.View.Modules.Encryption.Classical.Hill.HillImpl;
import myxfc.App.View.Modules.Encryption.Classical.Playfair.PlayfairImpl;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ClassicalCryptoTest {
    @Test
    void affineMatchesKnownExampleAndPreservesText() {
        assertEquals("IHHWVCSWFRCP", AffineImpl.encrypt("AFFINECIPHER", 5, 8));
        assertEquals("AFFINECIPHER", AffineImpl.decrypt("IHHWVCSWFRCP", 5, 8));
        assertEquals("Hello, World!", AffineImpl.decrypt(AffineImpl.encrypt("Hello, World!", 7, 3), 7, 3));
        assertThrows(IllegalArgumentException.class, () -> AffineImpl.encrypt("A", 2, 1));
    }

    @Test
    void baconSupportsBothAlphabets() {
        assertEquals("AAAAAAAAABAAABA", BaconImpl.encrypt("ABC", true));
        assertEquals("ABC", BaconImpl.decrypt("AAAAAAAAABAAABA", true));
        assertEquals(BaconImpl.encrypt("I", false), BaconImpl.encrypt("J", false));
        assertEquals("BACON", BaconImpl.decrypt(BaconImpl.encrypt("BACON", false), false));
        assertThrows(IllegalArgumentException.class, () -> BaconImpl.decrypt("AAAA", true));
        assertThrows(IllegalArgumentException.class, () -> BaconImpl.decrypt("BBBBB", true));
    }

    @Test
    void playfairMatchesPublishedExample() {
        String key = "PLAYFAIR EXAMPLE";
        String plaintext = "HIDETHEGOLDINTHETREESTUMP";
        String ciphertext = "BMODZBXDNABEKUDMUIXMMOUVIF";
        assertEquals(ciphertext, PlayfairImpl.encrypt(plaintext, key));
        assertEquals("HIDETHEGOLDINTHETREXESTUMP", PlayfairImpl.decrypt(ciphertext, key));
        assertEquals("BALXLOON", PlayfairImpl.decrypt(PlayfairImpl.encrypt("BALLOON", key), key));
    }

    @Test
    void hillSupportsTwoByTwoAndThreeByThreeMatrices() {
        int[][] key2 = {{3, 3}, {2, 5}};
        assertEquals("ACTX", HillImpl.decrypt(HillImpl.encrypt("ACT", key2), key2));

        int[][] key3 = {{6, 24, 1}, {13, 16, 10}, {20, 17, 15}};
        assertEquals("POH", HillImpl.encrypt("ACT", key3));
        assertEquals("ACT", HillImpl.decrypt("POH", key3));
        assertEquals("ACTXXX", HillImpl.decrypt(HillImpl.encrypt("ACTX", key3), key3));
        assertThrows(IllegalArgumentException.class,
                () -> HillImpl.encrypt("ACT", new int[][]{{2, 0}, {0, 2}}));
    }
}
