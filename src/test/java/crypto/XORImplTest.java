package crypto;

import myxfc.App.View.Modules.Encryption.Coding.XOR.XORImpl;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class XORImplTest {
    @Test
    void usesStandardRepeatingKeyXor() {
        byte[] result = XORImpl.encrypt("ABC".getBytes(StandardCharsets.UTF_8), new byte[]{1});
        assertEquals("404342", HexFormat.of().formatHex(result));
        assertArrayEquals("ABC".getBytes(StandardCharsets.UTF_8), XORImpl.encrypt(result, new byte[]{1}));

        byte[] repeated = XORImpl.encrypt("abcdef".getBytes(StandardCharsets.UTF_8), new byte[]{1, 2});
        assertEquals("606062666464", HexFormat.of().formatHex(repeated));
    }

    @Test
    void bruteForceRanksKnownFlagKeyFirst() {
        byte[] key = {0x42};
        byte[] encrypted = XORImpl.encrypt("flag{standard_xor}".getBytes(StandardCharsets.UTF_8), key);
        List<XORImpl.BruteForceResult> results = XORImpl.bruteForceSingleByte(encrypted);
        assertEquals(256, results.size());
        assertEquals(0x42, results.get(0).key());
        assertEquals("flag{standard_xor}", new String(results.get(0).plaintext(), StandardCharsets.UTF_8));
    }

    @Test
    void emptyKeyIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> XORImpl.encrypt(new byte[0], new byte[0]));
    }
}
