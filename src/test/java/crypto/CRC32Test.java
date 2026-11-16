package crypto;

import myxfc.App.View.Modules.Encryption.Modern.Hash.HashImpl;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CRC32Test {
    @Test
    void matchesStandardCheckValue() {
        byte[] result = HashImpl.hash("123456789".getBytes(StandardCharsets.UTF_8), "CRC", "32");
        assertEquals("cbf43926", HexFormat.of().formatHex(result));
    }
}
