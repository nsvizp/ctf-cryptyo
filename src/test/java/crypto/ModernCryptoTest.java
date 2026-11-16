package crypto;

import myxfc.App.View.Modules.Encryption.Modern.AsymmetricEncryption.RSA.RSAImpl;
import myxfc.App.View.Modules.Encryption.Modern.SymmetricEncryption.StreamCipher.RC4.RC4Impl;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ModernCryptoTest {
    @Test
    void rc4MatchesPublishedVector() throws Exception {
        byte[] encrypted = RC4Impl.crypt("Plaintext".getBytes(StandardCharsets.UTF_8),
                "Key".getBytes(StandardCharsets.UTF_8));
        assertEquals("bbf316e8d940af0ad3", HexFormat.of().formatHex(encrypted));
        assertArrayEquals("Plaintext".getBytes(StandardCharsets.UTF_8),
                RC4Impl.crypt(encrypted, "Key".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void rsaSupportsPemAndAllPaddingModes() throws Exception {
        KeyPair pair = RSAImpl.generateKeyPair(1024);
        PublicKey publicKey = RSAImpl.parsePublicKey(RSAImpl.encodePublicKey(pair.getPublic()));
        PrivateKey privateKey = RSAImpl.parsePrivateKey(RSAImpl.encodePrivateKey(pair.getPrivate()));
        byte[] plaintext = "myxfc RSA".getBytes(StandardCharsets.UTF_8);
        for (String mode : new String[]{"PKCS1Padding", "OAEP-SHA1", "OAEP-SHA256", "NoPadding"}) {
            byte[] encrypted = RSAImpl.encrypt(plaintext, publicKey, mode);
            byte[] decrypted = RSAImpl.decrypt(encrypted, privateKey, mode);
            if (mode.equals("NoPadding")) {
                assertEquals(new java.math.BigInteger(1, plaintext), new java.math.BigInteger(1, decrypted));
            } else {
                assertArrayEquals(plaintext, decrypted);
            }
        }
    }

    @Test
    void rsaSupportsNumericParameters() throws Exception {
        KeyPair pair = RSAImpl.generateKeyPair(1024);
        RSAPublicKey publicKey = (RSAPublicKey) pair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) pair.getPrivate();
        String modulus = publicKey.getModulus().toString(16);
        PublicKey restoredPublic = RSAImpl.publicKeyFromParameters(
                modulus, publicKey.getPublicExponent().toString(16), 16);
        PrivateKey restoredPrivate = RSAImpl.privateKeyFromParameters(
                modulus, privateKey.getPrivateExponent().toString(16), 16);
        byte[] plaintext = "parameters".getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(plaintext, RSAImpl.decrypt(
                RSAImpl.encrypt(plaintext, restoredPublic, "PKCS1Padding"), restoredPrivate, "PKCS1Padding"));
    }

    @Test
    void rsaRejectsInvalidRawInput() throws Exception {
        KeyPair pair = RSAImpl.generateKeyPair(512);
        assertThrows(IllegalArgumentException.class,
                () -> RSAImpl.encrypt(new byte[65], pair.getPublic(), "NoPadding"));
    }
}
