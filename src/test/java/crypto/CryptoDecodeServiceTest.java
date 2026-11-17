package crypto;

import myxfc.App.View.Modules.Encryption.Coding.BaseEncoding.Base58.Base58Impl;
import myxfc.App.View.Modules.Encryption.Coding.XOR.XORImpl;
import myxfc.App.View.Modules.Encryption.Modern.SymmetricEncryption.StreamCipher.RC4.RC4Impl;
import myxfc.App.View.Modules.Tools.CTF.Engine.Decode.CryptoDecodeService;
import myxfc.App.View.Modules.Tools.CTF.Engine.Decode.MultiDecodeService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertTrue;

class CryptoDecodeServiceTest {
    @Test
    void jwtAndBase58AreDetected() throws Exception {
        String token = "eyJhbGciOiJub25lIn0.eyJmbGFnIjoiZmxhZ3tqd3R9In0.";
        assertTrue(MultiDecodeService.decode(token, 2).get(0).output().contains("flag{jwt}"));
        String base58 = Base58Impl.encodeToString("flag{base58}", "UTF-8");
        assertTrue(MultiDecodeService.decode(base58, 2).get(0).output().contains("flag{base58}"));
    }

    @Test
    void jwtIsDetectedWithTokenPrefix() {
        String input = "myxfc_token=eyJhbGciOiJub25lIn0.eyJmbGFnIjoiZmxhZ3tqd3R9In0.";
        assertTrue(MultiDecodeService.decode(input, 2).get(0).output().contains("flag{jwt}"));
        assertTrue(CryptoDecodeService.decode(input, "", "").toString().contains("alg=none"));
    }

    @Test
    void xorAndRc4KeysProduceCandidates() {
        byte[] plaintext = "flag{xor_rc4}".getBytes(StandardCharsets.UTF_8);
        String xor = Base64.getEncoder().encodeToString(XORImpl.encrypt(plaintext, new byte[]{0x42}));
        assertTrue(CryptoDecodeService.decode(xor, "B", "").toString().contains("flag{xor_rc4}"));
        assertTrue(CryptoDecodeService.decode(xor, "", "").toString().contains("flag{xor_rc4}"));

        String rc4 = Base64.getEncoder().encodeToString(RC4Impl.crypt(plaintext, "Key".getBytes(StandardCharsets.UTF_8)));
        assertTrue(CryptoDecodeService.decode(rc4, "Key", "").toString().contains("flag{xor_rc4}"));
    }

    @Test
    void sm4IsAttemptedWithSuppliedKey() throws Exception {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        byte[] key = "0123456789012345".getBytes(StandardCharsets.UTF_8);
        Cipher cipher = Cipher.getInstance("SM4/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "SM4"));
        String encrypted = Base64.getEncoder().encodeToString(cipher.doFinal("flag{sm4_auto}".getBytes(StandardCharsets.UTF_8)));
        assertTrue(CryptoDecodeService.decode(encrypted, "0123456789012345", "").toString().contains("flag{sm4_auto}"));
    }
}
