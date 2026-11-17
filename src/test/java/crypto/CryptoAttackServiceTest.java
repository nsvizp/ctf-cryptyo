package crypto;

import myxfc.App.View.Modules.Tools.CTF.Engine.Crypto.ClassicalAttackService;
import myxfc.App.View.Modules.Tools.CTF.Engine.Crypto.RsaAttackService;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CryptoAttackServiceTest {
    @Test
    void rsaAttacksRecoverExpectedValues() {
        BigInteger n = BigInteger.valueOf(3233);
        BigInteger e = BigInteger.valueOf(17);
        BigInteger d = BigInteger.valueOf(2753);
        BigInteger plaintext = BigInteger.valueOf(65);
        BigInteger ciphertext = plaintext.modPow(e, n);

        assertEquals(plaintext, RsaAttackService.smallExponentDecrypt(plaintext.pow(3), BigInteger.valueOf(3)));
        BigInteger c1 = plaintext.modPow(e, n);
        BigInteger e2 = BigInteger.valueOf(23);
        BigInteger c2 = plaintext.modPow(e2, n);
        assertEquals(plaintext, RsaAttackService.commonModulusDecrypt(n, e, c1, e2, c2));
        var factors = RsaAttackService.recoverFromPrivateExponent(n, e, d);
        assertEquals(BigInteger.valueOf(53), factors.p());
        assertEquals(BigInteger.valueOf(61), factors.q());
        assertEquals(d, RsaAttackService.privateExponentFromDp(n, BigInteger.valueOf(61), e, BigInteger.valueOf(53)));
        assertEquals(plaintext, RsaAttackService.crtDecrypt(ciphertext, BigInteger.valueOf(61),
                BigInteger.valueOf(53), BigInteger.valueOf(53), BigInteger.valueOf(49)));
        assertEquals(BigInteger.valueOf(5), RsaAttackService.wienerAttack(
                BigInteger.valueOf(90581), BigInteger.valueOf(17993)));
    }

    @Test
    void vigenereAndXorAnalysisFindReadablePlaintext() {
        String plain = "CRYPTOGRAPHY IS THE PRACTICE AND STUDY OF TECHNIQUES FOR SECURE COMMUNICATION IN THE PRESENCE OF ADVERSARIES. MODERN CRYPTOGRAPHY EXISTS AT THE INTERSECTION OF MATHEMATICS COMPUTER SCIENCE ELECTRICAL ENGINEERING AND INFORMATION SECURITY. APPLICATIONS OF CRYPTOGRAPHY INCLUDE ELECTRONIC COMMERCE CHIP BASED PAYMENT CARDS DIGITAL CURRENCIES COMPUTER PASSWORDS AND MILITARY COMMUNICATIONS. ";
        String encrypted = ClassicalAttackService.vigenere(plain, "LEMON", true);
        var vigenere = ClassicalAttackService.crackVigenere(encrypted, 8);
        assertTrue(vigenere.get(0).plaintext().contains("CRYPTOGRAPHY"), vigenere.get(0).key());

        byte[] key = "KEY".getBytes(StandardCharsets.UTF_8);
        byte[] input = plain.getBytes(StandardCharsets.UTF_8);
        byte[] cipher = new byte[input.length];
        for (int i = 0; i < input.length; i++) cipher[i] = (byte) (input[i] ^ key[i % key.length]);
        var xor = ClassicalAttackService.crackRepeatingXor(cipher, 5);
        assertTrue(xor.get(0).plaintext().contains("CRYPTOGRAPHY"), xor.get(0).key());
        assertArrayEquals(key, Arrays.copyOf(ClassicalAttackService.recoverXorKey(cipher, input), key.length));
    }
}
