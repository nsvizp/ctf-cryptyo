package myxfc.App.View.Modules.Encryption.Modern.AsymmetricEncryption.RSA;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSAImpl {
    public static KeyPair generateKeyPair(int keySize) throws GeneralSecurityException {
        if (keySize < 512 || keySize % 8 != 0) {
            throw new IllegalArgumentException("RSA key size must be at least 512 bits and divisible by 8");
        }
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(keySize);
        return generator.generateKeyPair();
    }

    public static String encodePublicKey(PublicKey key) {
        return toPem("PUBLIC KEY", key.getEncoded());
    }

    public static String encodePrivateKey(PrivateKey key) {
        return toPem("PRIVATE KEY", key.getEncoded());
    }

    public static PublicKey parsePublicKey(String pem) throws GeneralSecurityException {
        byte[] encoded = fromPem(pem, "PUBLIC KEY");
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(encoded));
    }

    public static PrivateKey parsePrivateKey(String pem) throws GeneralSecurityException {
        byte[] encoded = fromPem(pem, "PRIVATE KEY");
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(encoded));
    }

    public static PublicKey publicKeyFromParameters(String modulus, String exponent, int radix)
            throws GeneralSecurityException {
        return KeyFactory.getInstance("RSA").generatePublic(
                new RSAPublicKeySpec(parseBigInteger(modulus, radix), parseBigInteger(exponent, radix)));
    }

    public static PrivateKey privateKeyFromParameters(String modulus, String exponent, int radix)
            throws GeneralSecurityException {
        return KeyFactory.getInstance("RSA").generatePrivate(
                new RSAPrivateKeySpec(parseBigInteger(modulus, radix), parseBigInteger(exponent, radix)));
    }

    public static byte[] encrypt(byte[] input, PublicKey key, String mode) throws GeneralSecurityException {
        return crypt(input, key, mode, Cipher.ENCRYPT_MODE);
    }

    public static byte[] decrypt(byte[] input, PrivateKey key, String mode) throws GeneralSecurityException {
        return crypt(input, key, mode, Cipher.DECRYPT_MODE);
    }

    private static byte[] crypt(byte[] input, Key key, String mode, int cipherMode)
            throws GeneralSecurityException {
        if (input == null || input.length == 0) {
            throw new IllegalArgumentException("Input must not be empty");
        }
        if (!(key instanceof RSAKey rsaKey)) {
            throw new IllegalArgumentException("An RSA key is required");
        }
        int keyBytes = (rsaKey.getModulus().bitLength() + 7) / 8;
        if ("NoPadding".equals(mode)) {
            if (input.length > keyBytes) {
                throw new IllegalArgumentException("Raw RSA input exceeds the RSA modulus size");
            }
            if (new BigInteger(1, input).compareTo(rsaKey.getModulus()) >= 0) {
                throw new IllegalArgumentException("Raw RSA input must be smaller than the modulus");
            }
        } else if (cipherMode == Cipher.DECRYPT_MODE && input.length != keyBytes) {
            throw new IllegalArgumentException("RSA ciphertext length must equal the RSA modulus size");
        }

        Cipher cipher = Cipher.getInstance(transformation(mode));
        OAEPParameterSpec oaep = oaepParameters(mode);
        if (oaep == null) {
            cipher.init(cipherMode, key);
        } else {
            cipher.init(cipherMode, key, oaep);
        }
        return cipher.doFinal(input);
    }

    private static String transformation(String mode) {
        return switch (mode) {
            case "PKCS1Padding" -> "RSA/ECB/PKCS1Padding";
            case "OAEP-SHA1" -> "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
            case "OAEP-SHA256" -> "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
            case "NoPadding" -> "RSA/ECB/NoPadding";
            default -> throw new IllegalArgumentException("Unsupported RSA mode: " + mode);
        };
    }

    private static OAEPParameterSpec oaepParameters(String mode) {
        return switch (mode) {
            case "OAEP-SHA1" -> new OAEPParameterSpec(
                    "SHA-1", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
            case "OAEP-SHA256" -> new OAEPParameterSpec(
                    "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
            default -> null;
        };
    }

    private static BigInteger parseBigInteger(String value, int radix) {
        if (value == null) {
            throw new IllegalArgumentException("RSA parameter must not be null");
        }
        String normalized = value.replaceAll("\\s", "");
        if (radix == 16 && normalized.startsWith("0x")) {
            normalized = normalized.substring(2);
        }
        if (normalized.isEmpty()) {
            throw new IllegalArgumentException("RSA parameter must not be empty");
        }
        BigInteger result = new BigInteger(normalized, radix);
        if (result.signum() <= 0) {
            throw new IllegalArgumentException("RSA parameters must be positive");
        }
        return result;
    }

    private static String toPem(String type, byte[] encoded) {
        String base64 = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(encoded);
        return "-----BEGIN " + type + "-----\n" + base64 + "\n-----END " + type + "-----";
    }

    private static byte[] fromPem(String pem, String type) {
        if (pem == null) {
            throw new IllegalArgumentException("PEM key must not be null");
        }
        String normalized = pem.replace("-----BEGIN " + type + "-----", "")
                .replace("-----END " + type + "-----", "")
                .replaceAll("\\s", "");
        if (normalized.isEmpty()) {
            throw new IllegalArgumentException("PEM key must not be empty");
        }
        return Base64.getDecoder().decode(normalized);
    }
}
