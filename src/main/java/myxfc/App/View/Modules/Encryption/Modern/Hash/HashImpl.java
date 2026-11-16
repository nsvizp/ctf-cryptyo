package myxfc.App.View.Modules.Encryption.Modern.Hash;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.ByteBuffer;
import java.util.zip.CRC32;

public class HashImpl {
    private static String getInstanceString(String hashMode,String hashBit) {
        return switch (hashMode) {
            case "MD5" -> "MD5";
            case "MD5-16" -> "MD5-16";
            case "SHA1" -> "SHA1";
            case "SM3" -> "SM3";
            case "MD4" -> "MD4";
            case "MD2" -> "MD2";
            case "Tiger" -> "Tiger";
            case "Whirlpool" -> "Whirlpool";
            case "GOST3411" -> "GOST3411";
            case "RIPEMD" -> "RIPEMD" + hashBit;
            case "CRC" -> "CRC" + hashBit;
            case "SHA2" -> "SHA" + "-" + hashBit;
            default -> hashMode + "-" + hashBit;
        };
    }

    public static byte[] hash(byte[] message,String hashMode,String hashBit) {
        hashMode = getInstanceString(hashMode,hashBit);
        return hash(message,hashMode);
    }

    public static byte[] hash(byte[] message,String hashMode) {
        if (hashMode.equals("CRC32")) {
            CRC32 crc32 = new CRC32();
            crc32.update(message);
            return ByteBuffer.allocate(4).putInt((int) crc32.getValue()).array();
        }
        MessageDigest mc = null;//实例化MessageDigest方法用来作MD5转换
        if (hashMode.equals("MD5-16")) {
            hashMode = "MD5";
        }

        try {
            mc = MessageDigest.getInstance(hashMode);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        assert mc != null;
        mc.update(message);//hash摘要
        byte[] out = mc.digest();
        return out;
    }
}
