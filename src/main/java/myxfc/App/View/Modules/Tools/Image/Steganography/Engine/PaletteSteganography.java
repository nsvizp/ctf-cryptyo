package myxfc.App.View.Modules.Tools.Image.Steganography.Engine;

import java.awt.image.BufferedImage;
import java.awt.image.IndexColorModel;
import java.nio.ByteBuffer;

public class PaletteSteganography {
    private static final byte[] MAGIC = {'P', 'A', 'L', '1'};

    public static BufferedImage embed(BufferedImage cover, byte[] payload) {
        IndexColorModel model = indexedModel(cover);
        int size = model.getMapSize();
        byte[] framed = frame(payload);
        if ((long) framed.length * 8 > (long) size * 3) {
            throw new IllegalArgumentException("Insufficient palette capacity");
        }
        byte[] reds = new byte[size];
        byte[] greens = new byte[size];
        byte[] blues = new byte[size];
        byte[] alphas = new byte[size];
        model.getReds(reds);
        model.getGreens(greens);
        model.getBlues(blues);
        model.getAlphas(alphas);
        for (int bit = 0; bit < framed.length * 8; bit++) {
            int component = bit % 3;
            int index = bit / 3;
            int value = switch (component) {
                case 0 -> reds[index] & 0xFF;
                case 1 -> greens[index] & 0xFF;
                default -> blues[index] & 0xFF;
            };
            int bitValue = (framed[bit / 8] >>> (7 - bit % 8)) & 1;
            value = (value & 0xFE) | bitValue;
            switch (component) {
                case 0 -> reds[index] = (byte) value;
                case 1 -> greens[index] = (byte) value;
                default -> blues[index] = (byte) value;
            }
        }
        IndexColorModel outputModel = new IndexColorModel(model.getPixelSize(), size,
                reds, greens, blues, alphas);
        return new BufferedImage(outputModel, copyRaster(cover), false, null);
    }

    public static byte[] extract(BufferedImage image) {
        IndexColorModel model = indexedModel(image);
        int size = model.getMapSize();
        byte[] reds = new byte[size];
        byte[] greens = new byte[size];
        byte[] blues = new byte[size];
        model.getReds(reds);
        model.getGreens(greens);
        model.getBlues(blues);
        byte[] header = readBytes(reds, greens, blues, 8, 0);
        for (int i = 0; i < MAGIC.length; i++) {
            if (header[i] != MAGIC[i]) {
                throw new IllegalArgumentException("No palette payload header found");
            }
        }
        int length = ByteBuffer.wrap(header, 4, 4).getInt();
        if (length < 0 || (long) (length + 8) * 8 > (long) size * 3) {
            throw new IllegalArgumentException("Invalid palette payload length");
        }
        return readBytes(reds, greens, blues, length, 64);
    }

    private static byte[] frame(byte[] payload) {
        if (payload == null) {
            throw new IllegalArgumentException("Payload must not be null");
        }
        byte[] framed = new byte[payload.length + 8];
        System.arraycopy(MAGIC, 0, framed, 0, 4);
        ByteBuffer.wrap(framed, 4, 4).putInt(payload.length);
        System.arraycopy(payload, 0, framed, 8, payload.length);
        return framed;
    }

    private static byte[] readBytes(byte[] reds, byte[] greens, byte[] blues, int length, int bitOffset) {
        byte[] result = new byte[length];
        for (int bit = 0; bit < length * 8; bit++) {
            int sourceBit = bitOffset + bit;
            int component = sourceBit % 3;
            int index = sourceBit / 3;
            int value = switch (component) {
                case 0 -> reds[index] & 0xFF;
                case 1 -> greens[index] & 0xFF;
                default -> blues[index] & 0xFF;
            };
            result[bit / 8] |= (byte) ((value & 1) << (7 - bit % 8));
        }
        return result;
    }

    private static IndexColorModel indexedModel(BufferedImage image) {
        if (!(image.getColorModel() instanceof IndexColorModel model)) {
            throw new IllegalArgumentException("Palette steganography requires an indexed-color image");
        }
        return model;
    }

    private static java.awt.image.WritableRaster copyRaster(BufferedImage image) {
        return image.getRaster().createWritableChild(0, 0, image.getWidth(), image.getHeight(),
                0, 0, null);
    }
}
