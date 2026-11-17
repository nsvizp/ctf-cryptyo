package myxfc.App.View.Modules.Tools.Image.Steganography.Engine;

import java.awt.image.BufferedImage;
import java.nio.ByteBuffer;
import java.util.List;

public class PixelValueSteganography {
    private static final byte[] MAGIC = {'P', 'V', 'M', '1'};

    public static BufferedImage embed(BufferedImage cover, byte[] payload, List<Character> channels,
                                      boolean columnScan) {
        if (channels == null || channels.isEmpty()) {
            throw new IllegalArgumentException("At least one channel is required");
        }
        byte[] framed = new byte[payload.length + 8];
        System.arraycopy(MAGIC, 0, framed, 0, 4);
        ByteBuffer.wrap(framed, 4, 4).putInt(payload.length);
        System.arraycopy(payload, 0, framed, 8, payload.length);
        long capacity = (long) cover.getWidth() * cover.getHeight() * channels.size();
        if (framed.length > capacity) {
            throw new IllegalArgumentException("Insufficient pixel-value capacity");
        }
        BufferedImage output = ImageStegoUtils.argb(cover);
        for (int index = 0; index < framed.length; index++) {
            int pixelIndex = index / channels.size();
            char channel = channels.get(index % channels.size());
            int[] point = point(output, pixelIndex, columnScan);
            int pixel = output.getRGB(point[0], point[1]);
            output.setRGB(point[0], point[1], ImageStegoUtils.setChannel(pixel, channel, framed[index] & 0xFF));
        }
        return output;
    }

    public static byte[] extract(BufferedImage image, List<Character> channels, boolean columnScan) {
        if (channels == null || channels.isEmpty()) {
            throw new IllegalArgumentException("At least one channel is required");
        }
        byte[] header = read(image, channels, 8, 0, columnScan);
        for (int i = 0; i < MAGIC.length; i++) {
            if (header[i] != MAGIC[i]) {
                throw new IllegalArgumentException("No pixel-value payload header found");
            }
        }
        int length = ByteBuffer.wrap(header, 4, 4).getInt();
        long capacity = (long) image.getWidth() * image.getHeight() * channels.size();
        if (length < 0 || length + 8L > capacity) {
            throw new IllegalArgumentException("Invalid pixel-value payload length");
        }
        return read(image, channels, length, 8, columnScan);
    }

    private static byte[] read(BufferedImage image, List<Character> channels, int length, int byteOffset,
                               boolean columnScan) {
        byte[] result = new byte[length];
        for (int index = 0; index < length; index++) {
            int sourceIndex = byteOffset + index;
            int pixelIndex = sourceIndex / channels.size();
            char channel = channels.get(sourceIndex % channels.size());
            int[] point = point(image, pixelIndex, columnScan);
            result[index] = (byte) ImageStegoUtils.getChannel(image.getRGB(point[0], point[1]), channel);
        }
        return result;
    }

    private static int[] point(BufferedImage image, int index, boolean columnScan) {
        return columnScan
                ? new int[]{index / image.getHeight(), index % image.getHeight()}
                : new int[]{index % image.getWidth(), index / image.getWidth()};
    }
}
