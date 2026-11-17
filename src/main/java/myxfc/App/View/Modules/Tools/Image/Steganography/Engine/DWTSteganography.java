package myxfc.App.View.Modules.Tools.Image.Steganography.Engine;

import java.awt.image.BufferedImage;
import java.nio.ByteBuffer;
import java.util.List;

public class DWTSteganography {
    private static final byte[] MAGIC = {'D', 'W', 'T', '1'};

    public static BufferedImage embed(BufferedImage cover, byte[] payload, List<Character> channels) {
        if (channels == null || channels.isEmpty()) {
            throw new IllegalArgumentException("At least one channel is required");
        }
        byte[] framed = new byte[payload.length + 8];
        System.arraycopy(MAGIC, 0, framed, 0, 4);
        ByteBuffer.wrap(framed, 4, 4).putInt(payload.length);
        System.arraycopy(payload, 0, framed, 8, payload.length);
        long capacity = capacityBits(cover, channels);
        if ((long) framed.length * 8 > capacity) {
            throw new IllegalArgumentException("Insufficient DWT capacity");
        }
        BufferedImage output = ImageStegoUtils.argb(cover);
        for (char channel : channels) {
            int[][] coefficients = forward(channelMatrix(output, channel));
            for (int y = 0; y < coefficients.length; y++) {
                for (int x = 0; x < coefficients[y].length; x++) {
                    if ((x & 1) == 0 && (y & 1) == 0) {
                        continue;
                    }
                    long detailIndex = detailIndex(coefficients.length, coefficients[0].length, x, y);
                    long bit = channelOffset(channels, channel, capacity) + detailIndex;
                    if (bit >= (long) framed.length * 8) {
                        continue;
                    }
                    int bitValue = (framed[(int) (bit / 8)] >>> (7 - (int) (bit % 8))) & 1;
                    coefficients[y][x] = (coefficients[y][x] & ~1) | bitValue;
                }
            }
            restoreChannel(output, channel, inverse(coefficients));
        }
        return output;
    }

    public static byte[] extract(BufferedImage image, List<Character> channels) {
        if (channels == null || channels.isEmpty()) {
            throw new IllegalArgumentException("At least one channel is required");
        }
        byte[] header = readBytes(image, channels, 8, 0);
        for (int i = 0; i < MAGIC.length; i++) {
            if (header[i] != MAGIC[i]) {
                throw new IllegalArgumentException("No DWT payload header found");
            }
        }
        int length = ByteBuffer.wrap(header, 4, 4).getInt();
        if (length < 0 || (long) (length + 8) * 8 > capacityBits(image, channels)) {
            throw new IllegalArgumentException("Invalid DWT payload length");
        }
        return readBytes(image, channels, length, 64);
    }

    public static long capacityBits(BufferedImage image, List<Character> channels) {
        return (long) channels.size() * 3 * (image.getWidth() / 2) * (image.getHeight() / 2);
    }

    private static byte[] readBytes(BufferedImage image, List<Character> channels, int length, long bitOffset) {
        byte[] result = new byte[length];
        long capacity = capacityBits(image, channels);
        for (char channel : channels) {
            int[][] coefficients = forward(channelMatrix(image, channel));
            for (int y = 0; y < coefficients.length; y++) {
                for (int x = 0; x < coefficients[y].length; x++) {
                    if ((x & 1) == 0 && (y & 1) == 0) {
                        continue;
                    }
                    long bit = channelOffset(channels, channel, capacity)
                            + detailIndex(coefficients.length, coefficients[0].length, x, y);
                    if (bit < bitOffset || bit >= bitOffset + (long) length * 8) {
                        continue;
                    }
                    int outputBit = (int) (bit - bitOffset);
                    result[outputBit / 8] |= (byte) ((coefficients[y][x] & 1) << (7 - outputBit % 8));
                }
            }
        }
        return result;
    }

    private static long channelOffset(List<Character> channels, char channel, long totalCapacity) {
        return totalCapacity / channels.size() * channels.indexOf(channel);
    }

    private static long detailIndex(int height, int width, int x, int y) {
        int band = (y & 1) * 2 + (x & 1);
        int bandIndex = switch (band) {
            case 1 -> 0;
            case 2 -> 1;
            default -> 2;
        };
        return (long) bandIndex * (width / 2) * (height / 2)
                + (long) (y / 2) * (width / 2) + x / 2;
    }

    private static int[][] channelMatrix(BufferedImage image, char channel) {
        int[][] result = new int[image.getHeight()][image.getWidth()];
        for (int y = 0; y < image.getHeight(); y++) {
            for (int x = 0; x < image.getWidth(); x++) {
                result[y][x] = ImageStegoUtils.getChannel(image.getRGB(x, y), channel);
            }
        }
        return result;
    }

    private static void restoreChannel(BufferedImage image, char channel, int[][] values) {
        for (int y = 0; y < image.getHeight(); y++) {
            for (int x = 0; x < image.getWidth(); x++) {
                int pixel = image.getRGB(x, y);
                image.setRGB(x, y, ImageStegoUtils.setChannel(pixel, channel, values[y][x]));
            }
        }
    }

    private static int[][] forward(int[][] input) {
        int[][] result = copy(input);
        for (int y = 0; y < result.length; y++) {
            for (int x = 0; x < result[y].length - 1; x += 2) {
                int first = result[y][x];
                int second = result[y][x + 1];
                result[y][x] = Math.floorDiv(first + second, 2);
                result[y][x + 1] = first - second;
            }
        }
        for (int x = 0; x < result[0].length; x++) {
            for (int y = 0; y < result.length - 1; y += 2) {
                int first = result[y][x];
                int second = result[y + 1][x];
                result[y][x] = Math.floorDiv(first + second, 2);
                result[y + 1][x] = first - second;
            }
        }
        return result;
    }

    private static int[][] inverse(int[][] input) {
        int[][] result = copy(input);
        for (int x = 0; x < result[0].length; x++) {
            for (int y = 0; y < result.length - 1; y += 2) {
                int average = result[y][x];
                int difference = result[y + 1][x];
                result[y][x] = average + Math.floorDiv(difference + 1, 2);
                result[y + 1][x] = average - Math.floorDiv(difference, 2);
            }
        }
        for (int y = 0; y < result.length; y++) {
            for (int x = 0; x < result[y].length - 1; x += 2) {
                int average = result[y][x];
                int difference = result[y][x + 1];
                result[y][x] = average + Math.floorDiv(difference + 1, 2);
                result[y][x + 1] = average - Math.floorDiv(difference, 2);
            }
        }
        return result;
    }

    private static int[][] copy(int[][] input) {
        int[][] result = new int[input.length][];
        for (int i = 0; i < input.length; i++) {
            result[i] = input[i].clone();
        }
        return result;
    }
}
