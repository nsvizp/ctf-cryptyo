package myxfc.App.View.Modules.Tools.Image.Steganography.Engine;

import java.awt.image.BufferedImage;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class LSBSteganography {
    private static final byte[] MAGIC = {'M', 'Y', 'X', '1'};

    public record Settings(List<Character> channels, int bitPlane, boolean msbFirst, boolean columnScan,
                           String order) {
        public Settings {
            if (channels == null || channels.isEmpty()) {
                throw new IllegalArgumentException("At least one channel is required");
            }
            if (bitPlane < 0 || bitPlane > 7) {
                throw new IllegalArgumentException("Bit plane must be between 0 and 7");
            }
            channels = List.copyOf(channels);
        }

        @Override
        public String toString() {
            return order + " plane=" + bitPlane + (msbFirst ? " MSB" : " LSB")
                    + (columnScan ? " columns" : " rows");
        }
    }

    public record Detection(Settings settings, byte[] data, double score, boolean framed) {
        public String preview() {
            String text = new String(data, StandardCharsets.UTF_8);
            StringBuilder printable = new StringBuilder();
            for (char c : text.toCharArray()) {
                printable.append(c == 9 || c == 10 || c == 13 || c >= 32 && c < 127 ? c : '.');
            }
            return printable.toString();
        }
    }

    public static BufferedImage embed(BufferedImage cover, byte[] payload, Settings settings) {
        if (payload == null) {
            throw new IllegalArgumentException("Payload must not be null");
        }
        byte[] framed = new byte[payload.length + 8];
        System.arraycopy(MAGIC, 0, framed, 0, MAGIC.length);
        ByteBuffer.wrap(framed, 4, 4).putInt(payload.length);
        System.arraycopy(payload, 0, framed, 8, payload.length);
        BufferedImage output = ImageStegoUtils.argb(cover);
        writeBytes(output, framed, settings);
        return output;
    }

    public static byte[] extract(BufferedImage image, Settings settings) {
        byte[] header = readBytes(image, 8, settings);
        for (int i = 0; i < MAGIC.length; i++) {
            if (header[i] != MAGIC[i]) {
                throw new IllegalArgumentException("No myxfc LSB header found");
            }
        }
        int length = ByteBuffer.wrap(header, 4, 4).getInt();
        if (length < 0 || (long) (length + 8) * 8 > capacityBits(image, settings)) {
            throw new IllegalArgumentException("Invalid LSB payload length: " + length);
        }
        return readBytes(image, length, settings, 64);
    }

    public static byte[] extractRaw(BufferedImage image, int length, Settings settings) {
        if (length < 0) {
            throw new IllegalArgumentException("Length must not be negative");
        }
        return readBytes(image, length, settings);
    }

    public static long capacityBits(BufferedImage image, Settings settings) {
        return (long) image.getWidth() * image.getHeight() * settings.channels().size();
    }

    public static List<Detection> autoDetect(BufferedImage image, boolean r, boolean g, boolean b, boolean a) {
        record Candidate(Settings settings, byte[] sampledData, double score, boolean framed, int capacity) {
        }
        String[] orders = {"RGB", "BGR", "RGBA", "BGRA", "ARGB", "ABGR"};
        List<Candidate> candidates = new ArrayList<>();
        for (String order : orders) {
            List<Character> channels;
            try {
                channels = ImageStegoUtils.channels(order, r, g, b, a);
            } catch (IllegalArgumentException ignored) {
                continue;
            }
            for (int plane = 0; plane < 8; plane++) {
                for (boolean msb : new boolean[]{false, true}) {
                    for (boolean columns : new boolean[]{false, true}) {
                        if (Thread.currentThread().isInterrupted()) {
                            throw new java.util.concurrent.CancellationException("LSB detection cancelled");
                        }
                        Settings settings = new Settings(channels, plane, msb, columns, order);
                        int sampleLength = (int) Math.min(4096, capacityBits(image, settings) / 8);
                        if (sampleLength < 8) {
                            continue;
                        }
                        byte[] raw = readBytes(image, sampleLength, settings);
                        int capacity = (int) Math.min(Integer.MAX_VALUE, capacityBits(image, settings) / 8);
                        boolean framed = hasValidHeader(raw, capacity);
                        byte[] sampledData = framed ? extract(image, settings) : raw;
                        double score = score(sampledData, framed);
                        if (framed || score >= 60) {
                            candidates.add(new Candidate(settings, sampledData, score, framed, capacity));
                        }
                    }
                }
            }
        }
        candidates.sort(Comparator.comparingDouble(Candidate::score).reversed());
        List<Detection> detections = new ArrayList<>();
        List<byte[]> uniqueSamples = new ArrayList<>();
        for (Candidate candidate : candidates) {
            if (uniqueSamples.stream().anyMatch(sample -> java.util.Arrays.equals(sample, candidate.sampledData()))) {
                continue;
            }
            uniqueSamples.add(candidate.sampledData());
            byte[] data = candidate.framed() ? candidate.sampledData()
                    : readBytes(image, candidate.capacity(), candidate.settings());
            detections.add(new Detection(candidate.settings(), data, candidate.score(), candidate.framed()));
        }
        return List.copyOf(detections);
    }

    private static boolean hasValidHeader(byte[] raw, int available) {
        for (int i = 0; i < MAGIC.length; i++) {
            if (raw[i] != MAGIC[i]) {
                return false;
            }
        }
        int length = ByteBuffer.wrap(raw, 4, 4).getInt();
        return length >= 0 && length <= available - 8;
    }

    private static double score(byte[] data, boolean framed) {
        if (data.length == 0) {
            return 0;
        }
        int printable = 0;
        for (byte value : data) {
            int c = value & 0xFF;
            if (c == 9 || c == 10 || c == 13 || (c >= 32 && c < 127)) {
                printable++;
            }
        }
        double score = printable * 100.0 / data.length;
        String text = new String(data, StandardCharsets.UTF_8).toLowerCase();
        if (text.contains("flag{") || text.contains("ctf{")) {
            score += 100;
        }
        if (data.length >= 4 && ((data[0] & 0xFF) == 0x89 && data[1] == 'P' && data[2] == 'N' && data[3] == 'G')
                || (data[0] & 0xFF) == 0xFF && (data[1] & 0xFF) == 0xD8
                || data[0] == 'P' && data[1] == 'K') {
            score += 80;
        }
        if (framed) {
            score += 40;
        }
        return score;
    }

    private static void writeBytes(BufferedImage image, byte[] data, Settings settings) {
        long requiredBits = (long) data.length * 8;
        if (requiredBits > capacityBits(image, settings)) {
            throw new IllegalArgumentException("Insufficient image capacity: need " + requiredBits
                    + " bits, available " + capacityBits(image, settings));
        }
        List<Character> channels = settings.channels();
        for (long bit = 0; bit < requiredBits; bit++) {
            int value = data[(int) (bit / 8)] & 0xFF;
            int shift = settings.msbFirst() ? 7 - (int) (bit % 8) : (int) (bit % 8);
            int bitValue = (value >>> shift) & 1;
            long pixelIndex = bit / channels.size();
            char channel = channels.get((int) (bit % channels.size()));
            int[] coordinates = coordinates(image, pixelIndex, settings.columnScan());
            int pixel = image.getRGB(coordinates[0], coordinates[1]);
            int channelValue = ImageStegoUtils.getChannel(pixel, channel);
            channelValue = (channelValue & ~(1 << settings.bitPlane())) | (bitValue << settings.bitPlane());
            image.setRGB(coordinates[0], coordinates[1],
                    ImageStegoUtils.setChannel(pixel, channel, channelValue));
        }
    }

    private static byte[] readBytes(BufferedImage image, int length, Settings settings) {
        return readBytes(image, length, settings, 0);
    }

    private static byte[] readBytes(BufferedImage image, int length, Settings settings, long bitOffset) {
        if (bitOffset < 0 || bitOffset + (long) length * 8 > capacityBits(image, settings)) {
            throw new IllegalArgumentException("Requested data exceeds LSB capacity");
        }
        byte[] result = new byte[length];
        List<Character> channels = settings.channels();
        for (long bit = 0; bit < (long) length * 8; bit++) {
            long sourceBit = bitOffset + bit;
            long pixelIndex = sourceBit / channels.size();
            char channel = channels.get((int) (sourceBit % channels.size()));
            int[] coordinates = coordinates(image, pixelIndex, settings.columnScan());
            int channelValue = ImageStegoUtils.getChannel(image.getRGB(coordinates[0], coordinates[1]), channel);
            int bitValue = (channelValue >>> settings.bitPlane()) & 1;
            int shift = settings.msbFirst() ? 7 - (int) (bit % 8) : (int) (bit % 8);
            result[(int) (bit / 8)] |= (byte) (bitValue << shift);
        }
        return result;
    }

    private static int[] coordinates(BufferedImage image, long index, boolean columnScan) {
        if (columnScan) {
            return new int[]{(int) (index / image.getHeight()), (int) (index % image.getHeight())};
        }
        return new int[]{(int) (index % image.getWidth()), (int) (index / image.getWidth())};
    }
}
