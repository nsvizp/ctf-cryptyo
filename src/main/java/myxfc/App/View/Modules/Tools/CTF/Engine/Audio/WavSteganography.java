package myxfc.App.View.Modules.Tools.CTF.Engine.Audio;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class WavSteganography {
    private static final byte[] MAGIC = {'M', 'Y', 'X', 'W'};

    public record WavData(byte[] bytes, int channels, int sampleRate, int bitsPerSample,
                          int dataOffset, int dataLength, int blockAlign) {
        public int frameCount() {
            return dataLength / blockAlign;
        }

        public int sampleValue(int frame, int channel) {
            int offset = sampleOffset(frame, channel);
            int bytes = bitsPerSample / 8;
            long value = 0;
            for (int i = 0; i < bytes; i++) {
                value |= (long) (this.bytes[offset + i] & 0xFF) << (8 * i);
            }
            if (bitsPerSample == 8) {
                return (int) value - 128;
            }
            long sign = 1L << (bitsPerSample - 1);
            return (int) ((value ^ sign) - sign);
        }

        public int sampleOffset(int frame, int channel) {
            return dataOffset + frame * blockAlign + channel * (bitsPerSample / 8);
        }
    }

    public static WavData read(Path path) throws Exception {
        return parse(Files.readAllBytes(path));
    }

    public static WavData parse(byte[] bytes) {
        if (bytes.length < 44 || !text(bytes, 0, 4).equals("RIFF") || !text(bytes, 8, 4).equals("WAVE")) {
            throw new IllegalArgumentException("Not a RIFF/WAVE file");
        }
        int channels = 0;
        int sampleRate = 0;
        int bits = 0;
        int blockAlign = 0;
        int offset = 12;
        while (offset + 8 <= bytes.length) {
            String type = text(bytes, offset, 4);
            int length = (int) u32(bytes, offset + 4);
            if (length < 0 || offset + 8L + length > bytes.length) {
                break;
            }
            if (type.equals("fmt ")) {
                if (length < 16) {
                    throw new IllegalArgumentException("Invalid WAV fmt chunk");
                }
                channels = u16(bytes, offset + 10);
                sampleRate = (int) u32(bytes, offset + 12);
                blockAlign = u16(bytes, offset + 20);
                bits = u16(bytes, offset + 22);
            } else if (type.equals("data")) {
                if (channels <= 0 || bits == 0 || bits % 8 != 0 || blockAlign == 0) {
                    throw new IllegalArgumentException("Unsupported WAV format");
                }
                return new WavData(bytes, channels, sampleRate, bits, offset + 8, length, blockAlign);
            }
            offset += 8 + length + (length & 1);
        }
        throw new IllegalArgumentException("WAV data chunk not found");
    }

    public static byte[] embed(WavData wav, byte[] payload, List<Integer> channels) {
        validateChannels(wav, channels);
        byte[] framed = new byte[payload.length + 8];
        System.arraycopy(MAGIC, 0, framed, 0, 4);
        ByteBuffer.wrap(framed, 4, 4).putInt(payload.length);
        System.arraycopy(payload, 0, framed, 8, payload.length);
        if ((long) framed.length * 8 > (long) wav.frameCount() * channels.size()) {
            throw new IllegalArgumentException("Insufficient WAV capacity");
        }
        byte[] output = wav.bytes().clone();
        for (int bit = 0; bit < framed.length * 8; bit++) {
            int frame = bit / channels.size();
            int channel = channels.get(bit % channels.size());
            int offset = wav.sampleOffset(frame, channel);
            int value = (framed[bit / 8] >>> (7 - bit % 8)) & 1;
            output[offset] = (byte) ((output[offset] & 0xFE) | value);
        }
        return output;
    }

    public static byte[] extract(WavData wav, List<Integer> channels) {
        validateChannels(wav, channels);
        byte[] header = readBytes(wav, channels, 8, 0);
        for (int i = 0; i < MAGIC.length; i++) {
            if (header[i] != MAGIC[i]) {
                throw new IllegalArgumentException("No WAV LSB header found");
            }
        }
        int length = ByteBuffer.wrap(header, 4, 4).getInt();
        if (length < 0 || (long) (length + 8) * 8 > (long) wav.frameCount() * channels.size()) {
            throw new IllegalArgumentException("Invalid WAV payload length");
        }
        return readBytes(wav, channels, length, 64);
    }

    public static String metadata(WavData wav) {
        StringBuilder result = new StringBuilder();
        result.append("Channels: ").append(wav.channels()).append('\n');
        result.append("Sample rate: ").append(wav.sampleRate()).append('\n');
        result.append("Bits per sample: ").append(wav.bitsPerSample()).append('\n');
        result.append("Frames: ").append(wav.frameCount()).append('\n');
        result.append("Duration: ").append(String.format("%.3f s", (double) wav.frameCount() / wav.sampleRate())).append('\n');
        int offset = 12;
        byte[] bytes = wav.bytes();
        while (offset + 8 <= bytes.length) {
            String type = text(bytes, offset, 4);
            int length = (int) u32(bytes, offset + 4);
            if (length < 0 || offset + 8L + length > bytes.length) {
                break;
            }
            result.append(type).append(": ").append(length).append(" bytes\n");
            if (List.of("LIST", "INFO", "INAM", "IART", "ICMT").contains(type)) {
                result.append(new String(bytes, offset + 8, Math.min(length, 4096), StandardCharsets.ISO_8859_1)).append('\n');
            }
            offset += 8 + length + (length & 1);
        }
        return result.toString();
    }

    private static byte[] readBytes(WavData wav, List<Integer> channels, int length, int bitOffset) {
        byte[] result = new byte[length];
        for (int bit = 0; bit < length * 8; bit++) {
            int sourceBit = bitOffset + bit;
            int frame = sourceBit / channels.size();
            int channel = channels.get(sourceBit % channels.size());
            int value = wav.bytes()[wav.sampleOffset(frame, channel)] & 1;
            result[bit / 8] |= (byte) (value << (7 - bit % 8));
        }
        return result;
    }

    private static void validateChannels(WavData wav, List<Integer> channels) {
        if (channels == null || channels.isEmpty()) {
            throw new IllegalArgumentException("At least one WAV channel is required");
        }
        for (int channel : channels) {
            if (channel < 0 || channel >= wav.channels()) {
                throw new IllegalArgumentException("Invalid WAV channel: " + channel);
            }
        }
    }

    private static String text(byte[] bytes, int offset, int length) {
        return new String(bytes, offset, length, StandardCharsets.ISO_8859_1);
    }

    private static int u16(byte[] bytes, int offset) {
        return (bytes[offset] & 0xFF) | (bytes[offset + 1] & 0xFF) << 8;
    }

    private static long u32(byte[] bytes, int offset) {
        return (bytes[offset] & 0xFFL) | (bytes[offset + 1] & 0xFFL) << 8
                | (bytes[offset + 2] & 0xFFL) << 16 | (bytes[offset + 3] & 0xFFL) << 24;
    }
}
