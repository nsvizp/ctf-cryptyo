package myxfc.App.View.Modules.Tools.CTF.Engine.Audio;

import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class AudioAnalysisService {
    private static final int[] LOW = {697, 770, 852, 941};
    private static final int[] HIGH = {1209, 1336, 1477, 1633};
    private static final char[][] KEYS = {{'1', '2', '3', 'A'}, {'4', '5', '6', 'B'},
            {'7', '8', '9', 'C'}, {'*', '0', '#', 'D'}};

    public record DTMF(char symbol, double start, double end, double confidence) {
        @Override
        public String toString() {
            return String.format(Locale.ROOT, "%c %.3f-%.3fs confidence=%.1f", symbol, start, end, confidence);
        }
    }

    public static BufferedImage waveform(WavSteganography.WavData wav, int channel, int width, int height) {
        BufferedImage output = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        Graphics2D graphics = output.createGraphics();
        graphics.setColor(Color.BLACK);
        graphics.fillRect(0, 0, width, height);
        graphics.setColor(new Color(60, 220, 230));
        int framesPerPixel = Math.max(1, wav.frameCount() / width);
        for (int x = 0; x < width; x++) {
            int start = x * framesPerPixel;
            int end = Math.min(wav.frameCount(), start + framesPerPixel);
            int min = 0;
            int max = 0;
            for (int frame = start; frame < end; frame++) {
                int value = wav.sampleValue(frame, channel);
                min = Math.min(min, value);
                max = Math.max(max, value);
            }
            double scale = (1L << (wav.bitsPerSample() - 1));
            int top = (int) (height / 2 - max * (height / 2 - 5) / scale);
            int bottom = (int) (height / 2 - min * (height / 2 - 5) / scale);
            graphics.drawLine(x, top, x, bottom);
        }
        graphics.dispose();
        return output;
    }

    public static BufferedImage spectrum(WavSteganography.WavData wav, int channel) {
        int fftSize = 1024;
        int columns = 256;
        int rows = 128;
        BufferedImage output = new BufferedImage(columns, rows, BufferedImage.TYPE_INT_RGB);
        double maxMagnitude = 0;
        double[][] magnitudes = new double[columns][fftSize / 2];
        for (int column = 0; column < columns; column++) {
            int start = (int) ((long) column * Math.max(1, wav.frameCount() - fftSize) / Math.max(1, columns - 1));
            double[] real = new double[fftSize];
            double[] imaginary = new double[fftSize];
            for (int i = 0; i < fftSize; i++) {
                int frame = Math.min(wav.frameCount() - 1, start + i);
                double window = 0.5 - 0.5 * Math.cos(2 * Math.PI * i / (fftSize - 1));
                real[i] = wav.sampleValue(frame, channel) * window;
            }
            fft(real, imaginary);
            for (int i = 0; i < fftSize / 2; i++) {
                magnitudes[column][i] = Math.log1p(Math.hypot(real[i], imaginary[i]));
                maxMagnitude = Math.max(maxMagnitude, magnitudes[column][i]);
            }
        }
        for (int x = 0; x < columns; x++) {
            for (int y = 0; y < rows; y++) {
                int frequency = (rows - 1 - y) * (fftSize / 2) / rows;
                int value = maxMagnitude == 0 ? 0 : (int) (255 * magnitudes[x][frequency] / maxMagnitude);
                output.setRGB(x, y, (value << 16) | (value << 8) | value);
            }
        }
        return output;
    }

    public static List<DTMF> detectDTMF(WavSteganography.WavData wav, int channel) {
        int window = Math.max(128, wav.sampleRate() / 50);
        List<DTMF> result = new ArrayList<>();
        char previous = 0;
        for (int start = 0; start + window <= wav.frameCount(); start += window / 2) {
            double[] samples = new double[window];
            double energy = 0;
            for (int i = 0; i < window; i++) {
                samples[i] = wav.sampleValue(start + i, channel);
                energy += samples[i] * samples[i];
            }
            if (energy / window < 100) {
                previous = 0;
                continue;
            }
            int low = strongest(samples, wav.sampleRate(), LOW);
            int high = strongest(samples, wav.sampleRate(), HIGH);
            double lowPower = goertzel(samples, wav.sampleRate(), LOW[low]);
            double highPower = goertzel(samples, wav.sampleRate(), HIGH[high]);
            double totalPower = 0;
            for (int frequency : LOW) {
                totalPower += goertzel(samples, wav.sampleRate(), frequency);
            }
            for (int frequency : HIGH) {
                totalPower += goertzel(samples, wav.sampleRate(), frequency);
            }
            double confidence = totalPower == 0 ? 0 : (lowPower + highPower) / totalPower * 100;
            char symbol = KEYS[low][high];
            if (confidence > 65 && symbol != previous) {
                result.add(new DTMF(symbol, (double) start / wav.sampleRate(),
                        (double) (start + window) / wav.sampleRate(), confidence));
                previous = symbol;
            } else if (confidence <= 65) {
                previous = 0;
            }
        }
        return result;
    }

    private static int strongest(double[] samples, int sampleRate, int[] frequencies) {
        int best = 0;
        double maximum = -1;
        for (int i = 0; i < frequencies.length; i++) {
            double power = goertzel(samples, sampleRate, frequencies[i]);
            if (power > maximum) {
                maximum = power;
                best = i;
            }
        }
        return best;
    }

    private static double goertzel(double[] samples, int sampleRate, int frequency) {
        double coefficient = 2 * Math.cos(2 * Math.PI * frequency / sampleRate);
        double previous = 0;
        double previousPrevious = 0;
        for (double sample : samples) {
            double current = sample + coefficient * previous - previousPrevious;
            previousPrevious = previous;
            previous = current;
        }
        return previousPrevious * previousPrevious + previous * previous - coefficient * previous * previousPrevious;
    }

    private static void fft(double[] real, double[] imaginary) {
        int length = real.length;
        for (int i = 1, j = 0; i < length; i++) {
            int bit = length >> 1;
            for (; (j & bit) != 0; bit >>= 1) {
                j ^= bit;
            }
            j ^= bit;
            if (i < j) {
                double value = real[i];
                real[i] = real[j];
                real[j] = value;
                value = imaginary[i];
                imaginary[i] = imaginary[j];
                imaginary[j] = value;
            }
        }
        for (int size = 2; size <= length; size <<= 1) {
            double angle = -2 * Math.PI / size;
            double wReal = Math.cos(angle);
            double wImaginary = Math.sin(angle);
            for (int start = 0; start < length; start += size) {
                double currentReal = 1;
                double currentImaginary = 0;
                for (int offset = 0; offset < size / 2; offset++) {
                    int even = start + offset;
                    int odd = even + size / 2;
                    double oddReal = real[odd] * currentReal - imaginary[odd] * currentImaginary;
                    double oddImaginary = real[odd] * currentImaginary + imaginary[odd] * currentReal;
                    real[odd] = real[even] - oddReal;
                    imaginary[odd] = imaginary[even] - oddImaginary;
                    real[even] += oddReal;
                    imaginary[even] += oddImaginary;
                    double nextReal = currentReal * wReal - currentImaginary * wImaginary;
                    currentImaginary = currentReal * wImaginary + currentImaginary * wReal;
                    currentReal = nextReal;
                }
            }
        }
    }
}
