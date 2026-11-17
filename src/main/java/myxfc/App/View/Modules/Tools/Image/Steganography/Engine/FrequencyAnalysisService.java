package myxfc.App.View.Modules.Tools.Image.Steganography.Engine;

import java.awt.image.BufferedImage;
import java.util.Locale;

public class FrequencyAnalysisService {
    public record DCTResult(BufferedImage coefficientMap, String report) {
    }

    public static BufferedImage frequencySpectrum(BufferedImage source) {
        BufferedImage image = ImageAnalysisService.scale(source, 256, 256);
        int width = image.getWidth();
        int height = image.getHeight();
        double[] real = new double[width * height];
        double[] imaginary = new double[width * height];
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                real[y * width + x] = luminance(image.getRGB(x, y));
            }
        }
        for (int y = 0; y < height; y++) {
            double[] rowReal = new double[width];
            double[] rowImaginary = new double[width];
            for (int x = 0; x < width; x++) {
                rowReal[x] = real[y * width + x];
                rowImaginary[x] = imaginary[y * width + x];
            }
            fft(rowReal, rowImaginary);
            for (int x = 0; x < width; x++) {
                real[y * width + x] = rowReal[x];
                imaginary[y * width + x] = rowImaginary[x];
            }
        }
        for (int x = 0; x < width; x++) {
            double[] columnReal = new double[height];
            double[] columnImaginary = new double[height];
            for (int y = 0; y < height; y++) {
                columnReal[y] = real[y * width + x];
                columnImaginary[y] = imaginary[y * width + x];
            }
            fft(columnReal, columnImaginary);
            for (int y = 0; y < height; y++) {
                real[y * width + x] = columnReal[y];
                imaginary[y * width + x] = columnImaginary[y];
            }
        }
        double maximum = 0;
        double[] magnitude = new double[real.length];
        for (int i = 0; i < real.length; i++) {
            magnitude[i] = Math.log1p(Math.hypot(real[i], imaginary[i]));
            maximum = Math.max(maximum, magnitude[i]);
        }
        BufferedImage output = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int shiftedY = (y + height / 2) % height;
                int shiftedX = (x + width / 2) % width;
                int value = (int) Math.round(255 * magnitude[shiftedY * width + shiftedX] / maximum);
                output.setRGB(x, y, (value << 16) | (value << 8) | value);
            }
        }
        return output;
    }

    public static DCTResult dctAnalysis(BufferedImage source) {
        BufferedImage image = ImageAnalysisService.scale(source, 256, 256);
        int width = image.getWidth();
        int height = image.getHeight();
        double[][] cosine = new double[8][8];
        for (int frequency = 0; frequency < 8; frequency++) {
            for (int position = 0; position < 8; position++) {
                cosine[frequency][position] = Math.cos((2 * position + 1) * frequency * Math.PI / 16);
            }
        }
        double[] coefficients = new double[width * height];
        double maximum = 0;
        double sum = 0;
        long zero = 0;
        for (int blockY = 0; blockY < height; blockY += 8) {
            for (int blockX = 0; blockX < width; blockX += 8) {
                for (int u = 0; u < 8; u++) {
                    for (int v = 0; v < 8; v++) {
                        double value = 0;
                        for (int y = 0; y < 8; y++) {
                            for (int x = 0; x < 8; x++) {
                                value += luminance(image.getRGB(blockX + x, blockY + y))
                                        * cosine[u][x] * cosine[v][y];
                            }
                        }
                        value *= 0.25 * scale(u) * scale(v);
                        coefficients[(blockY + v) * width + blockX + u] = value;
                        double magnitude = Math.abs(value);
                        maximum = Math.max(maximum, magnitude);
                        sum += magnitude;
                        if (magnitude < 0.01) {
                            zero++;
                        }
                    }
                }
            }
        }
        BufferedImage map = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        for (int i = 0; i < coefficients.length; i++) {
            int value = maximum == 0 ? 0
                    : (int) Math.round(255 * Math.log1p(Math.abs(coefficients[i])) / Math.log1p(maximum));
            map.setRGB(i % width, i / width, (value << 16) | (value << 8) | value);
        }
        String report = String.format(Locale.ROOT,
                "8x8 DCT coefficients: %d%nNear-zero (|c|<0.01): %d (%.2f%%)%nMean |coefficient|: %.4f%nMax |coefficient|: %.4f",
                coefficients.length, zero, zero * 100.0 / coefficients.length,
                sum / coefficients.length, maximum);
        return new DCTResult(map, report);
    }

    private static void fft(double[] real, double[] imaginary) {
        int length = real.length;
        if (Integer.bitCount(length) != 1) {
            throw new IllegalArgumentException("FFT input length must be a power of two");
        }
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

    private static double scale(int value) {
        return value == 0 ? 1 / Math.sqrt(2) : 1;
    }

    private static int luminance(int pixel) {
        return (ImageStegoUtils.getChannel(pixel, 'R') * 299
                + ImageStegoUtils.getChannel(pixel, 'G') * 587
                + ImageStegoUtils.getChannel(pixel, 'B') * 114) / 1000;
    }
}
