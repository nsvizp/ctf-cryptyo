package myxfc.App.View.Modules.Tools.Image.Steganography.Engine;

import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.util.Locale;

public class ImageAnalysisService {
    public enum CompareMode {DIFFERENCE, XOR, OVERLAY}
    public enum MirrorMode {HORIZONTAL, VERTICAL}

    public static BufferedImage channel(BufferedImage image, char channel) {
        BufferedImage output = ImageStegoUtils.argb(image);
        for (int y = 0; y < image.getHeight(); y++) {
            for (int x = 0; x < image.getWidth(); x++) {
                int value = ImageStegoUtils.getChannel(image.getRGB(x, y), channel);
                output.setRGB(x, y, 0xFF000000 | (value << 16) | (value << 8) | value);
            }
        }
        return output;
    }

    public static BufferedImage bitPlane(BufferedImage image, char channel, int plane) {
        if (plane < 0 || plane > 7) {
            throw new IllegalArgumentException("Bit plane must be between 0 and 7");
        }
        BufferedImage output = ImageStegoUtils.argb(image);
        for (int y = 0; y < image.getHeight(); y++) {
            for (int x = 0; x < image.getWidth(); x++) {
                int value = (ImageStegoUtils.getChannel(image.getRGB(x, y), channel) >>> plane) & 1;
                int gray = value == 0 ? 0 : 255;
                output.setRGB(x, y, 0xFF000000 | (gray << 16) | (gray << 8) | gray);
            }
        }
        return output;
    }

    public static BufferedImage invert(BufferedImage image) {
        BufferedImage output = ImageStegoUtils.argb(image);
        for (int y = 0; y < image.getHeight(); y++) {
            for (int x = 0; x < image.getWidth(); x++) {
                int pixel = image.getRGB(x, y);
                output.setRGB(x, y, pixel ^ 0x00FFFFFF);
            }
        }
        return output;
    }

    public static BufferedImage adjust(BufferedImage image, double brightness, double contrast) {
        BufferedImage output = ImageStegoUtils.argb(image);
        for (int y = 0; y < image.getHeight(); y++) {
            for (int x = 0; x < image.getWidth(); x++) {
                int pixel = image.getRGB(x, y);
                for (char channel : new char[]{'R', 'G', 'B'}) {
                    int value = ImageStegoUtils.getChannel(pixel, channel);
                    int adjusted = clamp((value - 128) * contrast + 128 + brightness);
                    pixel = ImageStegoUtils.setChannel(pixel, channel, adjusted);
                }
                output.setRGB(x, y, pixel);
            }
        }
        return output;
    }

    public static BufferedImage compare(BufferedImage first, BufferedImage second, CompareMode mode) {
        int width = Math.max(first.getWidth(), second.getWidth());
        int height = Math.max(first.getHeight(), second.getHeight());
        BufferedImage output = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int a = x < first.getWidth() && y < first.getHeight() ? first.getRGB(x, y) : 0;
                int b = x < second.getWidth() && y < second.getHeight() ? second.getRGB(x, y) : 0;
                int pixel = switch (mode) {
                    case DIFFERENCE -> difference(a, b);
                    case XOR -> (a & 0xFF000000) | ((a ^ b) & 0x00FFFFFF);
                    case OVERLAY -> overlay(a, b);
                };
                output.setRGB(x, y, pixel);
            }
        }
        return output;
    }

    public static BufferedImage scale(BufferedImage image, int width, int height) {
        if (width <= 0 || height <= 0) {
            throw new IllegalArgumentException("Image dimensions must be positive");
        }
        BufferedImage output = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
        Graphics2D graphics = output.createGraphics();
        graphics.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BICUBIC);
        graphics.drawImage(image, 0, 0, width, height, null);
        graphics.dispose();
        return output;
    }

    public static BufferedImage rotate(BufferedImage image, int degrees) {
        int normalized = ((degrees % 360) + 360) % 360;
        if (normalized % 90 != 0) {
            throw new IllegalArgumentException("Rotation must be a multiple of 90 degrees");
        }
        if (normalized == 0) {
            return ImageStegoUtils.argb(image);
        }
        int width = normalized % 180 == 0 ? image.getWidth() : image.getHeight();
        int height = normalized % 180 == 0 ? image.getHeight() : image.getWidth();
        BufferedImage output = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
        for (int y = 0; y < image.getHeight(); y++) {
            for (int x = 0; x < image.getWidth(); x++) {
                int[] target = switch (normalized) {
                    case 90 -> new int[]{image.getHeight() - 1 - y, x};
                    case 180 -> new int[]{image.getWidth() - 1 - x, image.getHeight() - 1 - y};
                    default -> new int[]{y, image.getWidth() - 1 - x};
                };
                output.setRGB(target[0], target[1], image.getRGB(x, y));
            }
        }
        return output;
    }

    public static BufferedImage mirror(BufferedImage image, MirrorMode mode) {
        BufferedImage output = ImageStegoUtils.argb(image);
        for (int y = 0; y < image.getHeight(); y++) {
            for (int x = 0; x < image.getWidth(); x++) {
                int targetX = mode == MirrorMode.HORIZONTAL ? image.getWidth() - 1 - x : x;
                int targetY = mode == MirrorMode.VERTICAL ? image.getHeight() - 1 - y : y;
                output.setRGB(targetX, targetY, image.getRGB(x, y));
            }
        }
        return output;
    }

    public static int[][] histogram(BufferedImage image) {
        int[][] result = new int[4][256];
        for (int y = 0; y < image.getHeight(); y++) {
            for (int x = 0; x < image.getWidth(); x++) {
                int pixel = image.getRGB(x, y);
                result[0][ImageStegoUtils.getChannel(pixel, 'R')]++;
                result[1][ImageStegoUtils.getChannel(pixel, 'G')]++;
                result[2][ImageStegoUtils.getChannel(pixel, 'B')]++;
                result[3][ImageStegoUtils.getChannel(pixel, 'A')]++;
            }
        }
        return result;
    }

    public static BufferedImage histogramImage(BufferedImage image, char channel) {
        int channelIndex = switch (channel) {
            case 'R' -> 0;
            case 'G' -> 1;
            case 'B' -> 2;
            case 'A' -> 3;
            default -> throw new IllegalArgumentException("Unknown channel");
        };
        int[] values = histogram(image)[channelIndex];
        int max = 1;
        for (int value : values) {
            max = Math.max(max, value);
        }
        BufferedImage output = new BufferedImage(768, 360, BufferedImage.TYPE_INT_RGB);
        Graphics2D graphics = output.createGraphics();
        graphics.setColor(Color.WHITE);
        graphics.fillRect(0, 0, output.getWidth(), output.getHeight());
        graphics.setColor(switch (channel) {
            case 'R' -> Color.RED;
            case 'G' -> new Color(0, 150, 0);
            case 'B' -> Color.BLUE;
            default -> Color.DARK_GRAY;
        });
        for (int i = 0; i < 256; i++) {
            int height = (int) Math.round(values[i] * 300.0 / max);
            graphics.fillRect(i * 3, 330 - height, 3, height);
        }
        graphics.dispose();
        return output;
    }

    public static String anomalyReport(BufferedImage image) {
        StringBuilder report = new StringBuilder();
        report.append(String.format(Locale.ROOT, "Size: %dx%d%n", image.getWidth(), image.getHeight()));
        for (char channel : new char[]{'R', 'G', 'B', 'A'}) {
            long odd = 0;
            long zero = 0;
            long maximum = 0;
            double sum = 0;
            double sumSquares = 0;
            long count = (long) image.getWidth() * image.getHeight();
            for (int y = 0; y < image.getHeight(); y++) {
                for (int x = 0; x < image.getWidth(); x++) {
                    int value = ImageStegoUtils.getChannel(image.getRGB(x, y), channel);
                    odd += value & 1;
                    if (value == 0) {
                        zero++;
                    }
                    if (value == 255) {
                        maximum++;
                    }
                    sum += value;
                    sumSquares += (double) value * value;
                }
            }
            double mean = sum / count;
            double deviation = Math.sqrt(Math.max(0, sumSquares / count - mean * mean));
            report.append(String.format(Locale.ROOT,
                    "%c: odd=%.2f%%, zero=%d, 255=%d, mean=%.2f, stddev=%.2f%n",
                    channel, odd * 100.0 / count, zero, maximum, mean, deviation));
        }
        return report.toString();
    }

    public static String pixelInfo(BufferedImage image, int x, int y) {
        if (x < 0 || y < 0 || x >= image.getWidth() || y >= image.getHeight()) {
            throw new IllegalArgumentException("Pixel coordinates are outside the image");
        }
        int pixel = image.getRGB(x, y);
        return String.format(Locale.ROOT, "(%d,%d) #%08X  A=%d R=%d G=%d B=%d", x, y, pixel,
                ImageStegoUtils.getChannel(pixel, 'A'), ImageStegoUtils.getChannel(pixel, 'R'),
                ImageStegoUtils.getChannel(pixel, 'G'), ImageStegoUtils.getChannel(pixel, 'B'));
    }

    private static int difference(int first, int second) {
        int result = first & 0xFF000000;
        for (char channel : new char[]{'R', 'G', 'B'}) {
            int value = Math.abs(ImageStegoUtils.getChannel(first, channel)
                    - ImageStegoUtils.getChannel(second, channel));
            result = ImageStegoUtils.setChannel(result, channel, value);
        }
        return result;
    }

    private static int overlay(int first, int second) {
        int result = first & 0xFF000000;
        for (char channel : new char[]{'R', 'G', 'B'}) {
            int value = (ImageStegoUtils.getChannel(first, channel)
                    + ImageStegoUtils.getChannel(second, channel)) / 2;
            result = ImageStegoUtils.setChannel(result, channel, value);
        }
        return result;
    }

    private static int clamp(double value) {
        return (int) Math.max(0, Math.min(255, Math.round(value)));
    }
}
