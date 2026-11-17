package myxfc.App.View.Modules.Tools.Image.Steganography.Engine;

import javax.imageio.ImageIO;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class ImageStegoUtils {
    public static BufferedImage read(File file) throws IOException {
        BufferedImage image = ImageIO.read(file);
        if (image == null) {
            throw new IOException("Unsupported or damaged image: " + file);
        }
        return image;
    }

    public static BufferedImage argb(BufferedImage source) {
        if (source.getType() == BufferedImage.TYPE_INT_ARGB) {
            BufferedImage copy = new BufferedImage(source.getWidth(), source.getHeight(), BufferedImage.TYPE_INT_ARGB);
            copy.setRGB(0, 0, source.getWidth(), source.getHeight(),
                    source.getRGB(0, 0, source.getWidth(), source.getHeight(), null, 0, source.getWidth()),
                    0, source.getWidth());
            return copy;
        }
        BufferedImage result = new BufferedImage(source.getWidth(), source.getHeight(), BufferedImage.TYPE_INT_ARGB);
        Graphics2D graphics = result.createGraphics();
        graphics.drawImage(source, 0, 0, null);
        graphics.dispose();
        return result;
    }

    public static void writePng(BufferedImage image, File output) throws IOException {
        if (!ImageIO.write(image, "png", output)) {
            throw new IOException("Unable to write PNG: " + output);
        }
    }

    public static List<Character> channels(String order, boolean r, boolean g, boolean b, boolean a) {
        String normalized = order == null ? "RGB" : order.toUpperCase();
        if (!normalized.matches("[RGBA]+")) {
            throw new IllegalArgumentException("Channel order must contain only R, G, B and A");
        }
        List<Character> result = new ArrayList<>();
        for (char channel : normalized.toCharArray()) {
            boolean selected = switch (channel) {
                case 'R' -> r;
                case 'G' -> g;
                case 'B' -> b;
                case 'A' -> a;
                default -> false;
            };
            if (selected && !result.contains(channel)) {
                result.add(channel);
            }
        }
        if (result.isEmpty()) {
            throw new IllegalArgumentException("At least one channel must be selected");
        }
        return result;
    }

    public static int getChannel(int pixel, char channel) {
        return switch (channel) {
            case 'R' -> (pixel >>> 16) & 0xFF;
            case 'G' -> (pixel >>> 8) & 0xFF;
            case 'B' -> pixel & 0xFF;
            case 'A' -> (pixel >>> 24) & 0xFF;
            default -> throw new IllegalArgumentException("Unknown channel: " + channel);
        };
    }

    public static int setChannel(int pixel, char channel, int value) {
        return switch (channel) {
            case 'R' -> (pixel & 0xFF00FFFF) | ((value & 0xFF) << 16);
            case 'G' -> (pixel & 0xFFFF00FF) | ((value & 0xFF) << 8);
            case 'B' -> (pixel & 0xFFFFFF00) | (value & 0xFF);
            case 'A' -> (pixel & 0x00FFFFFF) | ((value & 0xFF) << 24);
            default -> throw new IllegalArgumentException("Unknown channel: " + channel);
        };
    }

    public static Iterable<int[]> pixels(BufferedImage image, boolean columnScan) {
        List<int[]> coordinates = new ArrayList<>(image.getWidth() * image.getHeight());
        if (columnScan) {
            for (int x = 0; x < image.getWidth(); x++) {
                for (int y = 0; y < image.getHeight(); y++) {
                    coordinates.add(new int[]{x, y});
                }
            }
        } else {
            for (int y = 0; y < image.getHeight(); y++) {
                for (int x = 0; x < image.getWidth(); x++) {
                    coordinates.add(new int[]{x, y});
                }
            }
        }
        return coordinates;
    }
}
