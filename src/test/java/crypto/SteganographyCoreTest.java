package crypto;

import myxfc.App.View.Modules.Tools.Image.Steganography.Engine.DWTSteganography;
import myxfc.App.View.Modules.Tools.Image.Steganography.Engine.ImageStegoUtils;
import myxfc.App.View.Modules.Tools.Image.Steganography.Engine.LSBSteganography;
import myxfc.App.View.Modules.Tools.Image.Steganography.Engine.PaletteSteganography;
import myxfc.App.View.Modules.Tools.Image.Steganography.Engine.PixelValueSteganography;
import org.junit.jupiter.api.Test;

import java.awt.image.BufferedImage;
import java.awt.image.IndexColorModel;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SteganographyCoreTest {
    @Test
    void lsbRoundTripsEveryBitOrderAndScanMode() {
        BufferedImage image = testImage(48, 48);
        byte[] payload = "flag{lsb_test}".getBytes(StandardCharsets.UTF_8);
        for (String order : new String[]{"RGB", "BGR", "RGBA", "ABGR"}) {
            for (boolean msb : new boolean[]{false, true}) {
                for (boolean columns : new boolean[]{false, true}) {
                    var settings = new LSBSteganography.Settings(
                            ImageStegoUtils.channels(order, true, true, true, true), 2, msb, columns, order);
                    BufferedImage embedded = LSBSteganography.embed(image, payload, settings);
                    assertArrayEquals(payload, LSBSteganography.extract(embedded, settings));
                }
            }
        }
    }

    @Test
    void lsbAutoDetectionFindsPayload() {
        BufferedImage image = testImage(64, 64);
        byte[] payload = "flag{auto_detect}".getBytes(StandardCharsets.UTF_8);
        var settings = new LSBSteganography.Settings(List.of('R', 'G', 'B'), 0, false, false, "RGB");
        BufferedImage embedded = LSBSteganography.embed(image, payload, settings);
        var detections = LSBSteganography.autoDetect(embedded, true, true, true, false);
        assertTrue(detections.get(0).framed());
        assertArrayEquals(payload, detections.get(0).data());
    }

    @Test
    void lsbAutoDetectionReturnsCompleteRawDataAndPreview() {
        BufferedImage image = testImage(128, 128);
        byte[] payload = new byte[5000];
        java.util.Arrays.fill(payload, (byte) 'A');
        byte[] ending = "END flag{raw_complete}".getBytes(StandardCharsets.UTF_8);
        System.arraycopy(ending, 0, payload, payload.length - ending.length, ending.length);
        for (long bit = 0; bit < (long) payload.length * 8; bit++) {
            int pixelIndex = (int) (bit / 3);
            int channel = (int) (bit % 3);
            int x = pixelIndex % image.getWidth();
            int y = pixelIndex / image.getWidth();
            int pixel = image.getRGB(x, y);
            int shift = channel == 0 ? 16 : channel == 1 ? 8 : 0;
            int bitValue = (payload[(int) (bit / 8)] >>> (int) (bit % 8)) & 1;
            pixel = (pixel & ~(1 << shift)) | (bitValue << shift);
            image.setRGB(x, y, pixel);
        }
        var detection = LSBSteganography.autoDetect(image, true, true, true, false).stream()
                .filter(value -> !value.framed() && value.settings().order().equals("RGB")
                        && value.settings().bitPlane() == 0 && !value.settings().msbFirst()
                        && !value.settings().columnScan())
                .findFirst().orElseThrow();
        assertEquals(128 * 128 * 3 / 8, detection.data().length);
        assertTrue(new String(detection.data(), StandardCharsets.ISO_8859_1).contains("END flag{raw_complete}"));
        assertTrue(detection.preview().contains("END flag{raw_complete}"));
    }

    @Test
    void paletteRoundTripsPayload() {
        byte[] reds = new byte[64];
        byte[] greens = new byte[64];
        byte[] blues = new byte[64];
        for (int i = 0; i < 64; i++) {
            reds[i] = (byte) (i * 3);
            greens[i] = (byte) (255 - i * 2);
            blues[i] = (byte) (i + 20);
        }
        IndexColorModel model = new IndexColorModel(8, 64, reds, greens, blues);
        BufferedImage image = new BufferedImage(model, model.createCompatibleWritableRaster(16, 16), false, null);
        byte[] payload = "palette".getBytes(StandardCharsets.UTF_8);
        BufferedImage embedded = PaletteSteganography.embed(image, payload);
        assertArrayEquals(payload, PaletteSteganography.extract(embedded));
    }

    @Test
    void pixelValueMappingRoundTripsPayload() {
        BufferedImage image = testImage(24, 24);
        byte[] payload = "pixels".getBytes(StandardCharsets.UTF_8);
        BufferedImage embedded = PixelValueSteganography.embed(image, payload, List.of('R', 'G', 'B'), false);
        assertArrayEquals(payload, PixelValueSteganography.extract(embedded, List.of('R', 'G', 'B'), false));
    }

    @Test
    void dwtRoundTripsPayload() {
        BufferedImage image = testImage(32, 32);
        byte[] payload = "flag{dwt_haar}".getBytes(StandardCharsets.UTF_8);
        List<Character> channels = List.of('R', 'G', 'B');
        BufferedImage embedded = DWTSteganography.embed(image, payload, channels);
        assertArrayEquals(payload, DWTSteganography.extract(embedded, channels));
    }

    @Test
    void losslessPngRoundTripsPreservePayloads() throws Exception {
        java.nio.file.Path file = java.nio.file.Files.createTempFile("myxfc-stego", ".png");
        try {
            byte[] payload = "flag{png_roundtrip}".getBytes(StandardCharsets.UTF_8);
            var settings = new LSBSteganography.Settings(List.of('R', 'G', 'B'), 0, false, false, "RGB");
            ImageStegoUtils.writePng(LSBSteganography.embed(testImage(64, 64), payload, settings), file.toFile());
            assertArrayEquals(payload, LSBSteganography.extract(ImageStegoUtils.read(file.toFile()), settings));

            ImageStegoUtils.writePng(DWTSteganography.embed(testImage(32, 32), payload, List.of('R', 'G', 'B')), file.toFile());
            assertArrayEquals(payload, DWTSteganography.extract(ImageStegoUtils.read(file.toFile()), List.of('R', 'G', 'B')));
        } finally {
            java.nio.file.Files.deleteIfExists(file);
        }
    }

    private static BufferedImage testImage(int width, int height) {
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
        Random random = new Random(1234567);
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                image.setRGB(x, y, random.nextInt());
            }
        }
        return image;
    }
}
