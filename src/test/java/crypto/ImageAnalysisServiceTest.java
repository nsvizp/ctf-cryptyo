package crypto;

import myxfc.App.View.Modules.Tools.Image.Steganography.Engine.FrequencyAnalysisService;
import myxfc.App.View.Modules.Tools.Image.Steganography.Engine.ImageAnalysisService;
import org.junit.jupiter.api.Test;

import java.awt.image.BufferedImage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ImageAnalysisServiceTest {
    @Test
    void channelBitPlaneAndColorOperationsWork() {
        BufferedImage image = new BufferedImage(2, 2, BufferedImage.TYPE_INT_ARGB);
        image.setRGB(0, 0, 0xFF000000);
        image.setRGB(1, 0, 0xFFFFFFFF);
        image.setRGB(0, 1, 0xFF112233);
        image.setRGB(1, 1, 0x80445566);

        assertEquals(0xFF000000, ImageAnalysisService.bitPlane(image, 'R', 0).getRGB(0, 0));
        assertEquals(0xFFFFFFFF, ImageAnalysisService.bitPlane(image, 'R', 0).getRGB(1, 0));
        assertEquals(0x00FFFFFF, ImageAnalysisService.invert(image).getRGB(0, 0) & 0x00FFFFFF);
        assertEquals(255, ImageAnalysisService.adjust(image, 300, 1).getRGB(0, 0) & 0xFF);
        assertEquals(4, ImageAnalysisService.histogram(image).length);
    }

    @Test
    void compareScaleRotateAndMirrorWork() {
        BufferedImage first = gradient(3, 2);
        BufferedImage second = gradient(3, 2);
        for (ImageAnalysisService.CompareMode mode : ImageAnalysisService.CompareMode.values()) {
            assertNotNull(ImageAnalysisService.compare(first, second, mode));
        }
        assertEquals(5, ImageAnalysisService.scale(first, 5, 4).getWidth());
        assertEquals(2, ImageAnalysisService.rotate(first, 90).getWidth());
        assertEquals(first.getRGB(2, 0), ImageAnalysisService.mirror(first,
                ImageAnalysisService.MirrorMode.HORIZONTAL).getRGB(0, 0));
        assertTrue(ImageAnalysisService.pixelInfo(first, 1, 1).contains("R="));
        assertTrue(ImageAnalysisService.anomalyReport(first).contains("odd="));
    }

    @Test
    void compareKeepsTheFullBoundsOfDifferentSizedImages() {
        BufferedImage first = gradient(3, 2);
        BufferedImage second = gradient(5, 4);
        for (ImageAnalysisService.CompareMode mode : ImageAnalysisService.CompareMode.values()) {
            BufferedImage compared = ImageAnalysisService.compare(first, second, mode);
            assertEquals(5, compared.getWidth());
            assertEquals(4, compared.getHeight());
        }
    }

    @Test
    void frequencyAndDctProduceOutputs() {
        BufferedImage image = gradient(32, 32);
        assertEquals(256, FrequencyAnalysisService.frequencySpectrum(image).getWidth());
        FrequencyAnalysisService.DCTResult result = FrequencyAnalysisService.dctAnalysis(image);
        assertEquals(256, result.coefficientMap().getWidth());
        assertTrue(result.report().contains("8x8 DCT coefficients: 65536"));
        assertNotNull(ImageAnalysisService.histogramImage(image, 'G'));
    }

    private static BufferedImage gradient(int width, int height) {
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                image.setRGB(x, y, 0xFF000000 | (x * 17 << 16) | (y * 19 << 8) | (x + y));
            }
        }
        return image;
    }
}
