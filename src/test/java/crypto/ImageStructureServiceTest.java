package crypto;

import myxfc.App.View.Modules.Tools.Image.Steganography.Engine.ExifService;
import myxfc.App.View.Modules.Tools.Image.Steganography.Engine.ImageStructureService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ImageStructureServiceTest {
    @TempDir
    Path tempDirectory;

    @Test
    void pngChunksTrailingDataAndCarvingWork() throws Exception {
        BufferedImage image = new BufferedImage(8, 8, BufferedImage.TYPE_INT_ARGB);
        Path png = tempDirectory.resolve("cover.png");
        ImageIO.write(image, "png", png.toFile());
        byte[] original = Files.readAllBytes(png);
        byte[] suffix = "hidden-tail".getBytes(StandardCharsets.UTF_8);
        byte[] combined = Arrays.copyOf(original, original.length + suffix.length);
        System.arraycopy(suffix, 0, combined, original.length, suffix.length);

        var chunks = ImageStructureService.parsePng(original);
        assertTrue(chunks.size() >= 3);
        assertTrue(chunks.stream().allMatch(ImageStructureService.PNGChunk::crcValid));
        assertArrayEquals(suffix, ImageStructureService.trailingData(combined).data());

        var carved = ImageStructureService.carve(combined);
        assertEquals(1, carved.size());
        assertArrayEquals(original, carved.get(0).data());
        assertTrue(ImageStructureService.metadata(png).contains("Width: 8"));
    }

    @Test
    void exifTiffFieldsAreDecoded() throws Exception {
        byte[] jpeg = minimalExifJpeg();
        Path path = tempDirectory.resolve("exif.jpg");
        Files.write(path, jpeg);
        String exif = ExifService.readExif(path);
        assertTrue(exif.contains("Make = MYXFC"), exif);
    }

    private static byte[] minimalExifJpeg() throws Exception {
        ByteArrayOutputStream tiff = new ByteArrayOutputStream();
        tiff.write('I');
        tiff.write('I');
        write16(tiff, 42);
        write32(tiff, 8);
        write16(tiff, 1);
        write16(tiff, 0x010F);
        write16(tiff, 2);
        write32(tiff, 6);
        write32(tiff, 26);
        write32(tiff, 0);
        tiff.write("MYXFC\0".getBytes(StandardCharsets.US_ASCII));

        ByteArrayOutputStream app = new ByteArrayOutputStream();
        app.write("Exif\0\0".getBytes(StandardCharsets.US_ASCII));
        app.write(tiff.toByteArray());

        ByteArrayOutputStream jpeg = new ByteArrayOutputStream();
        jpeg.write(0xFF);
        jpeg.write(0xD8);
        jpeg.write(0xFF);
        jpeg.write(0xE1);
        jpeg.write((app.size() + 2) >>> 8);
        jpeg.write((app.size() + 2) & 0xFF);
        app.writeTo(jpeg);
        jpeg.write(0xFF);
        jpeg.write(0xD9);
        return jpeg.toByteArray();
    }

    private static void write16(ByteArrayOutputStream output, int value) {
        output.write(value & 0xFF);
        output.write((value >>> 8) & 0xFF);
    }

    private static void write32(ByteArrayOutputStream output, long value) {
        output.write((int) (value & 0xFF));
        output.write((int) ((value >>> 8) & 0xFF));
        output.write((int) ((value >>> 16) & 0xFF));
        output.write((int) ((value >>> 24) & 0xFF));
    }
}
