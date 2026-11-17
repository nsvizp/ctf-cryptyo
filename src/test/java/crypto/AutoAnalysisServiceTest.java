package crypto;

import myxfc.App.View.Modules.Tools.CTF.Engine.Analysis.AutoAnalysisService;
import myxfc.App.View.Modules.Tools.CTF.Engine.Audio.DtmfDecodeService;
import myxfc.App.View.Modules.Tools.Image.Steganography.Engine.ImageStegoUtils;
import myxfc.App.View.Modules.Tools.Image.Steganography.Engine.LSBSteganography;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.awt.image.BufferedImage;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AutoAnalysisServiceTest {
    @TempDir
    Path temp;

    @Test
    void textAndZipAreAutomaticallyDecoded() throws Exception {
        Path text = temp.resolve("encoded.txt");
        Files.writeString(text, Base64.getEncoder().encodeToString("flag{auto_text}".getBytes(StandardCharsets.UTF_8)));
        assertTrue(AutoAnalysisService.analyze(text).toString().contains("flag{auto_text}"));

        Path zip = temp.resolve("hidden.zip");
        try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(zip))) {
            output.putNextEntry(new ZipEntry("flag.txt"));
            output.write("flag{auto_zip}".getBytes(StandardCharsets.UTF_8));
            output.closeEntry();
        }
        assertTrue(AutoAnalysisService.analyze(zip).toString().contains("flag{auto_zip}"));
    }

    @Test
    void imageLsbIsAutomaticallyDetected() throws Exception {
        BufferedImage image = new BufferedImage(48, 48, BufferedImage.TYPE_INT_ARGB);
        var settings = new LSBSteganography.Settings(List.of('R', 'G', 'B'), 0, false, false, "RGB");
        byte[] payload = "flag{auto_image}".getBytes(StandardCharsets.UTF_8);
        Path png = temp.resolve("stego.png");
        ImageStegoUtils.writePng(LSBSteganography.embed(image, payload, settings), png.toFile());
        assertTrue(AutoAnalysisService.analyze(png).toString().contains("flag{auto_image}"));
    }

    @Test
    void analyzesMultipleImagesIndependently() throws Exception {
        Path first = temp.resolve("first.png");
        Path second = temp.resolve("second.png");
        var settings = new LSBSteganography.Settings(List.of('R', 'G', 'B'), 0, false, false, "RGB");
        BufferedImage image = new BufferedImage(48, 48, BufferedImage.TYPE_INT_ARGB);
        ImageStegoUtils.writePng(LSBSteganography.embed(image,
                "flag{batch_first}".getBytes(StandardCharsets.UTF_8), settings), first.toFile());
        ImageStegoUtils.writePng(LSBSteganography.embed(image,
                "flag{batch_second}".getBytes(StandardCharsets.UTF_8), settings), second.toFile());

        var reports = AutoAnalysisService.analyzeAll(List.of(first, second));
        assertEquals(2, reports.size());
        assertTrue(reports.get(0).findings().toString().contains("flag{batch_first}"));
        assertTrue(reports.get(1).findings().toString().contains("flag{batch_second}"));
    }

    @Test
    void dtmfCandidatesIncludeCommonEncodings() {
        var candidates = DtmfDecodeService.decodeCandidates("666C6167");
        assertTrue(candidates.stream().anyMatch(candidate -> candidate.text().equals("flag")));
        assertTrue(DtmfDecodeService.decodeCandidates("102108097103").stream()
                .anyMatch(candidate -> candidate.text().equals("flag")));
        assertEquals("HELLO", DtmfDecodeService.decodeCandidates("44 33 555 555 666").stream()
                .filter(candidate -> candidate.encoding().equals("Phone T9")).findFirst().orElseThrow().text());
    }
}
