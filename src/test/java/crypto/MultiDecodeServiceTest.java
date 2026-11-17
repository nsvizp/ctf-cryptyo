package crypto;

import myxfc.App.View.Modules.Encryption.Coding.BaseEncoding.CustomBase.CustomBaseImpl;
import myxfc.App.View.Modules.Tools.CTF.Engine.Decode.MultiDecodeService;
import org.junit.jupiter.api.Test;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MultiDecodeServiceTest {
    @Test
    void recursivelyDecodesNestedFormats() {
        String plaintext = "flag{multi_decode}";
        String base32 = CustomBaseImpl.encode(plaintext.getBytes(StandardCharsets.UTF_8),
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", '=', true);
        String url = URLEncoder.encode(base32, StandardCharsets.UTF_8);
        String base64 = Base64.getEncoder().encodeToString(url.getBytes(StandardCharsets.UTF_8));
        var results = MultiDecodeService.decode(base64, 6);
        assertEquals(plaintext, results.get(0).output());
        assertTrue(results.get(0).chain().contains("Base64"));
        assertTrue(results.get(0).chain().contains("Base32"));
        assertTrue(MultiDecodeService.identify(base64).contains("Base64"));
    }

    @Test
    void decodesHtmlEntities() {
        var results = MultiDecodeService.decode("&#102;&#108;&#97;&#103;&#123;&#104;&#116;&#109;&#108;&#125;", 2);
        assertEquals("flag{html}", results.get(0).output());
    }

    @Test
    void decodesEveryJwtInCommaSeparatedBatch() {
        String input = "eyJhbGciOiJub25lIn0.eyJpZCI6MX0.,"
                + "eyJhbGciOiJub25lIn0.eyJpZCI6Mn0.,"
                + "eyJhbGciOiJub25lIn0.eyJpZCI6M30.";
        String output = MultiDecodeService.decode(input, 6).get(0).output();
        assertTrue(output.contains("\"id\":1"), output);
        assertTrue(output.contains("\"id\":2"), output);
        assertTrue(output.contains("\"id\":3"), output);
    }

    @Test
    void decodesEveryUrlEncodedLine() {
        String input = "flag%7Bone%7D\nhello%20world\nflag%7Bthree%7D";
        String output = MultiDecodeService.decode(input, 6).get(0).output();
        assertTrue(output.contains("flag{one}"), output);
        assertTrue(output.contains("hello world"), output);
        assertTrue(output.contains("flag{three}"), output);
    }

    @Test
    void decodesMixedAndNestedEncodingBatches() {
        String nested = Base64.getEncoder().encodeToString(
                URLEncoder.encode("flag{nested}", StandardCharsets.UTF_8).getBytes(StandardCharsets.UTF_8));
        String base64 = Base64.getEncoder().encodeToString("flag{base64}".getBytes(StandardCharsets.UTF_8));
        var results = MultiDecodeService.decode(nested + "\n" + base64 + "\nflag%7Burl%7D", 6);
        assertEquals(1, results.size());
        assertEquals("Batch", results.get(0).chain());
        assertTrue(results.get(0).output().contains("flag{nested}"), results.get(0).output());
        assertTrue(results.get(0).output().contains("flag{base64}"), results.get(0).output());
        assertTrue(results.get(0).output().contains("flag{url}"), results.get(0).output());
    }
}
