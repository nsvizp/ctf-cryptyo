package crypto;

import myxfc.App.View.Modules.Tools.CTF.Engine.Audio.AudioAnalysisService;
import myxfc.App.View.Modules.Tools.CTF.Engine.Audio.WavSteganography;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AudioAnalysisServiceTest {
    @Test
    void wavLsbAndImagesWork() throws Exception {
        byte[] wavBytes = wav(8000, 10000, new int[0][0]);
        var wav = WavSteganography.parse(wavBytes);
        byte[] payload = "flag{wav_lsb}".getBytes(StandardCharsets.UTF_8);
        byte[] embedded = WavSteganography.embed(wav, payload, List.of(0));
        assertArrayEquals(payload, WavSteganography.extract(WavSteganography.parse(embedded), List.of(0)));
        assertNotNull(AudioAnalysisService.waveform(wav, 0, 200, 100));
        assertNotNull(AudioAnalysisService.spectrum(wav, 0));
        assertTrue(WavSteganography.metadata(wav).contains("Sample rate: 8000"));
    }

    @Test
    void dtmfSequenceIsDetected() throws Exception {
        int[][] frequencies = {{697, 1209}, {852, 1477}};
        byte[] wavBytes = wav(8000, 4000, frequencies);
        var wavData = WavSteganography.parse(wavBytes);
        var detections = AudioAnalysisService.detectDTMF(wavData, 0);
        assertEquals("19", myxfc.App.View.Modules.Tools.CTF.Engine.Audio.DtmfDecodeService.autoDetect(wavData).symbols());
        StringBuilder symbols = new StringBuilder();
        detections.forEach(value -> symbols.append(value.symbol()));
        assertTrue(symbols.toString().contains("1"), symbols.toString());
        assertTrue(symbols.toString().contains("9"), symbols.toString());
    }

    private static byte[] wav(int sampleRate, int framesPerTone, int[][] frequencies) throws Exception {
        ByteArrayOutputStream samples = new ByteArrayOutputStream();
        int frames = frequencies.length == 0 ? 10000 : frequencies.length * (framesPerTone + 800);
        for (int frame = 0; frame < frames; frame++) {
            int sample = 0;
            if (frequencies.length > 0 && frame % (framesPerTone + 800) < framesPerTone) {
                int tone = Math.min(frequencies.length - 1, frame / (framesPerTone + 800));
                sample = (int) (9000 * Math.sin(2 * Math.PI * frequencies[tone][0] * frame / sampleRate)
                        + 9000 * Math.sin(2 * Math.PI * frequencies[tone][1] * frame / sampleRate));
            }
            samples.write(sample & 0xFF);
            samples.write((sample >> 8) & 0xFF);
        }
        ByteArrayOutputStream wav = new ByteArrayOutputStream();
        wav.write("RIFF".getBytes(StandardCharsets.US_ASCII));
        write32(wav, 36 + samples.size());
        wav.write("WAVEfmt ".getBytes(StandardCharsets.US_ASCII));
        write32(wav, 16);
        write16(wav, 1);
        write16(wav, 1);
        write32(wav, sampleRate);
        write32(wav, sampleRate * 2);
        write16(wav, 2);
        write16(wav, 16);
        wav.write("data".getBytes(StandardCharsets.US_ASCII));
        write32(wav, samples.size());
        samples.writeTo(wav);
        return wav.toByteArray();
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
