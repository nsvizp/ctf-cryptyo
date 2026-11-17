package myxfc.App.View.Modules.Tools.CTF.Engine.Analysis;

import myxfc.App.View.Modules.Tools.CTF.Engine.Archive.ZipAnalysisService;
import myxfc.App.View.Modules.Tools.CTF.Engine.Audio.AudioAnalysisService;
import myxfc.App.View.Modules.Tools.CTF.Engine.Audio.DtmfDecodeService;
import myxfc.App.View.Modules.Tools.CTF.Engine.Audio.WavSteganography;
import myxfc.App.View.Modules.Tools.CTF.Engine.Decode.MultiDecodeService;
import myxfc.App.View.Modules.Tools.CTF.Engine.Document.OfficeAnalysisService;
import myxfc.App.View.Modules.Tools.CTF.Engine.Document.PdfAnalysisService;
import myxfc.App.View.Modules.Tools.CTF.Engine.Pcap.PcapAnalysisService;
import myxfc.App.View.Modules.Tools.Image.Steganography.Engine.DWTSteganography;
import myxfc.App.View.Modules.Tools.Image.Steganography.Engine.ImageStegoUtils;
import myxfc.App.View.Modules.Tools.Image.Steganography.Engine.ImageStructureService;
import myxfc.App.View.Modules.Tools.Image.Steganography.Engine.LSBSteganography;
import myxfc.App.View.Modules.Tools.Image.Steganography.Engine.PaletteSteganography;
import myxfc.App.View.Modules.Tools.Image.Steganography.Engine.PixelValueSteganography;

import java.awt.image.IndexColorModel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class AutoAnalysisService {
    public record Finding(String source, String method, String result, double score) {
        @Override
        public String toString() {
            return String.format("[%s] %.1f %s\n%s", source, score, method, result);
        }
    }

    public record FileAnalysis(Path path, List<Finding> findings, String error) {
    }

    public static void checkCancelled() {
        if (Thread.currentThread().isInterrupted()) {
            throw new java.util.concurrent.CancellationException("Analysis cancelled");
        }
    }

    public static List<FileAnalysis> analyzeAll(List<Path> paths) {
        List<FileAnalysis> reports = new ArrayList<>();
        for (Path path : paths) {
            checkCancelled();
            try {
                reports.add(new FileAnalysis(path, analyze(path), null));
            } catch (java.util.concurrent.CancellationException e) {
                throw e;
            } catch (Exception e) {
                String error = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
                reports.add(new FileAnalysis(path, List.of(), error));
            }
        }
        return List.copyOf(reports);
    }

    public static List<Finding> analyze(Path path) throws Exception {
        checkCancelled();
        byte[] bytes = Files.readAllBytes(path);
        checkCancelled();
        List<Finding> findings = new ArrayList<>();
        if (matches(bytes, "RIFF") && matches(bytes, 8, "WAVE")) {
            analyzeWav(path, findings);
        } else if (matches(bytes, 0, 0x89, 0x50, 0x4E, 0x47) || matches(bytes, 0, 0xFF, 0xD8, 0xFF)
                || matches(bytes, "GIF8") || matches(bytes, "BM")) {
            analyzeImage(path, findings);
        } else if (matches(bytes, "%PDF")) {
            findings.addAll(DocumentAnomalyService.analyze(path));
            try {
                add(findings, "PDF", "Structure", PdfAnalysisService.inspect(path), 20);
                for (PdfAnalysisService.PdfStream stream : PdfAnalysisService.extract(path)) {
                    add(findings, "PDF", "Embedded " + stream.kind(), stream.name(), 40);
                    analyzeText(stream.data(), "PDF object " + stream.objectNumber(), findings);
                }
            } catch (Exception e) {
                add(findings, "PDF", "Extraction failure", e.getMessage(), 80);
            }
        } else if (matches(bytes, "PK\003\004")) {
            analyzeZip(path, findings);
        } else if (matches(bytes, 0, 0xD4, 0xC3, 0xB2, 0xA1) || matches(bytes, 0, 0xA1, 0xB2, 0xC3, 0xD4)
                || matches(bytes, 0, 0x0A, 0x0D, 0x0D, 0x0A)) {
            analyzePcap(path, findings);
        } else {
            analyzeText(bytes, "Text", findings);
        }
        findings.sort(Comparator.comparingDouble(Finding::score).reversed());
        return List.copyOf(findings);
    }

    private static void analyzeWav(Path path, List<Finding> findings) throws Exception {
        var wav = WavSteganography.read(path);
        add(findings, "WAV", "Metadata", WavSteganography.metadata(wav), 10);
        List<Integer> channels = new ArrayList<>();
        for (int i = 0; i < wav.channels(); i++) {
            channels.add(i);
        }
        try {
            byte[] payload = WavSteganography.extract(wav, channels);
            add(findings, "WAV LSB", "Embedded payload", preview(payload), 90);
            analyzeText(payload, "WAV LSB", findings);
        } catch (Exception ignored) {
        }
        DtmfDecodeService.AutoResult dtmf = DtmfDecodeService.autoDetect(wav);
        if (!dtmf.symbols().isEmpty()) {
            add(findings, "DTMF", "Channel " + dtmf.channel(), dtmf.symbols(), 60);
            for (DtmfDecodeService.Candidate candidate : dtmf.candidates()) {
                add(findings, "DTMF", candidate.encoding(), candidate.text(), candidate.score());
            }
        }
    }

    private static void analyzeImage(Path path, List<Finding> findings) throws Exception {
        var image = ImageStegoUtils.read(path.toFile());
        add(findings, "Image", "Properties", image.getWidth() + "x" + image.getHeight(), 10);
        for (LSBSteganography.Detection detection : LSBSteganography.autoDetect(image, true, true, true, false)) {
            add(findings, "Image LSB", detection.settings().toString(), detection.preview(), detection.score());
            if (detection.framed()) {
                analyzeText(detection.data(), "Image LSB", findings);
            }
        }
        if (image.getColorModel() instanceof IndexColorModel) {
            try {
                byte[] payload = PaletteSteganography.extract(image);
                add(findings, "Palette", "Embedded payload", preview(payload), 85);
                analyzeText(payload, "Palette", findings);
            } catch (Exception ignored) {
            }
        }
        try {
            byte[] payload = DWTSteganography.extract(image, List.of('R', 'G', 'B'));
            add(findings, "DWT", "Haar payload", preview(payload), 85);
            analyzeText(payload, "DWT", findings);
        } catch (Exception ignored) {
        }
        try {
            byte[] payload = PixelValueSteganography.extract(image, List.of('R', 'G', 'B'), false);
            add(findings, "Pixel Value", "Embedded payload", preview(payload), 80);
            analyzeText(payload, "Pixel Value", findings);
        } catch (Exception ignored) {
        }
        byte[] bytes = Files.readAllBytes(path);
        var trailing = ImageStructureService.trailingData(bytes);
        if (trailing.data().length > 0) {
            add(findings, "File", "Trailing data", preview(trailing.data()), 70);
            analyzeText(trailing.data(), "Trailing data", findings);
        }
    }

    private static void analyzeZip(Path path, List<Finding> findings) throws Exception {
        findings.addAll(DocumentAnomalyService.analyze(path));
        List<ZipAnalysisService.ZipEntryInfo> entries;
        try {
            entries = ZipAnalysisService.inspect(path);
        } catch (Exception e) {
            add(findings, "ZIP", "Central directory failure", e.getMessage(), 90);
            entries = List.of();
        }
        StringBuilder summary = new StringBuilder();
        for (var entry : entries) {
            summary.append(entry.summary()).append('\n');
        }
        add(findings, "ZIP", "Entries", summary.toString(), 20);
        for (var entry : entries) {
            checkCancelled();
            if (entry.size() > 2_000_000 || entry.encrypted() || entry.name().endsWith("/")) {
                continue;
            }
            try {
                byte[] data = ZipAnalysisService.readEntry(path, entry.name());
                analyzeText(data, "ZIP " + entry.name(), findings);
            } catch (java.util.concurrent.CancellationException e) {
                throw e;
            } catch (Exception ignored) {
            }
        }
        add(findings, "ZIP", "Trailing", ZipAnalysisService.trailingReport(path), 20);
        if (Files.isRegularFile(path) && (entries.stream().anyMatch(entry -> entry.name().startsWith("word/"))
                || entries.stream().anyMatch(entry -> entry.name().startsWith("xl/")))) {
            add(findings, "Office", "Metadata and hidden content", OfficeAnalysisService.inspect(path), 40);
            for (var entry : OfficeAnalysisService.embedded(path)) {
                checkCancelled();
                analyzeText(entry.data(), "Office " + entry.name(), findings);
            }
        }
    }

    private static void analyzePcap(Path path, List<Finding> findings) throws Exception {
        var capture = PcapAnalysisService.read(path);
        add(findings, "PCAP", "Capture", "Packets: " + capture.packets().size(), 10);
        var smartReport = TrafficIntelligenceService.analyze(capture);
        add(findings, "PCAP", "Executive summary", smartReport.summary(), 10000);
        findings.addAll(smartReport.findings());
        var streams = PcapAnalysisService.tcpStreams(capture);
        for (var stream : streams) {
            checkCancelled();
            stream.directions().forEach((direction, data) -> analyzeText(data, "TCP " + direction, findings));
        }
        for (var object : PcapAnalysisService.httpObjects(streams)) {
            checkCancelled();
            add(findings, "HTTP", object.method() + " " + object.uri(), object.status() + " " + object.contentType(), 30);
            analyzeText(object.body(), "HTTP " + object.uri(), findings);
        }
    }

    private static void analyzeText(byte[] data, String source, List<Finding> findings) {
        checkCancelled();
        if (data == null || data.length == 0 || data.length > 2_000_000) {
            return;
        }
        String text = new String(data, StandardCharsets.UTF_8);
        double printable = text.chars().filter(c -> c == 9 || c == 10 || c == 13 || c >= 32 && c < 127).count()
                / (double) Math.max(1, text.length());
        if (printable >= 0.6) {
            add(findings, source, "Plain text", preview(data), 30 + printable * 30);
            try {
                for (MultiDecodeService.Result result : MultiDecodeService.decode(text, 6)) {
                    add(findings, source, result.chain(), result.output(), result.score());
                }
            } catch (IllegalArgumentException ignored) {
            }
        }
    }

    private static void add(List<Finding> findings, String source, String method, String result, double score) {
        if (result == null || result.isBlank()) {
            return;
        }
        String lower = result.toLowerCase();
        if (lower.contains("flag{") || lower.contains("ctf{")) {
            score += 200;
        }
        findings.add(new Finding(source, method, result, score));
    }

    private static String preview(byte[] data) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < data.length; i++) {
            int c = data[i] & 0xFF;
            result.append(c == 9 || c == 10 || c == 13 || c >= 32 && c < 127 ? (char) c : '.');
        }
        return result.toString();
    }

    private static boolean matches(byte[] bytes, String text) {
        return matches(bytes, 0, text.getBytes(StandardCharsets.ISO_8859_1));
    }

    private static boolean matches(byte[] bytes, int offset, String text) {
        return matches(bytes, offset, text.getBytes(StandardCharsets.ISO_8859_1));
    }

    private static boolean matches(byte[] bytes, int offset, int... values) {
        if (offset < 0 || offset + values.length > bytes.length) {
            return false;
        }
        for (int i = 0; i < values.length; i++) {
            if ((bytes[offset + i] & 0xFF) != values[i]) {
                return false;
            }
        }
        return true;
    }

    private static boolean matches(byte[] bytes, int offset, byte[] values) {
        if (offset < 0 || offset + values.length > bytes.length) {
            return false;
        }
        for (int i = 0; i < values.length; i++) {
            if (bytes[offset + i] != values[i]) {
                return false;
            }
        }
        return true;
    }
}
