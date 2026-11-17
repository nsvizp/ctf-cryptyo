package myxfc.App.View.Modules.Tools.CTF;

import com.jfoenix.controls.JFXComboBox;
import com.jfoenix.controls.JFXTextArea;
import com.jfoenix.controls.JFXTextField;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.image.ImageView;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import myxfc.App.View.Modules.Tools.CTF.Engine.Archive.BinwalkService;
import myxfc.App.View.Modules.Tools.CTF.Engine.Archive.ZipAnalysisService;
import myxfc.App.View.Modules.Tools.CTF.Engine.Audio.AudioAnalysisService;
import myxfc.App.View.Modules.Tools.CTF.Engine.Audio.WavSteganography;
import myxfc.App.View.Modules.Tools.CTF.Engine.Audio.DtmfDecodeService;
import myxfc.App.View.Modules.Tools.CTF.Engine.Crypto.ClassicalAttackService;
import myxfc.App.View.Modules.Tools.CTF.Engine.Crypto.RsaAttackService;
import myxfc.App.View.Modules.Tools.CTF.Engine.Decode.MultiDecodeService;
import myxfc.App.View.Modules.Tools.CTF.Engine.Document.OfficeAnalysisService;
import myxfc.App.View.Modules.Tools.CTF.Engine.Document.PdfAnalysisService;
import myxfc.App.View.Modules.Tools.CTF.Engine.Pcap.PcapAnalysisService;
import myxfc.App.View.Viewobj.ViewController;
import myxfc.Kit.Utils.ViewNode;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

@ViewNode(name = "CTFToolkit", folderPath = "Root/Tools/CTF/", fxmlName = "CtfToolkitView.fxml")
public class CtfToolkitController extends ViewController {
    @FXML private JFXComboBox<Integer> JCB_decodeDepth;
    @FXML private JFXTextField JTF_decodeKey;
    @FXML private JFXTextField JTF_decodeIv;
    @FXML private JFXComboBox<String> JCB_wavChannel;
    @FXML private JFXComboBox<String> JCB_attackMode;
    @FXML private JFXComboBox<Integer> JCB_attackKeyLength;
    @FXML private JFXTextArea JTA_decodeInput;
    @FXML private JFXTextArea JTA_decodeOutput;
    @FXML private JFXTextArea JTA_zipOutput;
    @FXML private JFXTextArea JTA_audioPayload;
    @FXML private JFXTextArea JTA_audioOutput;
    @FXML private JFXTextArea JTA_pcapOutput;
    @FXML private JFXTextArea JTA_cryptoInput;
    @FXML private JFXTextArea JTA_cryptoOutput;
    @FXML private JFXTextArea JTA_documentOutput;
    @FXML private JFXTextArea JTA_autoOutput;
    @FXML private ImageView IV_audio;

    private File autoFile;
    private List<File> autoFiles = List.of();
    private volatile boolean autoRunning;
    private java.util.concurrent.ExecutorService autoExecutor;
    private Thread autoWorker;
    private File zipFile;
    private File wavFile;
    private File pcapFile;
    private File documentFile;
    private WavSteganography.WavData wav;
    private PcapAnalysisService.Capture capture;
    private byte[] wavOutput;
    private byte[] audioPayload;
    private List<PcapAnalysisService.HttpObject> httpObjects;

    @Override
    protected void initialize() {
        JTA_src = JTA_decodeInput;
        JTA_dst = JTA_decodeOutput;
        super.initialize();
        for (int i = 1; i <= 10; i++) {
            JCB_decodeDepth.getItems().add(i);
        }
        JCB_decodeDepth.setValue(6);
        JCB_wavChannel.getItems().setAll("Channel 0", "Channel 1", "Both");
        JCB_wavChannel.setValue("Channel 0");
        JCB_attackMode.getItems().setAll("RSA Small Exponent", "RSA Common Modulus", "RSA Wiener",
                "RSA Factor from d", "RSA Recover from dp", "RSA CRT Decrypt",
                "Vigenere Auto Crack", "XOR Auto Crack", "XOR Known Plaintext");
        JCB_attackMode.setValue("RSA Small Exponent");
        for (int i = 1; i <= 40; i++) {
            JCB_attackKeyLength.getItems().add(i);
        }
        JCB_attackKeyLength.setValue(20);
    }

    @FXML public void ONClickLoadAuto() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Open files for automatic CTF analysis");
        List<File> files = chooser.showOpenMultipleDialog(ACP_controllerAnchorPane.getScene().getWindow());
        if (files != null && !files.isEmpty()) {
            autoFiles = List.copyOf(files);
            autoFile = files.get(0);
            StringBuilder selected = new StringBuilder("Selected ").append(files.size()).append(" file(s):\n");
            files.forEach(file -> selected.append(file).append('\n'));
            JTA_autoOutput.setText(selected.append("Click Auto Analyze.").toString());
        }
    }

    @FXML public void ONClickAutoAnalyze() {
        if (autoRunning) {
            JTA_autoOutput.setText("Analysis is already running");
            return;
        }
        if (autoFiles.isEmpty()) {
            JTA_autoOutput.setText("Load one or more files first");
            return;
        }
        autoRunning = true;
        List<Path> paths = autoFiles.stream().map(File::toPath).toList();
        JTA_autoOutput.setText("Analyzing " + paths.size() + " file(s), 0/" + paths.size() + " completed...");
        autoExecutor = java.util.concurrent.Executors.newFixedThreadPool(2);
        java.util.concurrent.CompletionService<myxfc.App.View.Modules.Tools.CTF.Engine.Analysis.AutoAnalysisService.FileAnalysis> completion =
                new java.util.concurrent.ExecutorCompletionService<>(autoExecutor);
        for (Path path : paths) {
            completion.submit(() -> {
                try {
                    return new myxfc.App.View.Modules.Tools.CTF.Engine.Analysis.AutoAnalysisService.FileAnalysis(
                            path, myxfc.App.View.Modules.Tools.CTF.Engine.Analysis.AutoAnalysisService.analyze(path), null);
                } catch (java.util.concurrent.CancellationException e) {
                    throw e;
                } catch (Exception e) {
                    String error = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
                    return new myxfc.App.View.Modules.Tools.CTF.Engine.Analysis.AutoAnalysisService.FileAnalysis(
                            path, List.of(), error);
                }
            });
        }
        autoWorker = new Thread(() -> processAutoReports(paths.size(), completion), "myxfc-auto-reports");
        autoWorker.setDaemon(true);
        autoWorker.start();
    }

    @FXML public void ONClickCancelAuto() {
        if (!autoRunning) {
            JTA_autoOutput.setText("No automatic analysis is running");
            return;
        }
        JTA_autoOutput.setText("Cancelling analysis...");
        autoExecutor.shutdownNow();
        autoWorker.interrupt();
    }

    private void processAutoReports(int total,
                                    java.util.concurrent.CompletionService<myxfc.App.View.Modules.Tools.CTF.Engine.Analysis.AutoAnalysisService.FileAnalysis> completion) {
        final int displayLimit = 1_000_000;
        StringBuilder display = new StringBuilder();
        Path reportPath = null;
        try {
            reportPath = Files.createTempFile("myxfc-auto-report-", ".txt");
            try (java.io.BufferedWriter writer = Files.newBufferedWriter(reportPath, StandardCharsets.UTF_8)) {
                for (int completed = 0; completed < total; completed++) {
                    var report = completion.take().get();
                    StringBuilder section = new StringBuilder("########## ").append(report.path()).append(" ##########\n");
                    if (report.error() != null) {
                        section.append("Analysis error: ").append(report.error()).append("\n\n");
                    } else {
                        section.append(myxfc.App.View.Modules.Tools.CTF.Engine.Analysis.AnalysisReportFormatter
                                .format(report.findings())).append("\n\n");
                    }
                    writer.write(section.toString());
                    int remaining = displayLimit - display.length();
                    if (remaining > 0) {
                        display.append(section, 0, Math.min(remaining, section.length()));
                    }
                    int finished = completed + 1;
                    Platform.runLater(() -> JTA_autoOutput.setText("Analyzing " + total + " file(s), "
                            + finished + "/" + total + " completed...\nLast: " + report.path()));
                }
            }
            boolean large = Files.size(reportPath) > displayLimit;
            String finalText = display.toString();
            if (large) {
                finalText += "\n\nLarge report: the complete result is saved at " + reportPath;
            } else {
                Files.deleteIfExists(reportPath);
            }
            String output = finalText;
            Platform.runLater(() -> JTA_autoOutput.setText(output));
        } catch (InterruptedException | java.util.concurrent.CancellationException e) {
            Thread.currentThread().interrupt();
            String partial = reportPath == null ? "" : "\nPartial report: " + reportPath;
            Platform.runLater(() -> JTA_autoOutput.setText("Analysis cancelled." + partial));
        } catch (Exception e) {
            Platform.runLater(() -> showError(JTA_autoOutput, e));
        } finally {
            autoExecutor.shutdownNow();
            autoRunning = false;
        }
    }

    @FXML public void ONClickIdentify() {
        JTA_decodeOutput.setText(MultiDecodeService.identify(JTA_decodeInput.getText()));
    }

    @FXML public void ONClickMultiDecode() {
        try {
            StringBuilder output = new StringBuilder();
            for (MultiDecodeService.Result result : MultiDecodeService.decode(JTA_decodeInput.getText(), JCB_decodeDepth.getValue())) {
                output.append("score=").append(String.format("%.1f", result.score())).append(' ')
                        .append(result.chain()).append("\n").append(result.output()).append("\n\n");
            }
            JTA_decodeOutput.setText(output.toString());
        } catch (Exception e) {
            showError(JTA_decodeOutput, e);
        }
    }

    @FXML public void ONClickCryptoDecode() {
        try {
            StringBuilder output = new StringBuilder();
            for (var candidate : myxfc.App.View.Modules.Tools.CTF.Engine.Decode.CryptoDecodeService.decode(
                    JTA_decodeInput.getText(), JTF_decodeKey.getText(), JTF_decodeIv.getText())) {
                output.append(candidate.algorithm()).append(" key=").append(candidate.key())
                        .append(" score=").append(String.format("%.1f", candidate.score()))
                        .append("\n").append(candidate.output()).append("\n\n");
            }
            JTA_decodeOutput.setText(output.isEmpty() ? "No readable plaintext candidate found" : output.toString());
        } catch (Exception e) {
            showError(JTA_decodeOutput, e);
        }
    }

    @FXML public void ONClickLoadZip() {
        zipFile = chooseFile("Open ZIP or binary file");
        if (zipFile != null) JTA_zipOutput.setText(zipFile + "\n" + BinwalkService.status());
    }

    @FXML public void ONClickInspectZip() {
        runZip(() -> {
            StringBuilder output = new StringBuilder();
            for (ZipAnalysisService.ZipEntryInfo entry : ZipAnalysisService.inspect(zipFile.toPath())) {
                output.append(entry.summary()).append('\n');
            }
            return output.toString();
        });
    }

    @FXML public void ONClickExtractZip() {
        if (!requireFile(zipFile, JTA_zipOutput)) return;
        Path directory = chooseDirectory();
        if (directory != null) {
            runZip(() -> ZipAnalysisService.extractAll(zipFile.toPath(), directory).toString());
        }
    }

    @FXML public void ONClickZipTrailing() {
        runZip(() -> ZipAnalysisService.trailingReport(zipFile.toPath()));
    }

    @FXML public void ONClickBinwalk() {
        if (!requireFile(zipFile, JTA_zipOutput)) return;
        Path directory = chooseDirectory();
        if (directory == null) return;
        JTA_zipOutput.setText("Running binwalk...");
        new Thread(() -> {
            BinwalkService.Result result = BinwalkService.extract(zipFile.toPath(), directory);
            Platform.runLater(() -> JTA_zipOutput.setText(result.success() + "\n" + result.output()));
        }).start();
    }

    @FXML public void ONClickLoadWav() {
        File file = chooseFile("Open WAV");
        if (file != null) {
            try {
                wavFile = file;
                wav = WavSteganography.read(file.toPath());
                wavOutput = wav.bytes();
                IV_audio.setImage(fxImage(AudioAnalysisService.waveform(wav, 0, 1000, 240)));
                JTA_audioOutput.setText(WavSteganography.metadata(wav));
            } catch (Exception e) {
                showError(JTA_audioOutput, e);
            }
        }
    }

    @FXML public void ONClickWavMetadata() {
        if (requireWav()) JTA_audioOutput.setText(WavSteganography.metadata(wav));
    }

    @FXML public void ONClickWaveform() {
        if (requireWav()) {
            try {
                IV_audio.setImage(fxImage(AudioAnalysisService.waveform(wav, audioChannel(), 1000, 240)));
            } catch (Exception e) {
                showError(JTA_audioOutput, e);
            }
        }
    }

    @FXML public void ONClickSpectrum() {
        if (requireWav()) {
            try {
                IV_audio.setImage(fxImage(AudioAnalysisService.spectrum(wav, audioChannel())));
            } catch (Exception e) {
                showError(JTA_audioOutput, e);
            }
        }
    }

    @FXML public void ONClickDtmf() {
        if (requireWav()) {
            DtmfDecodeService.AutoResult result = DtmfDecodeService.autoDetect(wav);
            StringBuilder output = new StringBuilder("Best channel: ").append(result.channel())
                    .append("\nDTMF: ").append(result.symbols()).append("\n\nCandidates:\n");
            for (DtmfDecodeService.Candidate candidate : result.candidates()) {
                output.append(candidate.encoding()).append(" (").append(String.format("%.1f", candidate.score()))
                        .append("): ").append(candidate.text()).append('\n');
            }
            output.append("\nDetails:\n");
            result.detections().forEach(value -> output.append(value).append('\n'));
            JTA_audioOutput.setText(output.toString());
        }
    }

    @FXML public void ONClickWavEmbed() {
        if (!requireWav()) return;
        try {
            wavOutput = WavSteganography.embed(wav, JTA_audioPayload.getText().getBytes(StandardCharsets.UTF_8), audioChannels());
            JTA_audioOutput.setText("Payload embedded. Save WAV to keep the result.");
        } catch (Exception e) {
            showError(JTA_audioOutput, e);
        }
    }

    @FXML public void ONClickWavExtract() {
        if (!requireWav()) return;
        try {
            audioPayload = WavSteganography.extract(WavSteganography.parse(wavOutput), audioChannels());
            JTA_audioPayload.setText(new String(audioPayload, StandardCharsets.UTF_8));
        } catch (Exception e) {
            showError(JTA_audioOutput, e);
        }
    }

    @FXML public void ONClickSaveWav() {
        if (wavOutput == null) return;
        File output = chooseSave("stego.wav");
        if (output != null) {
            try {
                Files.write(output.toPath(), wavOutput);
                JTA_audioOutput.setText("Saved: " + output);
            } catch (Exception e) {
                showError(JTA_audioOutput, e);
            }
        }
    }

    @FXML public void ONClickSaveAudioData() {
        if (audioPayload == null) return;
        File output = chooseSave("audio-payload.bin");
        if (output != null) {
            try {
                Files.write(output.toPath(), audioPayload);
            } catch (Exception e) {
                showError(JTA_audioOutput, e);
            }
        }
    }

    @FXML public void ONClickLoadPcap() {
        pcapFile = chooseFile("Open PCAP / PCAPNG");
        if (pcapFile != null) {
            try {
                capture = PcapAnalysisService.read(pcapFile.toPath());
                httpObjects = null;
                JTA_pcapOutput.setText("Packets: " + capture.packets().size() + "\nLink type: " + capture.linkType());
            } catch (Exception e) {
                showError(JTA_pcapOutput, e);
            }
        }
    }

    @FXML public void ONClickPcapStreams() {
        if (!requireCapture()) return;
        StringBuilder output = new StringBuilder();
        List<PcapAnalysisService.TcpStream> streams = PcapAnalysisService.tcpStreams(capture);
        for (PcapAnalysisService.TcpStream stream : streams) {
            output.append(stream.key()).append('\n');
            stream.directions().forEach((direction, data) -> output.append(direction).append(" bytes=")
                    .append(data.length).append("\n").append(PcapAnalysisService.printable(data)).append("\n"));
        }
        output.append("\nUDP:\n");
        PcapAnalysisService.udpSummaries(capture).forEach(value -> output.append(value).append('\n'));
        JTA_pcapOutput.setText(output.toString());
    }

    @FXML public void ONClickPcapAnomalies() {
        if (!requireCapture()) return;
        var report = myxfc.App.View.Modules.Tools.CTF.Engine.Analysis.TrafficIntelligenceService.analyze(capture);
        String output = report.summary() + "\n\n" + myxfc.App.View.Modules.Tools.CTF.Engine.Analysis
                .AnalysisReportFormatter.format(report.findings());
        JTA_pcapOutput.setText(output);
    }

    @FXML public void ONClickHttpObjects() {
        if (!requireCapture()) return;
        httpObjects = PcapAnalysisService.httpObjects(PcapAnalysisService.tcpStreams(capture));
        StringBuilder output = new StringBuilder();
        for (PcapAnalysisService.HttpObject object : httpObjects) {
            output.append(object.method()).append(' ').append(object.uri()).append(' ').append(object.status())
                    .append(' ').append(object.contentType()).append(" body=").append(object.body().length)
                    .append("\n").append(PcapAnalysisService.printable(object.body())).append("\n\n");
        }
        JTA_pcapOutput.setText(output.toString());
    }

    @FXML public void ONClickExportHttp() {
        if (httpObjects == null) ONClickHttpObjects();
        Path directory = chooseDirectory();
        if (directory == null || httpObjects == null) return;
        try {
            int index = 0;
            for (PcapAnalysisService.HttpObject object : httpObjects) {
                Files.write(directory.resolve(index++ + "." + object.extension()), object.body());
            }
            JTA_pcapOutput.setText("Exported " + httpObjects.size() + " objects to " + directory);
        } catch (Exception e) {
            showError(JTA_pcapOutput, e);
        }
    }

    @FXML public void ONClickRunAttack() {
        try {
            JTA_cryptoOutput.setText(runAttack());
        } catch (Exception e) {
            showError(JTA_cryptoOutput, e);
        }
    }

    @FXML public void ONClickLoadDocument() {
        documentFile = chooseFile("Open PDF or Office document");
        if (documentFile != null) JTA_documentOutput.setText(documentFile.toString());
    }

    @FXML public void ONClickInspectDocument() {
        if (!requireFile(documentFile, JTA_documentOutput)) return;
        try {
            var findings = myxfc.App.View.Modules.Tools.CTF.Engine.Analysis.DocumentAnomalyService
                    .analyze(documentFile.toPath());
            JTA_documentOutput.setText(myxfc.App.View.Modules.Tools.CTF.Engine.Analysis.AnalysisReportFormatter
                    .format(findings));
        } catch (Exception e) {
            showError(JTA_documentOutput, e);
        }
    }

    @FXML public void ONClickExtractDocument() {
        if (!requireFile(documentFile, JTA_documentOutput)) return;
        Path directory = chooseDirectory();
        if (directory == null) return;
        try {
            if (documentFile.getName().toLowerCase().endsWith(".pdf")) {
                PdfAnalysisService.extract(documentFile.toPath(), directory);
            } else {
                OfficeAnalysisService.extract(documentFile.toPath(), directory);
            }
            JTA_documentOutput.setText("Extracted to " + directory);
        } catch (Exception e) {
            showError(JTA_documentOutput, e);
        }
    }

    @FXML public void ONClickRepairDocument() {
        if (!requireFile(documentFile, JTA_documentOutput)) return;
        File output = chooseSave("repaired-" + documentFile.getName());
        if (output == null) return;
        try {
            myxfc.App.View.Modules.Tools.CTF.Engine.Analysis.DocumentAnomalyService.repair(
                    documentFile.toPath(), output.toPath());
            JTA_documentOutput.setText("Repaired: " + output);
        } catch (Exception e) {
            showError(JTA_documentOutput, e);
        }
    }

    @FXML public void ONClickDecryptDocument() {
        if (!requireFile(documentFile, JTA_documentOutput)) return;
        File output = chooseSave("decrypted-" + documentFile.getName());
        if (output == null) return;
        JTA_documentOutput.setText(myxfc.App.View.Modules.Tools.CTF.Engine.Analysis.DocumentAnomalyService
                .decryptEmptyPassword(documentFile.toPath(), output.toPath()));
    }

    private String runAttack() {
        String mode = JCB_attackMode.getValue();
        if (mode.startsWith("Vigenere")) {
            return attackResults(ClassicalAttackService.crackVigenere(JTA_cryptoInput.getText(), JCB_attackKeyLength.getValue()));
        }
        if (mode.equals("XOR Auto Crack")) {
            byte[] data = HexFormat.of().parseHex(JTA_cryptoInput.getText().replaceAll("\\s", ""));
            return attackResults(ClassicalAttackService.crackRepeatingXor(data, JCB_attackKeyLength.getValue()));
        }
        Map<String, String> parameters = parameters();
        if (mode.equals("XOR Known Plaintext")) {
            byte[] cipher = HexFormat.of().parseHex(parameters.get("cipher"));
            byte[] plain = HexFormat.of().parseHex(parameters.get("plain"));
            return "key=" + HexFormat.of().formatHex(ClassicalAttackService.recoverXorKey(cipher, plain));
        }
        BigInteger result;
        String details = "";
        if (mode.equals("RSA Small Exponent")) {
            result = RsaAttackService.smallExponentDecrypt(big(parameters, "c"), big(parameters, "e"));
        } else if (mode.equals("RSA Common Modulus")) {
            result = RsaAttackService.commonModulusDecrypt(big(parameters, "n"), big(parameters, "e1"),
                    big(parameters, "c1"), big(parameters, "e2"), big(parameters, "c2"));
        } else if (mode.equals("RSA Wiener")) {
            result = RsaAttackService.wienerAttack(big(parameters, "n"), big(parameters, "e"));
        } else if (mode.equals("RSA Factor from d")) {
            var factors = RsaAttackService.recoverFromPrivateExponent(big(parameters, "n"), big(parameters, "e"), big(parameters, "d"));
            return "p=" + factors.p() + "\nq=" + factors.q() + "\np(hex)=" + factors.p().toString(16) + "\nq(hex)=" + factors.q().toString(16);
        } else if (mode.equals("RSA Recover from dp")) {
            result = RsaAttackService.privateExponentFromDp(big(parameters, "n"), big(parameters, "p"),
                    big(parameters, "e"), big(parameters, "dp"));
        } else {
            result = RsaAttackService.crtDecrypt(big(parameters, "c"), big(parameters, "p"), big(parameters, "q"),
                    big(parameters, "dp"), big(parameters, "dq"));
        }
        if (result == null) return "No exact small-exponent plaintext found";
        return "Result: " + result + "\nHEX: " + result.toString(16) + "\nText: "
                + new String(result.toByteArray(), StandardCharsets.UTF_8) + details;
    }

    private String attackResults(List<ClassicalAttackService.Result> results) {
        StringBuilder output = new StringBuilder();
        for (ClassicalAttackService.Result result : results) {
            output.append("key=").append(result.key()).append(" length=").append(result.keyLength())
                    .append(" score=").append(String.format("%.1f", result.score()))
                    .append("\n").append(result.plaintext()).append("\n\n");
        }
        return output.toString();
    }

    private Map<String, String> parameters() {
        Map<String, String> result = new HashMap<>();
        for (String line : JTA_cryptoInput.getText().split("\\r?\\n")) {
            int equals = line.indexOf('=');
            if (equals > 0) result.put(line.substring(0, equals).trim(), line.substring(equals + 1).trim());
        }
        return result;
    }

    private BigInteger big(Map<String, String> parameters, String name) {
        String value = parameters.get(name);
        if (value == null) throw new IllegalArgumentException("Missing parameter: " + name);
        value = value.replaceAll("\\s", "");
        return value.startsWith("0x") ? new BigInteger(value.substring(2), 16) : new BigInteger(value);
    }

    private boolean requireWav() {
        if (wav == null) {
            JTA_audioOutput.setText("Load a WAV file first");
            return false;
        }
        return true;
    }

    private boolean requireCapture() {
        if (capture == null) {
            JTA_pcapOutput.setText("Load a capture first");
            return false;
        }
        return true;
    }

    private int audioChannel() {
        return JCB_wavChannel.getValue().equals("Channel 1") && wav.channels() > 1 ? 1 : 0;
    }

    private List<Integer> audioChannels() {
        return JCB_wavChannel.getValue().equals("Both") && wav.channels() > 1 ? List.of(0, 1) : List.of(audioChannel());
    }

    private void runZip(Callable<String> action) {
        if (!requireFile(zipFile, JTA_zipOutput)) return;
        try {
            JTA_zipOutput.setText(action.call());
        } catch (Exception e) {
            showError(JTA_zipOutput, e);
        }
    }

    private boolean requireFile(File file, JFXTextArea output) {
        if (file == null) {
            output.setText("Load a file first");
            return false;
        }
        return true;
    }

    private File chooseFile(String title) {
        FileChooser chooser = new FileChooser();
        chooser.setTitle(title);
        return chooser.showOpenDialog(ACP_controllerAnchorPane.getScene().getWindow());
    }

    private File chooseSave(String name) {
        FileChooser chooser = new FileChooser();
        chooser.setInitialFileName(name);
        return chooser.showSaveDialog(ACP_controllerAnchorPane.getScene().getWindow());
    }

    private Path chooseDirectory() {
        DirectoryChooser chooser = new DirectoryChooser();
        File directory = chooser.showDialog(ACP_controllerAnchorPane.getScene().getWindow());
        return directory == null ? null : directory.toPath();
    }

    private javafx.scene.image.Image fxImage(BufferedImage image) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        ImageIO.write(image, "png", output);
        return new javafx.scene.image.Image(new ByteArrayInputStream(output.toByteArray()));
    }

    private void showError(JFXTextArea area, Exception e) {
        area.setText(e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
    }
}
