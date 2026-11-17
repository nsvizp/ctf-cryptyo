package myxfc.App.View.Modules.Tools.Image.Steganography;

import com.jfoenix.controls.JFXCheckBox;
import com.jfoenix.controls.JFXComboBox;
import com.jfoenix.controls.JFXTextArea;
import com.jfoenix.controls.JFXTextField;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.image.ImageView;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import myxfc.App.View.Modules.Tools.Image.Steganography.Engine.DWTSteganography;
import myxfc.App.View.Modules.Tools.Image.Steganography.Engine.ExternalStegoService;
import myxfc.App.View.Modules.Tools.Image.Steganography.Engine.FrequencyAnalysisService;
import myxfc.App.View.Modules.Tools.Image.Steganography.Engine.ImageAnalysisService;
import myxfc.App.View.Modules.Tools.Image.Steganography.Engine.ImageStegoUtils;
import myxfc.App.View.Modules.Tools.Image.Steganography.Engine.ImageStructureService;
import myxfc.App.View.Modules.Tools.Image.Steganography.Engine.LSBSteganography;
import myxfc.App.View.Modules.Tools.Image.Steganography.Engine.PaletteSteganography;
import myxfc.App.View.Modules.Tools.Image.Steganography.Engine.PixelValueSteganography;
import myxfc.App.View.Viewobj.ViewController;
import myxfc.Kit.Utils.CryptoTextUtils;
import myxfc.Kit.Utils.ViewNode;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.function.Supplier;

@ViewNode(name = "Steganography", folderPath = "Root/Tools/ImageTools/", fxmlName = "SteganographyView.fxml")
public class SteganographyController extends ViewController {
    @FXML private JFXComboBox<String> JCB_stegoMode;
    @FXML private JFXComboBox<String> JCB_payloadType;
    @FXML private JFXComboBox<String> JCB_channelOrder;
    @FXML private JFXComboBox<Integer> JCB_bitPlane;
    @FXML private JFXComboBox<String> JCB_bitOrder;
    @FXML private JFXComboBox<String> JCB_scan;
    @FXML private JFXComboBox<String> JCB_imageOperation;
    @FXML private JFXComboBox<String> JCB_analysisChannel;
    @FXML private JFXComboBox<Integer> JCB_analysisPlane;
    @FXML private JFXCheckBox JCB_R;
    @FXML private JFXCheckBox JCB_G;
    @FXML private JFXCheckBox JCB_B;
    @FXML private JFXCheckBox JCB_A;
    @FXML private JFXCheckBox JCB_rawMode;
    @FXML private JFXTextField JTF_rawLength;
    @FXML private JFXTextField JTF_param1;
    @FXML private JFXTextField JTF_param2;
    @FXML private JFXTextField JTF_externalPassword;
    @FXML private JFXTextArea JTA_payload;
    @FXML private JFXTextArea JTA_output;
    @FXML private JFXTextArea JTA_analysisOutput;
    @FXML private JFXTextArea JTA_structureOutput;
    @FXML private JFXTextArea JTA_externalOutput;
    @FXML private ImageView IV_cover;
    @FXML private ImageView IV_analysis;
    @FXML private ImageView IV_analysisResult;

    private BufferedImage coverImage;
    private BufferedImage stegoImage;
    private List<File> stegoFiles = List.of();
    private BufferedImage analysisImage;
    private BufferedImage compareImage;
    private BufferedImage analysisResult;
    private File payloadFile;
    private File structureFile;
    private File externalInput;
    private File externalPayload;
    private byte[] extractedPayload;
    private byte[] structureData;

    @Override
    protected void initialize() {
        JTA_src = JTA_payload;
        JTA_dst = JTA_output;
        super.initialize();
        JCB_stegoMode.getItems().setAll("LSB", "Palette", "Pixel Value", "DWT Haar");
        JCB_stegoMode.setValue("LSB");
        JCB_payloadType.getItems().setAll("Text", "HEX", "File");
        JCB_payloadType.setValue("Text");
        JCB_channelOrder.getItems().setAll("RGB", "BGR", "RGBA", "BGRA", "ARGB", "ABGR");
        JCB_channelOrder.setValue("RGB");
        JCB_bitOrder.getItems().setAll("LSB", "MSB");
        JCB_bitOrder.setValue("LSB");
        JCB_scan.getItems().setAll("Row", "Column");
        JCB_scan.setValue("Row");
        JCB_R.setSelected(true);
        JCB_G.setSelected(true);
        JCB_B.setSelected(true);
        JCB_A.setSelected(false);
        JCB_rawMode.setSelected(false);
        JTF_rawLength.setText("256");
        for (int i = 0; i < 8; i++) {
            JCB_bitPlane.getItems().add(i);
            JCB_analysisPlane.getItems().add(i);
        }
        JCB_bitPlane.setValue(0);
        JCB_analysisPlane.setValue(0);
        JCB_analysisChannel.getItems().setAll("R", "G", "B", "A");
        JCB_analysisChannel.setValue("R");
        JCB_imageOperation.getItems().setAll("Channel", "Bit Plane", "Invert", "Brightness / Contrast",
                "Difference", "XOR", "Overlay", "Scale", "Rotate 90", "Mirror Horizontal", "Mirror Vertical",
                "Histogram", "FFT Spectrum", "8x8 DCT", "Anomaly Report");
        JCB_imageOperation.setValue("Bit Plane");
        JTF_param1.setPromptText("Brightness / width");
        JTF_param2.setPromptText("Contrast / height");
        IV_analysis.setOnMouseClicked(event -> {
            if (analysisImage != null) {
                int x = (int) Math.min(analysisImage.getWidth() - 1,
                        event.getX() * analysisImage.getWidth() / IV_analysis.getFitWidth());
                int y = (int) Math.min(analysisImage.getHeight() - 1,
                        event.getY() * analysisImage.getHeight() / IV_analysis.getFitHeight());
                JTA_analysisOutput.setText(ImageAnalysisService.pixelInfo(analysisImage, x, y));
            }
        });
    }

    @FXML
    public void ONClickLoadCover() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Load one or more images");
        chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter(
                "Images", "*.png", "*.jpg", "*.jpeg", "*.gif", "*.bmp"));
        List<File> files = chooser.showOpenMultipleDialog(ACP_controllerAnchorPane.getScene().getWindow());
        if (files != null && !files.isEmpty()) {
            try {
                stegoFiles = List.copyOf(files);
                coverImage = ImageStegoUtils.read(files.get(0));
                stegoImage = coverImage;
                IV_cover.setImage(fxImage(coverImage));
                JTA_output.setText("Loaded " + files.size() + " image(s). First: " + files.get(0)
                        + "\n" + ImageAnalysisService.anomalyReport(coverImage));
            } catch (Exception e) {
                showError(JTA_output, e);
            }
        }
    }

    @FXML
    public void ONClickSaveStegoImage() {
        saveImage(stegoImage, JTA_output);
    }

    @FXML
    public void ONClickChoosePayload() {
        File file = chooseFile("Choose payload", false);
        if (file != null) {
            payloadFile = file;
            JCB_payloadType.setValue("File");
            JTA_payload.setText(file.getAbsolutePath());
        }
    }

    @FXML
    public void ONClickEmbed() {
        try {
            requireImage(coverImage);
            byte[] payload = payload();
            stegoImage = switch (JCB_stegoMode.getValue()) {
                case "Palette" -> PaletteSteganography.embed(coverImage, payload);
                case "Pixel Value" -> PixelValueSteganography.embed(coverImage, payload, channels(), columnScan());
                case "DWT Haar" -> DWTSteganography.embed(coverImage, payload, channels());
                default -> LSBSteganography.embed(coverImage, payload, lsbSettings());
            };
            IV_cover.setImage(fxImage(stegoImage));
            JTA_output.setText("Embedded " + payload.length + " bytes. Save the result as a lossless PNG.");
        } catch (Exception e) {
            showError(JTA_output, e);
        }
    }

    @FXML
    public void ONClickExtract() {
        try {
            requireImage(stegoImage);
            extractedPayload = switch (JCB_stegoMode.getValue()) {
                case "Palette" -> PaletteSteganography.extract(stegoImage);
                case "Pixel Value" -> PixelValueSteganography.extract(stegoImage, channels(), columnScan());
                case "DWT Haar" -> DWTSteganography.extract(stegoImage, channels());
                default -> JCB_rawMode.isSelected()
                        ? LSBSteganography.extractRaw(stegoImage, Integer.parseInt(JTF_rawLength.getText().trim()), lsbSettings())
                        : LSBSteganography.extract(stegoImage, lsbSettings());
            };
            JTA_output.setText(displayPayload(extractedPayload));
        } catch (Exception e) {
            showError(JTA_output, e);
        }
    }

    @FXML
    public void ONClickAutoDetect() {
        try {
            requireImage(stegoImage);
            boolean batch = stegoFiles.size() > 1;
            List<File> files = stegoFiles;
            BufferedImage current = stegoImage;
            boolean r = JCB_R.isSelected();
            boolean g = JCB_G.isSelected();
            boolean b = JCB_B.isSelected();
            boolean a = JCB_A.isSelected();
            JTA_output.setText("Detecting LSB parameters in " + (batch ? files.size() : 1) + " image(s)...");
            new Thread(() -> {
                StringBuilder output = new StringBuilder();
                int count = batch ? files.size() : 1;
                for (int i = 0; i < count; i++) {
                    try {
                        BufferedImage source = batch ? ImageStegoUtils.read(files.get(i)) : current;
                        output.append("########## ").append(batch ? files.get(i).toString() : "Current image")
                                .append(" ##########\n");
                        List<LSBSteganography.Detection> detections = LSBSteganography.autoDetect(source, r, g, b, a);
                        if (detections.isEmpty()) {
                            output.append("No likely LSB payload detected\n\n");
                        }
                        for (LSBSteganography.Detection detection : detections) {
                            output.append(detection.settings()).append(" score=")
                                    .append(String.format("%.1f", detection.score()))
                                    .append(detection.framed() ? " framed" : " raw")
                                    .append(" bytes=").append(detection.data().length)
                                    .append("\n").append(detection.preview()).append("\n\n");
                        }
                    } catch (Exception e) {
                        output.append("Analysis error: ").append(e.getMessage() == null
                                ? e.getClass().getSimpleName() : e.getMessage()).append("\n\n");
                    }
                }
                Platform.runLater(() -> JTA_output.setText(output.toString()));
            }).start();
        } catch (Exception e) {
            showError(JTA_output, e);
        }
    }

    @FXML
    public void ONClickSavePayload() {
        if (extractedPayload == null) {
            JTA_output.setText("No extracted payload to save");
            return;
        }
        File output = chooseSave("payload.bin");
        if (output != null) {
            try {
                Files.write(output.toPath(), extractedPayload);
                JTA_output.setText("Saved: " + output);
            } catch (Exception e) {
                showError(JTA_output, e);
            }
        }
    }

    @FXML
    public void ONClickLoadAnalysis() {
        File file = chooseFile("Load image A", true);
        if (file != null) {
            try {
                analysisImage = ImageStegoUtils.read(file);
                IV_analysis.setImage(fxImage(analysisImage));
                JTA_analysisOutput.setText(ImageAnalysisService.anomalyReport(analysisImage));
            } catch (Exception e) {
                showError(JTA_analysisOutput, e);
            }
        }
    }

    @FXML
    public void ONClickLoadCompare() {
        File file = chooseFile("Load image B", true);
        if (file != null) {
            try {
                compareImage = ImageStegoUtils.read(file);
                JTA_analysisOutput.setText("Loaded comparison image: " + file);
            } catch (Exception e) {
                showError(JTA_analysisOutput, e);
            }
        }
    }

    @FXML
    public void ONClickSaveAnalysis() {
        saveImage(analysisResult, JTA_analysisOutput);
    }

    @FXML
    public void ONClickApplyAnalysis() {
        try {
            requireImage(analysisImage);
            char channel = JCB_analysisChannel.getValue().charAt(0);
            String operation = JCB_imageOperation.getValue();
            String report = "";
            analysisResult = switch (operation) {
                case "Channel" -> ImageAnalysisService.channel(analysisImage, channel);
                case "Bit Plane" -> ImageAnalysisService.bitPlane(analysisImage, channel, JCB_analysisPlane.getValue());
                case "Invert" -> ImageAnalysisService.invert(analysisImage);
                case "Brightness / Contrast" -> ImageAnalysisService.adjust(analysisImage,
                        Double.parseDouble(JTF_param1.getText().trim()), Double.parseDouble(JTF_param2.getText().trim()));
                case "Difference", "XOR", "Overlay" -> {
                    requireImage(compareImage);
                    ImageAnalysisService.CompareMode mode = switch (operation) {
                        case "Difference" -> ImageAnalysisService.CompareMode.DIFFERENCE;
                        case "XOR" -> ImageAnalysisService.CompareMode.XOR;
                        default -> ImageAnalysisService.CompareMode.OVERLAY;
                    };
                    yield ImageAnalysisService.compare(analysisImage, compareImage, mode);
                }
                case "Scale" -> ImageAnalysisService.scale(analysisImage,
                        Integer.parseInt(JTF_param1.getText().trim()), Integer.parseInt(JTF_param2.getText().trim()));
                case "Rotate 90" -> ImageAnalysisService.rotate(analysisImage, 90);
                case "Mirror Horizontal" -> ImageAnalysisService.mirror(analysisImage, ImageAnalysisService.MirrorMode.HORIZONTAL);
                case "Mirror Vertical" -> ImageAnalysisService.mirror(analysisImage, ImageAnalysisService.MirrorMode.VERTICAL);
                case "Histogram" -> ImageAnalysisService.histogramImage(analysisImage, channel);
                case "FFT Spectrum" -> FrequencyAnalysisService.frequencySpectrum(analysisImage);
                case "8x8 DCT" -> {
                    FrequencyAnalysisService.DCTResult result = FrequencyAnalysisService.dctAnalysis(analysisImage);
                    report = result.report();
                    yield result.coefficientMap();
                }
                case "Anomaly Report" -> {
                    report = ImageAnalysisService.anomalyReport(analysisImage);
                    yield null;
                }
                default -> throw new IllegalArgumentException("Unknown operation");
            };
            if (analysisResult != null) {
                IV_analysisResult.setImage(fxImage(analysisResult));
            }
            JTA_analysisOutput.setText(report);
        } catch (Exception e) {
            showError(JTA_analysisOutput, e);
        }
    }

    @FXML
    public void ONClickLoadStructure() {
        File file = chooseFile("Load file", false);
        if (file != null) {
            structureFile = file;
            JTA_structureOutput.setText("Loaded: " + file + " (" + file.length() + " bytes)");
        }
    }

    @FXML
    public void ONClickMetadata() {
        runStructure(() -> ImageStructureService.metadata(structureFile.toPath()));
    }

    @FXML
    public void ONClickPngChunks() {
        runStructure(() -> {
            StringBuilder output = new StringBuilder();
            for (ImageStructureService.PNGChunk chunk : ImageStructureService.parsePng(Files.readAllBytes(structureFile.toPath()))) {
                output.append(chunk).append('\n');
            }
            return output.toString();
        });
    }

    @FXML
    public void ONClickTrailing() {
        runStructure(() -> {
            ImageStructureService.TrailingData trailing = ImageStructureService.trailingData(
                    Files.readAllBytes(structureFile.toPath()));
            structureData = trailing.data();
            return "Real file end: " + trailing.endOffset() + "\nTrailing bytes: " + trailing.data().length
                    + "\n" + previewBytes(trailing.data());
        });
    }

    @FXML
    public void ONClickCarve() {
        if (structureFile == null) {
            JTA_structureOutput.setText("Load a file first");
            return;
        }
        DirectoryChooser chooser = new DirectoryChooser();
        chooser.setTitle("Choose carving output directory");
        File directory = chooser.showDialog(ACP_controllerAnchorPane.getScene().getWindow());
        if (directory == null) {
            return;
        }
        runStructure(() -> {
            List<ImageStructureService.CarvedFile> files = ImageStructureService.carve(Files.readAllBytes(structureFile.toPath()));
            StringBuilder output = new StringBuilder();
            int index = 0;
            for (ImageStructureService.CarvedFile carved : files) {
                File carvedOutput = new File(directory, "carved_" + index++ + "_" + carved.offset() + "." + carved.extension());
                Files.write(carvedOutput.toPath(), carved.data());
                output.append(carvedOutput).append(" (").append(carved.data().length).append(" bytes)\n");
            }
            return files.isEmpty() ? "No complete embedded files found" : output.toString();
        });
    }

    @FXML
    public void ONClickSaveStructureData() {
        if (structureData == null || structureData.length == 0) {
            JTA_structureOutput.setText("No trailing data to save");
            return;
        }
        File output = chooseSave("trailing.bin");
        if (output != null) {
            try {
                Files.write(output.toPath(), structureData);
                JTA_structureOutput.setText("Saved: " + output);
            } catch (Exception e) {
                showError(JTA_structureOutput, e);
            }
        }
    }

    @FXML
    public void ONClickExternalInput() {
        externalInput = chooseFile("External tool input", false);
        if (externalInput != null) {
            JTA_externalOutput.setText("Input: " + externalInput);
        }
    }

    @FXML
    public void ONClickExternalPayload() {
        externalPayload = chooseFile("External tool payload", false);
        if (externalPayload != null) {
            JTA_externalOutput.setText("Payload: " + externalPayload);
        }
    }

    @FXML
    public void ONClickExternalStatus() {
        runExternal(() -> new ExternalStegoService.Result(true,
                ExternalStegoService.toolStatus("steghide") + "\n" + ExternalStegoService.toolStatus("outguess")));
    }

    @FXML
    public void ONClickSteghideEmbed() {
        externalOperation(true, true);
    }

    @FXML
    public void ONClickSteghideExtract() {
        externalOperation(true, false);
    }

    @FXML
    public void ONClickOutguessEmbed() {
        externalOperation(false, true);
    }

    @FXML
    public void ONClickOutguessExtract() {
        externalOperation(false, false);
    }

    private void externalOperation(boolean steghide, boolean embed) {
        if (externalInput == null || embed && externalPayload == null) {
            JTA_externalOutput.setText("Choose input and payload files first");
            return;
        }
        File output = chooseSave("stego-output" + (embed ? ".jpg" : ".bin"));
        if (output == null) {
            return;
        }
        String password = JTF_externalPassword.getText();
        runExternal(() -> {
            if (steghide) {
                return embed ? ExternalStegoService.steghideEmbed(externalInput.toPath(), externalPayload.toPath(),
                        output.toPath(), password)
                        : ExternalStegoService.steghideExtract(externalInput.toPath(), output.toPath(), password);
            }
            return embed ? ExternalStegoService.outguessEmbed(externalInput.toPath(), externalPayload.toPath(),
                    output.toPath(), password)
                    : ExternalStegoService.outguessExtract(externalInput.toPath(), output.toPath(), password);
        });
    }

    private LSBSteganography.Settings lsbSettings() {
        return new LSBSteganography.Settings(channels(), JCB_bitPlane.getValue(),
                JCB_bitOrder.getValue().equals("MSB"), columnScan(), JCB_channelOrder.getValue());
    }

    private List<Character> channels() {
        return ImageStegoUtils.channels(JCB_channelOrder.getValue(), JCB_R.isSelected(),
                JCB_G.isSelected(), JCB_B.isSelected(), JCB_A.isSelected());
    }

    private boolean columnScan() {
        return JCB_scan.getValue().equals("Column");
    }

    private byte[] payload() throws Exception {
        return switch (JCB_payloadType.getValue()) {
            case "HEX" -> CryptoTextUtils.parse(JTA_payload.getText(), "HEX", "UTF-8");
            case "File" -> {
                if (payloadFile == null) {
                    throw new IllegalArgumentException("Choose a payload file");
                }
                yield Files.readAllBytes(payloadFile.toPath());
            }
            default -> JTA_payload.getText().getBytes(StandardCharsets.UTF_8);
        };
    }

    private String displayPayload(byte[] payload) {
        return switch (JCB_payloadType.getValue()) {
            case "HEX" -> HexFormat.of().formatHex(payload);
            case "File" -> payload.length + " bytes\n" + previewBytes(payload);
            default -> new String(payload, StandardCharsets.UTF_8);
        };
    }

    private void runStructure(Callable<String> action) {
        if (structureFile == null) {
            JTA_structureOutput.setText("Load a file first");
            return;
        }
        try {
            JTA_structureOutput.setText(action.call());
        } catch (Exception e) {
            showError(JTA_structureOutput, e);
        }
    }

    private void runExternal(Supplier<ExternalStegoService.Result> action) {
        JTA_externalOutput.setText("Running...");
        new Thread(() -> {
            try {
                ExternalStegoService.Result result = action.get();
                Platform.runLater(() -> JTA_externalOutput.setText(result.success() + "\n" + result.output()));
            } catch (Exception e) {
                Platform.runLater(() -> showError(JTA_externalOutput, e));
            }
        }).start();
    }

    private void saveImage(BufferedImage image, JFXTextArea outputArea) {
        if (image == null) {
            outputArea.setText("No image to save");
            return;
        }
        File output = chooseSave("myxfc-image.png");
        if (output != null) {
            try {
                ImageStegoUtils.writePng(image, output);
                outputArea.setText("Saved: " + output);
            } catch (Exception e) {
                showError(outputArea, e);
            }
        }
    }

    private File chooseFile(String title, boolean imagesOnly) {
        FileChooser chooser = new FileChooser();
        chooser.setTitle(title);
        if (imagesOnly) {
            chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter(
                    "Images", "*.png", "*.jpg", "*.jpeg", "*.gif", "*.bmp"));
        }
        return chooser.showOpenDialog(ACP_controllerAnchorPane.getScene().getWindow());
    }

    private File chooseSave(String name) {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Save output");
        chooser.setInitialFileName(name);
        return chooser.showSaveDialog(ACP_controllerAnchorPane.getScene().getWindow());
    }

    private javafx.scene.image.Image fxImage(BufferedImage image) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        ImageIO.write(image, "png", output);
        return new javafx.scene.image.Image(new ByteArrayInputStream(output.toByteArray()));
    }

    private String previewBytes(byte[] data) {
        String hex = HexFormat.of().formatHex(data);
        String text = new String(data, StandardCharsets.ISO_8859_1).replaceAll("[^\\x20-\\x7E\\r\\n\\t]", ".");
        return "HEX:\n" + hex + "\nText:\n" + text;
    }

    private void requireImage(BufferedImage image) {
        if (image == null) {
            throw new IllegalArgumentException("Load an image first");
        }
    }

    private void showError(JFXTextArea area, Exception e) {
        area.setText(e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
    }
}
