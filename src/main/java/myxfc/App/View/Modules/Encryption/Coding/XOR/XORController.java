package myxfc.App.View.Modules.Encryption.Coding.XOR;

import com.jfoenix.controls.JFXComboBox;
import com.jfoenix.controls.JFXTextField;
import myxfc.App.View.Viewobj.PopupSettingNode;
import myxfc.App.View.Viewobj.PopupSettingView;
import myxfc.App.View.Viewobj.ViewControllerFileMode;
import myxfc.Init.Init;
import myxfc.Init.ViewInit;
import myxfc.Kit.Utils.CryptoTextUtils;
import myxfc.Kit.Utils.FileUtils;
import myxfc.Kit.Utils.ViewNode;
import myxfc.Kit.Utils.ViewUtils;
import javafx.fxml.FXML;

import java.util.List;

@ViewNode(name = "XOR", folderPath = "Root/Encryption/Coding/", fxmlName = "XORView.fxml")
public class XORController extends ViewControllerFileMode {
    @FXML private JFXTextField JTF_key;
    @FXML private JFXComboBox JCB_charset;
    private JFXComboBox<String> JCB_inputFormat = new JFXComboBox<>();
    private JFXComboBox<String> JCB_keyFormat = new JFXComboBox<>();
    private JFXComboBox<String> JCB_outputFormat = new JFXComboBox<>();

    @Override
    protected void initialize() {
        super.initialize();
        ViewInit.comboBoxCharset(JCB_charset);
        setFileSelectButton();
    }

    @Override
    protected void LoadPopupSettingNode() {
        PopupSettingView popup = new PopupSettingView(ACP_controllerAnchorPane);
        for (JFXComboBox<String> combo : new JFXComboBox[]{JCB_inputFormat, JCB_keyFormat, JCB_outputFormat}) {
            combo.getItems().setAll("Text", "HEX", "Base64");
        }
        JCB_inputFormat.setValue("Text");
        JCB_keyFormat.setValue("Text");
        JCB_outputFormat.setValue("Text");
        popup.setSetting(new PopupSettingNode(Init.getLanguage("InputFormat"), JCB_inputFormat, true));
        popup.setSetting(new PopupSettingNode(Init.getLanguage("KeyFormat"), JCB_keyFormat));
        popup.setSetting(new PopupSettingNode(Init.getLanguage("OutputFormat"), JCB_outputFormat));
    }

    @Override
    public void ONClickConfirm() {
        super.ONClickConfirm();
        try {
            String charset = JCB_charset.getValue().toString();
            byte[] input = input();
            byte[] key = CryptoTextUtils.parse(JTF_key.getText(), JCB_keyFormat.getValue(), charset);
            byte[] output = XORImpl.encrypt(input, key);
            if (JTB_modeSelect.isSelected()) {
                FileUtils.outPutFile(output);
                fileEncodeEnd();
            } else {
                JTA_dst.setText(CryptoTextUtils.format(output, JCB_outputFormat.getValue(), charset));
            }
        } catch (Exception e) {
            showError(e);
        }
    }

    @FXML
    public void ONClickBruteForce() {
        super.ONClickConfirm();
        try {
            String charset = JCB_charset.getValue().toString();
            List<XORImpl.BruteForceResult> results = XORImpl.bruteForceSingleByte(input());
            StringBuilder output = new StringBuilder();
            for (XORImpl.BruteForceResult result : results) {
                String plaintext = CryptoTextUtils.format(result.plaintext(), JCB_outputFormat.getValue(), charset)
                        .replace("\r", "\\r").replace("\n", "\\n");
                output.append(String.format("key=0x%02X (%3d) score=%.3f  %s%n",
                        result.key(), result.key(), result.score(), plaintext));
            }
            JTA_dst.setText(output.toString());
        } catch (Exception e) {
            showError(e);
        }
    }

    private byte[] input() throws Exception {
        return JTB_modeSelect.isSelected() ? byteFile
                : CryptoTextUtils.parse(JTA_src.getText(), JCB_inputFormat.getValue(), JCB_charset.getValue().toString());
    }

    private void showError(Exception e) {
        ViewUtils.setTextAreaTextRed(true, JTA_dst);
        JTA_dst.setText(e.getMessage());
    }
}
