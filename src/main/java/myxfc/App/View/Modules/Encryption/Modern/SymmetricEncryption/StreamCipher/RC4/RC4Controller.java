package myxfc.App.View.Modules.Encryption.Modern.SymmetricEncryption.StreamCipher.RC4;

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

@ViewNode(name = "RC4", folderPath = "Root/Encryption/Modern/SymmetricEncryption/StreamCipher/", fxmlName = "RC4View.fxml")
public class RC4Controller extends ViewControllerFileMode {
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
        JCB_outputFormat.setValue("Base64");
        popup.setSetting(new PopupSettingNode(Init.getLanguage("InputFormat"), JCB_inputFormat, true));
        popup.setSetting(new PopupSettingNode(Init.getLanguage("KeyFormat"), JCB_keyFormat));
        popup.setSetting(new PopupSettingNode(Init.getLanguage("OutputFormat"), JCB_outputFormat));
    }

    @Override
    public void ONClickEncode() {
        super.ONClickEncode();
        crypt();
    }

    @Override
    public void ONClickDecode() {
        super.ONClickDecode();
        crypt();
    }

    private void crypt() {
        try {
            String charset = JCB_charset.getValue().toString();
            byte[] input = JTB_modeSelect.isSelected() ? byteFile
                    : CryptoTextUtils.parse(JTA_src.getText(), JCB_inputFormat.getValue(), charset);
            byte[] key = CryptoTextUtils.parse(JTF_key.getText(), JCB_keyFormat.getValue(), charset);
            byte[] output = RC4Impl.crypt(input, key);
            if (JTB_modeSelect.isSelected()) {
                FileUtils.outPutFile(output);
                fileEncodeEnd();
            } else {
                JTA_dst.setText(CryptoTextUtils.format(output, JCB_outputFormat.getValue(), charset));
            }
        } catch (Exception e) {
            ViewUtils.setTextAreaTextRed(true, JTA_dst);
            JTA_dst.setText(e.getMessage());
        }
    }
}
