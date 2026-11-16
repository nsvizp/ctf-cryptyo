package myxfc.App.View.Modules.Encryption.Modern.AsymmetricEncryption.RSA;

import com.jfoenix.controls.JFXComboBox;
import com.jfoenix.controls.JFXTextField;
import myxfc.App.View.Viewobj.ViewController;
import myxfc.Init.ViewInit;
import myxfc.Kit.Utils.CryptoTextUtils;
import myxfc.Kit.Utils.ViewNode;
import myxfc.Kit.Utils.ViewUtils;
import javafx.fxml.FXML;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@ViewNode(name = "RSA", folderPath = "Root/Encryption/Modern/AsymmetricEncryption/", fxmlName = "RSAView.fxml")
public class RSAController extends ViewController {
    @FXML private JFXTextField JTF_n;
    @FXML private JFXTextField JTF_e;
    @FXML private JFXTextField JTF_d;
    @FXML private JFXComboBox<String> JCB_keyMode;
    @FXML private JFXComboBox<String> JCB_parameterRadix;
    @FXML private JFXComboBox<String> JCB_padding;
    @FXML private JFXComboBox<String> JCB_keySize;
    @FXML private JFXComboBox<String> JCB_inputFormat;
    @FXML private JFXComboBox<String> JCB_outputFormat;
    @FXML private JFXComboBox JCB_charset;

    @Override
    protected void initialize() {
        super.initialize();
        JCB_keyMode.getItems().setAll("PEM", "Parameters");
        JCB_keyMode.setValue("PEM");
        JCB_parameterRadix.getItems().setAll("HEX", "Decimal");
        JCB_parameterRadix.setValue("HEX");
        JCB_padding.getItems().setAll("PKCS1Padding", "OAEP-SHA1", "OAEP-SHA256", "NoPadding");
        JCB_padding.setValue("PKCS1Padding");
        JCB_keySize.getItems().setAll("1024", "2048", "3072");
        JCB_keySize.setValue("2048");
        JCB_inputFormat.getItems().setAll("Text", "HEX", "Base64");
        JCB_outputFormat.getItems().setAll("Text", "HEX", "Base64");
        JCB_inputFormat.setValue("Text");
        JCB_outputFormat.setValue("Base64");
        ViewInit.comboBoxCharset(JCB_charset);
    }

    @FXML
    public void ONClickGenerate() {
        try {
            KeyPair pair = RSAImpl.generateKeyPair(Integer.parseInt(JCB_keySize.getValue()));
            JTA_src1.setText(RSAImpl.encodePublicKey(pair.getPublic()));
            JTA_src2.setText(RSAImpl.encodePrivateKey(pair.getPrivate()));
            RSAPublicKey publicKey = (RSAPublicKey) pair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) pair.getPrivate();
            JTF_n.setText(publicKey.getModulus().toString(16));
            JTF_e.setText(publicKey.getPublicExponent().toString(16));
            JTF_d.setText(privateKey.getPrivateExponent().toString(16));
        } catch (Exception e) {
            showError(e);
        }
    }

    @Override
    public void ONClickEncode() {
        super.ONClickEncode();
        try {
            JCB_outputFormat.setValue("Base64");
            PublicKey key = publicKey();
            byte[] input = input();
            byte[] output = RSAImpl.encrypt(input, key, JCB_padding.getValue());
            JTA_dst.setText(CryptoTextUtils.format(output, JCB_outputFormat.getValue(), JCB_charset.getValue().toString()));
        } catch (Exception e) {
            showError(e);
        }
    }

    @Override
    public void ONClickDecode() {
        super.ONClickDecode();
        try {
            JCB_outputFormat.setValue("Text");
            PrivateKey key = privateKey();
            byte[] input = input();
            byte[] output = RSAImpl.decrypt(input, key, JCB_padding.getValue());
            JTA_dst.setText(CryptoTextUtils.format(output, JCB_outputFormat.getValue(), JCB_charset.getValue().toString()));
        } catch (Exception e) {
            showError(e);
        }
    }

    private byte[] input() throws Exception {
        return CryptoTextUtils.parse(JTA_src.getText(), JCB_inputFormat.getValue(), JCB_charset.getValue().toString());
    }

    private PublicKey publicKey() throws Exception {
        if ("PEM".equals(JCB_keyMode.getValue())) {
            return RSAImpl.parsePublicKey(JTA_src1.getText());
        }
        return RSAImpl.publicKeyFromParameters(JTF_n.getText(), JTF_e.getText(), parameterRadix());
    }

    private PrivateKey privateKey() throws Exception {
        if ("PEM".equals(JCB_keyMode.getValue())) {
            return RSAImpl.parsePrivateKey(JTA_src2.getText());
        }
        return RSAImpl.privateKeyFromParameters(JTF_n.getText(), JTF_d.getText(), parameterRadix());
    }

    private int parameterRadix() {
        return "HEX".equals(JCB_parameterRadix.getValue()) ? 16 : 10;
    }

    private void showError(Exception e) {
        ViewUtils.setTextAreaTextRed(true, JTA_dst);
        JTA_dst.setText(e.getMessage());
    }
}
