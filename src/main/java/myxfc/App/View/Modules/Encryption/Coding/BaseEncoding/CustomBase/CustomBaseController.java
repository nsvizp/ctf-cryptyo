package myxfc.App.View.Modules.Encryption.Coding.BaseEncoding.CustomBase;

import com.jfoenix.controls.JFXCheckBox;
import com.jfoenix.controls.JFXComboBox;
import com.jfoenix.controls.JFXTextField;
import myxfc.App.View.Viewobj.ViewController;
import myxfc.Init.Init;
import myxfc.Kit.Utils.CryptoTextUtils;
import myxfc.Kit.Utils.ViewNode;
import myxfc.Kit.Utils.ViewUtils;
import javafx.fxml.FXML;

import java.nio.charset.StandardCharsets;

@ViewNode(name = "CustomBase", folderPath = "Root/Encryption/Coding/BaseEncoding/", fxmlName = "CustomBaseView.fxml")
public class CustomBaseController extends ViewController {
    private static final String BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    private static final String BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final String BASE16 = "0123456789ABCDEF";

    @FXML private JFXComboBox<String> JCB_base;
    @FXML private JFXTextField JTF_alphabet;
    @FXML private JFXCheckBox JCB_padding;

    @Override
    protected void initialize() {
        super.initialize();
        JCB_base.getItems().setAll("Base64", "Base32", "Base16");
        JCB_base.setValue("Base64");
        JTF_alphabet.setText(BASE64);
        JCB_base.setOnAction(event -> JTF_alphabet.setText(defaultAlphabet()));
    }

    @Override
    public void ONClickEncode() {
        super.ONClickEncode();
        transform(true);
    }

    @Override
    public void ONClickDecode() {
        super.ONClickDecode();
        transform(false);
    }

    private String defaultAlphabet() {
        return switch (JCB_base.getValue()) {
            case "Base32" -> BASE32;
            case "Base16" -> BASE16;
            default -> BASE64;
        };
    }

    private void transform(boolean encode) {
        try {
            String alphabet = JTF_alphabet.getText();
            boolean padding = JCB_padding.isSelected();
            if (encode) {
                byte[] input = JTA_src.getText().getBytes(StandardCharsets.UTF_8);
                JTA_dst.setText(CustomBaseImpl.encode(input, alphabet, '=', padding));
            } else {
                byte[] output = CustomBaseImpl.decode(JTA_src.getText(), alphabet, '=', padding);
                JTA_dst.setText(CryptoTextUtils.format(output, "Text", StandardCharsets.UTF_8.name()));
            }
        } catch (Exception e) {
            ViewUtils.setTextAreaTextRed(true, JTA_dst);
            String message = e.getMessage() == null ? Init.getLanguage("ErrorMessage") : e.getMessage();
            JTA_dst.setText(message);
        }
    }
}
