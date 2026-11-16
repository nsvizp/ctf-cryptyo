package myxfc.App.View.Modules.Encryption.Classical.Bacon;

import com.jfoenix.controls.JFXComboBox;
import myxfc.App.View.Viewobj.ViewController;
import myxfc.Kit.Utils.ViewNode;
import myxfc.Kit.Utils.ViewUtils;
import javafx.fxml.FXML;

@ViewNode(name = "Bacon", folderPath = "Root/Encryption/Classical/", fxmlName = "BaconView.fxml")
public class BaconController extends ViewController {
    @FXML private JFXComboBox<String> JCB_alphabet;

    @Override
    protected void initialize() {
        super.initialize();
        JCB_alphabet.getItems().setAll("24 letters (I/J, U/V)", "26 letters");
        JCB_alphabet.setValue("26 letters");
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

    private void transform(boolean encrypt) {
        try {
            boolean use26Letters = JCB_alphabet.getValue().startsWith("26");
            JTA_dst.setText(encrypt ? BaconImpl.encrypt(JTA_src.getText(), use26Letters)
                    : BaconImpl.decrypt(JTA_src.getText(), use26Letters));
        } catch (Exception e) {
            ViewUtils.setTextAreaTextRed(true, JTA_dst);
            JTA_dst.setText(e.getMessage());
        }
    }
}
