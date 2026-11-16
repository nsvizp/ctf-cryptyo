package myxfc.App.View.Modules.Encryption.Classical.Playfair;

import com.jfoenix.controls.JFXTextField;
import myxfc.App.View.Viewobj.ViewController;
import myxfc.Kit.Utils.ViewNode;
import myxfc.Kit.Utils.ViewUtils;
import javafx.fxml.FXML;

@ViewNode(name = "Playfair", folderPath = "Root/Encryption/Classical/", fxmlName = "PlayfairView.fxml")
public class PlayfairController extends ViewController {
    @FXML private JFXTextField JTF_key;

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
            JTA_dst.setText(encrypt ? PlayfairImpl.encrypt(JTA_src.getText(), JTF_key.getText())
                    : PlayfairImpl.decrypt(JTA_src.getText(), JTF_key.getText()));
        } catch (Exception e) {
            ViewUtils.setTextAreaTextRed(true, JTA_dst);
            JTA_dst.setText(e.getMessage());
        }
    }
}
