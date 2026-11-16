package myxfc.App.View.Modules.Encryption.Classical.Affine;

import com.jfoenix.controls.JFXTextField;
import myxfc.App.View.Viewobj.ViewController;
import myxfc.Kit.Utils.ViewNode;
import myxfc.Kit.Utils.ViewUtils;
import javafx.fxml.FXML;

@ViewNode(name = "Affine", folderPath = "Root/Encryption/Classical/", fxmlName = "AffineView.fxml")
public class AffineController extends ViewController {
    @FXML private JFXTextField JTF_a;
    @FXML private JFXTextField JTF_b;

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
            int a = Integer.parseInt(JTF_a.getText().trim());
            int b = Integer.parseInt(JTF_b.getText().trim());
            JTA_dst.setText(encrypt ? AffineImpl.encrypt(JTA_src.getText(), a, b)
                    : AffineImpl.decrypt(JTA_src.getText(), a, b));
        } catch (Exception e) {
            ViewUtils.setTextAreaTextRed(true, JTA_dst);
            JTA_dst.setText(e.getMessage());
        }
    }
}
