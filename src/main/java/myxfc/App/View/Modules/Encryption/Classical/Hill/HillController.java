package myxfc.App.View.Modules.Encryption.Classical.Hill;

import com.jfoenix.controls.JFXTextField;
import myxfc.App.View.Viewobj.ViewController;
import myxfc.Kit.Utils.ViewNode;
import myxfc.Kit.Utils.ViewUtils;
import javafx.fxml.FXML;

@ViewNode(name = "Hill", folderPath = "Root/Encryption/Classical/", fxmlName = "HillView.fxml")
public class HillController extends ViewController {
    @FXML private JFXTextField JTF_matrix;

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
            int[][] matrix = HillImpl.parseMatrix(JTF_matrix.getText());
            JTA_dst.setText(encrypt ? HillImpl.encrypt(JTA_src.getText(), matrix)
                    : HillImpl.decrypt(JTA_src.getText(), matrix));
        } catch (Exception e) {
            ViewUtils.setTextAreaTextRed(true, JTA_dst);
            JTA_dst.setText(e.getMessage());
        }
    }
}
