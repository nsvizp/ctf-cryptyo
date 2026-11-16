package myxfc.App.View.Modules.Encryption.Coding.URL;

import com.jfoenix.controls.JFXCheckBox;
import myxfc.Kit.Utils.ViewNode;
import myxfc.Kit.Utils.ViewUtils;
import myxfc.Init.ViewInit;
import myxfc.App.View.Viewobj.ViewController;
import com.jfoenix.controls.JFXComboBox;
import javafx.fxml.FXML;
import org.apache.commons.codec.DecoderException;

import java.io.UnsupportedEncodingException;

/**
 * @author myxfc
 */
@ViewNode(name = "URL",folderPath = "Root/Encryption/Coding/",fxmlName = "URLView.fxml")
public class URLController extends ViewController {
    @FXML
    private JFXComboBox JCB_charset;
    @FXML
    private JFXCheckBox JCB_encodeAll;

    @Override
    protected void initialize(){
        super.initialize();
        ViewInit.comboBoxCharset(JCB_charset);
        ViewInit.textAreaErrorInfoGeneral(JTA_dst);
    }

    @Override
    public void ONClickEncode() {
        super.ONClickEncode();
        try {
            if (JCB_encodeAll.isSelected()) {
                JTA_dst.setText(URLImpl.encodeAll(JTA_src.getText(),JCB_charset.getValue().toString()));
            }else {
                JTA_dst.setText(URLImpl.encode(JTA_src.getText(),JCB_charset.getValue().toString()));
            }
        } catch (UnsupportedEncodingException e) {
//            e.printStackTrace();
            ViewUtils.textAreaValidate(JTA_dst);
        }
    }

    @Override
    public void ONClickDecode() {
        super.ONClickDecode();
        try {
            JTA_dst.setText(URLImpl.decode(JTA_src.getText(),JCB_charset.getValue().toString()));
        } catch (UnsupportedEncodingException e) {
//            e.printStackTrace();
            ViewUtils.textAreaValidate(JTA_dst);
        } catch (DecoderException e) {
            e.printStackTrace();
        }
    }
}
