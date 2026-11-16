package myxfc.App.View.Modules.Encryption.Coding.ASCII;

import myxfc.Kit.Utils.ViewNode;
import myxfc.Kit.Utils.ViewUtils;
import myxfc.App.View.Viewobj.ViewController;
import com.jfoenix.controls.*;
import javafx.fxml.FXML;

/**
 * @author myxfc
 */
@ViewNode(name = "ASCII",folderPath = "Root/Encryption/Coding/",fxmlName = "ASCIIView.fxml")
public class ASCIIViewController extends ViewController {
    @FXML
    private JFXTextField JTF_split;

    @Override
    protected void initialize() {
        super.initialize();
    }

    @Override
    public void ONClickEncode(){
        super.ONClickEncode();
        try {
            JTA_dst.setText(ASCIIEnCode());
        }catch (Exception e){
            ViewUtils.textAreaValidate(JTA_dst);
        }

    }

    @Override
    public void ONClickDecode(){
        super.ONClickDecode();
        try{
            JTA_dst.setText(ASCIIDeCode());
        }catch (Exception e){
            ViewUtils.textAreaValidate(JTA_dst);
        }
    }


    private String ASCIIEnCode(){
        return ASCIIImpl.encode(
                JTA_src.getText(),
                ViewUtils.getSplit(JTF_split),0);
    }

    private String ASCIIDeCode(){
        return ASCIIImpl.deCode(
                JTA_src.getText(),
                ViewUtils.getSplit(JTF_split));
    }
}
