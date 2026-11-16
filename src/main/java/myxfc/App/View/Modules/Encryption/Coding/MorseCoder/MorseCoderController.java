package myxfc.App.View.Modules.Encryption.Coding.MorseCoder;

import myxfc.Kit.Utils.ViewNode;
import myxfc.Kit.Utils.ViewUtils;
import myxfc.App.View.Viewobj.ViewController;
import com.jfoenix.controls.JFXTextField;
import javafx.fxml.FXML;

@ViewNode(name = "MorseCoder",folderPath = "Root/Encryption/Coding/",fxmlName = "MorseCoderView.fxml")
public class MorseCoderController extends ViewController {

    @FXML private JFXTextField JTF_split;

    @Override
    protected void initialize() {
        super.initialize();
    }

    @Override
    public void ONClickEncode() {
        super.ONClickEncode();
        try {
            if(JTF_split.getText().equals("")){
                JTA_dst.setText(MorseCoderImpl.encode(JTA_src.getText()," "));
            }else{
                JTA_dst.setText(MorseCoderImpl.encode(JTA_src.getText(),JTF_split.getText()));
            }
        }catch (Exception e){
            ViewUtils.textAreaValidate(JTA_dst);
        }
    }

    @Override
    public void ONClickDecode() {
        super.ONClickDecode();
        try {
            if(JTF_split.getText().equals("")){
                JTA_dst.setText(MorseCoderImpl.decode(JTA_src.getText()," "));
            }else{
                JTA_dst.setText(MorseCoderImpl.decode(JTA_src.getText(),JTF_split.getText()));
            }
        }catch (Exception e){
            ViewUtils.textAreaValidate(JTA_dst);
        }
    }
}
