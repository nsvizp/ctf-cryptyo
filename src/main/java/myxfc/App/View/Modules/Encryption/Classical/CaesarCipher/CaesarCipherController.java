package myxfc.App.View.Modules.Encryption.Classical.CaesarCipher;

import com.jfoenix.controls.JFXTextField;
import myxfc.App.View.Viewobj.ViewController;
import myxfc.Kit.Utils.ViewNode;
import myxfc.Kit.Utils.ViewUtils;
import javafx.fxml.FXML;

/**
 * @author: myxfc
 * @create: 2021-05-24 14:47
 **/

@ViewNode(name = "CaesarCipher",folderPath = "Root/Encryption/Classical/",fxmlName = "CaesarCipherView.fxml")
public class CaesarCipherController extends ViewController {
    @FXML private JFXTextField JTA_key;

    /**
     * 全局界面初始化
     */
    @Override
    protected void initialize() {
        super.initialize();
    }

    /**
     * 全局加密按钮事件
     */
    @Override
    public void ONClickEncode() {
        super.ONClickEncode();
        try{
            JTA_dst.setText(CaesarCipherImpl.encode(JTA_src.getText(), Integer.parseInt(JTA_key.getText())));
        }catch (Exception e){
            ViewUtils.textAreaValidate(JTA_dst);
        }
    }

    /**
     * 全局解密按钮事件
     */
    @Override
    public void ONClickDecode() {
        super.ONClickDecode();
        try{
            JTA_dst.setText(CaesarCipherImpl.decode(JTA_src.getText(),getKey(JTA_key)));
        }catch (Exception e){
            ViewUtils.textAreaValidate(JTA_dst);
        }
    }

    private int getKey(JFXTextField JTA_key){
        if (JTA_key.getText().equals("")){
            return 0;
        }else{
            return Integer.parseInt(JTA_key.getText());
        }
    }
}
