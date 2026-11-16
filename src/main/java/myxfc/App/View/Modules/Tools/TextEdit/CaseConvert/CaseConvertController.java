package myxfc.App.View.Modules.Tools.TextEdit.CaseConvert;

import myxfc.Kit.Utils.ViewNode;
import myxfc.Kit.Utils.ViewUtils;
import myxfc.App.View.Viewobj.ViewController;

@ViewNode(name = "CaseConvert",folderPath = "Root/Tools/TextModify/",fxmlName = "CaseConvertView.fxml")
public class CaseConvertController extends ViewController {
    @Override
    protected void initialize() {
        super.initialize();
    }

    @Override
    public void ONClickEncode() {
        super.ONClickEncode();
        try {
            JTA_dst.setText(CaseConvertImpl.Uppercase(JTA_src.getText()));
        }catch (Exception e){
            ViewUtils.textAreaValidate(JTA_dst);
        }
    }

    @Override
    public void ONClickDecode() {
        super.ONClickDecode();
        try {
            JTA_dst.setText(CaseConvertImpl.Lowercase(JTA_src.getText()));
        }catch (Exception e){
            ViewUtils.textAreaValidate(JTA_dst);
        }
    }
}
