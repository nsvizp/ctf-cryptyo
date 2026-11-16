package myxfc.App.View.Modules.Encryption.Classical.Atbash;


import myxfc.Kit.Utils.ViewNode;
import myxfc.Kit.Utils.ViewUtils;
import myxfc.App.View.Viewobj.ViewController;

@ViewNode(name = "Atbash",folderPath = "Root/Encryption/Classical/",fxmlName = "AtbashView.fxml")
public class AtbashController extends ViewController {

    @Override
    protected void initialize() {
        super.initialize();
    }

    @Override
    public void ONReleasedOrSelected() {
        super.ONReleasedOrSelected();
        try {
            JTA_dst.setText(AtbashImpl.encode(JTA_src.getText()));
        }catch (Exception e){
            ViewUtils.textAreaValidate(JTA_dst);
        }
    }
}
