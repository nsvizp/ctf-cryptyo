package myxfc.App.View.Modules.Encryption.Coding.BaseEncoding.Base92;

import myxfc.App.View.Modules.Encryption.Coding.BaseEncoding.BaseEncodingViewController;
import myxfc.Kit.Utils.ViewNode;
import myxfc.Kit.Utils.ViewUtils;

import java.io.UnsupportedEncodingException;

/**
 * @author: myxfc
 * @create: 2021/11/22 21:19
 **/
@ViewNode(name = "Base92",folderPath = "Root/Encryption/Coding/BaseEncoding/",fxmlName = "Base92View.fxml")
public class Base92ViewController extends BaseEncodingViewController {
    @Override
    protected String encodeSplitToString() {
        try {
            return Base92Impl.encodeSplitToString(JTA_src.getText(),JCB_charset.getValue().toString(),ViewUtils.getSplit(JTF_split));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            JTA_dst.validate();
        }
        return "";
    }

    @Override
    protected String decodeSplitToString() {
        try {
            return Base92Impl.decodeSplitToString(JTA_src.getText(),JCB_charset.getValue().toString(),ViewUtils.getSplit(JTF_split));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            JTA_dst.validate();
        }
        return "";
    }

    @Override
    protected String encodeToString() {
        try {
            return Base92Impl.encodeToString(JTA_src.getText(),JCB_charset.getValue().toString());
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            JTA_dst.validate();
        }
        return "";
    }

    @Override
    protected String decodeToString() {
        try {
            return Base92Impl.decodeToString(JTA_src.getText(),JCB_charset.getValue().toString());
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            JTA_dst.validate();
        }
        return "";
    }

    @Override
    protected byte[] encodeToFile() {
        return Base92Impl.encode(byteFile);
    }

    @Override
    protected byte[] decodeToFile() {
        return Base92Impl.decode(byteFile);
    }
}
