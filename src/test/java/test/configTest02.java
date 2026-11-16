package test;

import myxfc.Kit.Utils.ConfigUtils;

import java.io.IOException;

/**
 * @author: myxfc
 * @create: 2022/8/5 14:42
 **/
public class configTest02 {
    public static void main(String[] args) throws IOException {
        ConfigUtils.createConfigFile("D:\\test.txt");
    }
}
