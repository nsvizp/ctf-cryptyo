package crypto;

import com.jfoenix.controls.JFXComboBox;
import com.jfoenix.controls.JFXTextArea;
import com.jfoenix.controls.JFXTextField;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import myxfc.App.View.Modules.Encryption.Classical.Affine.AffineController;
import myxfc.App.View.Modules.Encryption.Classical.Bacon.BaconController;
import myxfc.App.View.Modules.Encryption.Classical.Hill.HillController;
import myxfc.App.View.Modules.Encryption.Classical.Playfair.PlayfairController;
import myxfc.App.View.Modules.Encryption.Coding.BaseEncoding.Base64.Base64ViewController;
import myxfc.App.View.Modules.Encryption.Coding.BaseEncoding.CustomBase.CustomBaseController;
import myxfc.App.View.Modules.Encryption.Coding.XOR.XORController;
import myxfc.App.View.Modules.Encryption.Modern.AsymmetricEncryption.RSA.RSAController;
import myxfc.App.View.Modules.Encryption.Modern.Hash.HashController;
import myxfc.App.View.Modules.Encryption.Modern.SymmetricEncryption.BlockCipher.BlockCipherController;
import myxfc.App.View.Modules.Encryption.Modern.SymmetricEncryption.StreamCipher.RC4.RC4Controller;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NewViewsTest {
    @BeforeAll
    static void startJavaFX() throws Exception {
        CountDownLatch latch = new CountDownLatch(1);
        Platform.setImplicitExit(false);
        Platform.startup(latch::countDown);
        if (!latch.await(20, TimeUnit.SECONDS)) {
            throw new IllegalStateException("JavaFX did not start");
        }
    }

    @Test
    void allNewViewsLoad() {
        String[] views = {
                "/myxfc/App/View/Modules/Encryption/Modern/AsymmetricEncryption/RSA/RSAView.fxml",
                "/myxfc/App/View/Modules/Encryption/Modern/SymmetricEncryption/StreamCipher/RC4/RC4View.fxml",
                "/myxfc/App/View/Modules/Encryption/Classical/Affine/AffineView.fxml",
                "/myxfc/App/View/Modules/Encryption/Classical/Bacon/BaconView.fxml",
                "/myxfc/App/View/Modules/Encryption/Classical/Playfair/PlayfairView.fxml",
                "/myxfc/App/View/Modules/Encryption/Classical/Hill/HillView.fxml",
                "/myxfc/App/View/Modules/Encryption/Coding/BaseEncoding/CustomBase/CustomBaseView.fxml",
                "/myxfc/App/View/Modules/Encryption/Coding/XOR/XORView.fxml",
                "/myxfc/App/View/Modules/Encryption/Modern/Hash/HashView.fxml",
                "/myxfc/App/View/Modules/Encryption/Coding/BaseEncoding/Base64/Base64View.fxml",
                "/myxfc/App/View/Modules/Encryption/Modern/SymmetricEncryption/BlockCipher/BlockCipherView.fxml",
                "/myxfc/App/View/Modules/Tools/Image/Steganography/SteganographyView.fxml",
                "/myxfc/App/View/Modules/Tools/CTF/CtfToolkitView.fxml"
        };
        for (String view : views) {
            assertNotNull(load(view), view);
        }
    }

    @Test
    void steganographyViewUsesOriginalTitleAndTheme() throws Exception {
        FXMLLoader loader = loadLoader("/myxfc/App/View/Modules/Tools/Image/Steganography/SteganographyView.fxml");
        Parent root = loader.getRoot();
        javafx.scene.Scene scene = runFx(() -> {
            javafx.scene.Scene value = new javafx.scene.Scene(root, 630, 600);
            value.getStylesheets().add(NewViewsTest.class.getResource("/css/MainCSS_dark.css").toExternalForm());
            root.applyCss();
            root.layout();
            return value;
        });
        javafx.scene.control.Label title = (javafx.scene.control.Label) root.lookup("#JLB_title");
        assertEquals(70, title.getPrefHeight());
        assertEquals(45, title.getFont().getSize());
        assertEquals(80, javafx.scene.layout.AnchorPane.getTopAnchor(
                (javafx.scene.layout.AnchorPane) root.lookup("#ACP_controllerAnchorPane")));

        if (Boolean.getBoolean("myxfc.captureUi")) {
            javafx.scene.image.WritableImage snapshot = runFx(() -> scene.snapshot(null));
            java.awt.image.BufferedImage image = new java.awt.image.BufferedImage(
                    (int) snapshot.getWidth(), (int) snapshot.getHeight(), java.awt.image.BufferedImage.TYPE_INT_ARGB);
            for (int y = 0; y < image.getHeight(); y++) {
                for (int x = 0; x < image.getWidth(); x++) {
                    image.setRGB(x, y, snapshot.getPixelReader().getArgb(x, y));
                }
            }
            javax.imageio.ImageIO.write(image, "png", new java.io.File("/tmp/myxfc-stego-ui.png"));
        }
    }

    @Test
    void rsaViewEncryptsAndDecrypts() {
        runFx(() -> {
            FXMLLoader loader = loadLoader("/myxfc/App/View/Modules/Encryption/Modern/AsymmetricEncryption/RSA/RSAView.fxml");
            Parent root = loader.getRoot();
            RSAController controller = loader.getController();
            combo(root, "JCB_keySize").setValue("1024");
            controller.ONClickGenerate();
            area(root, "JTA_src").setText("myxfc RSA");
            controller.ONClickEncode();
            String encrypted = area(root, "JTA_dst").getText();
            area(root, "JTA_src").setText(encrypted);
            combo(root, "JCB_inputFormat").setValue("Base64");
            controller.ONClickDecode();
            assertEquals("myxfc RSA", area(root, "JTA_dst").getText());
            return null;
        });
    }

    @Test
    void rc4ViewMatchesKnownVector() {
        runFx(() -> {
            FXMLLoader loader = loadLoader("/myxfc/App/View/Modules/Encryption/Modern/SymmetricEncryption/StreamCipher/RC4/RC4View.fxml");
            Parent root = loader.getRoot();
            area(root, "JTA_src").setText("Plaintext");
            field(root, "JTF_key").setText("Key");
            ((RC4Controller) loader.getController()).ONClickEncode();
            assertEquals("u/MW6NlArwrT", area(root, "JTA_dst").getText());
            return null;
        });
    }

    @Test
    void classicalViewsRunKnownExamples() {
        runFx(() -> {
            FXMLLoader affine = loadLoader("/myxfc/App/View/Modules/Encryption/Classical/Affine/AffineView.fxml");
            area(affine.getRoot(), "JTA_src").setText("AFFINECIPHER");
            ((AffineController) affine.getController()).ONClickEncode();
            assertEquals("IHHWVCSWFRCP", area(affine.getRoot(), "JTA_dst").getText());
            area(affine.getRoot(), "JTA_src").setText("IHHWVCSWFRCP");
            ((AffineController) affine.getController()).ONClickDecode();
            assertEquals("AFFINECIPHER", area(affine.getRoot(), "JTA_dst").getText());

            FXMLLoader bacon = loadLoader("/myxfc/App/View/Modules/Encryption/Classical/Bacon/BaconView.fxml");
            area(bacon.getRoot(), "JTA_src").setText("ABC");
            ((BaconController) bacon.getController()).ONClickEncode();
            assertEquals("AAAAAAAAABAAABA", area(bacon.getRoot(), "JTA_dst").getText());

            FXMLLoader playfair = loadLoader("/myxfc/App/View/Modules/Encryption/Classical/Playfair/PlayfairView.fxml");
            area(playfair.getRoot(), "JTA_src").setText("HIDETHEGOLDINTHETREESTUMP");
            field(playfair.getRoot(), "JTF_key").setText("PLAYFAIR EXAMPLE");
            ((PlayfairController) playfair.getController()).ONClickEncode();
            assertEquals("BMODZBXDNABEKUDMUIXMMOUVIF", area(playfair.getRoot(), "JTA_dst").getText());

            FXMLLoader hill = loadLoader("/myxfc/App/View/Modules/Encryption/Classical/Hill/HillView.fxml");
            area(hill.getRoot(), "JTA_src").setText("ACT");
            field(hill.getRoot(), "JTF_matrix").setText("6,24,1;13,16,10;20,17,15");
            ((HillController) hill.getController()).ONClickEncode();
            assertEquals("POH", area(hill.getRoot(), "JTA_dst").getText());
            return null;
        });
    }

    @Test
    void customBaseAndXorViewsRun() {
        runFx(() -> {
            FXMLLoader custom = loadLoader("/myxfc/App/View/Modules/Encryption/Coding/BaseEncoding/CustomBase/CustomBaseView.fxml");
            area(custom.getRoot(), "JTA_src").setText("foobar");
            ((CustomBaseController) custom.getController()).ONClickEncode();
            assertEquals("Zm9vYmFy", area(custom.getRoot(), "JTA_dst").getText());

            FXMLLoader xor = loadLoader("/myxfc/App/View/Modules/Encryption/Coding/XOR/XORView.fxml");
            area(xor.getRoot(), "JTA_src").setText("flag{ui_test}");
            field(xor.getRoot(), "JTF_key").setText("A");
            ((XORController) xor.getController()).ONClickBruteForce();
            assertTrue(area(xor.getRoot(), "JTA_dst").getText().contains("key=0x00"));
            assertTrue(area(xor.getRoot(), "JTA_dst").getText().contains("flag{ui_test}"));
            return null;
        });
    }

    @Test
    void hashViewRemainsFunctional() {
        runFx(() -> {
            FXMLLoader hash = loadLoader("/myxfc/App/View/Modules/Encryption/Modern/Hash/HashView.fxml");
            area(hash.getRoot(), "JTA_src").setText("abc");
            ((HashController) hash.getController()).ONClickConfirm();
            assertEquals("900150983cd24fb0d6963f7d28e17f72", area(hash.getRoot(), "JTA_dst1").getText());
            combo(hash.getRoot(), "JCB_hashMode").setValue("CRC");
            combo(hash.getRoot(), "JCB_hashBit").setValue("32");
            area(hash.getRoot(), "JTA_src").setText("123456789");
            ((HashController) hash.getController()).ONClickConfirm();
            assertEquals("cbf43926", area(hash.getRoot(), "JTA_dst1").getText());
            return null;
        });
    }

    @Test
    void aesViewRemainsFunctional() throws Exception {
        FXMLLoader aes = loadLoader("/myxfc/App/View/Modules/Encryption/Modern/SymmetricEncryption/BlockCipher/BlockCipherView.fxml");
        BlockCipherController controller = aes.getController();
        runFx(() -> {
            field(aes.getRoot(), "JTF_key").setText("0123456789012345");
            privateField(controller, "JTF_iv", "0123456789012345");
            area(aes.getRoot(), "JTA_src").setText("hello");
            controller.ONClickEncode();
            return null;
        });
        Thread.sleep(1000);
        String encrypted = runFx(() -> area(aes.getRoot(), "JTA_dst").getText());
        assertTrue(encrypted.length() > 0);
        runFx(() -> {
            privateCombo(controller, "JCB_inputFormat", "Base64");
            privateCombo(controller, "JCB_outputFormat", "Text");
            area(aes.getRoot(), "JTA_src").setText(encrypted);
            controller.ONClickDecode();
            return null;
        });
        Thread.sleep(1000);
        assertEquals("hello", runFx(() -> area(aes.getRoot(), "JTA_dst").getText()));
    }

    @Test
    void base64ViewRemainsFunctional() throws Exception {
        FXMLLoader loader = loadLoader("/myxfc/App/View/Modules/Encryption/Coding/BaseEncoding/Base64/Base64View.fxml");
        runFx(() -> {
            area(loader.getRoot(), "JTA_src").setText("abc");
            ((Base64ViewController) loader.getController()).ONClickEncode();
            return null;
        });
        Thread.sleep(1000);
        assertEquals("YWJj", runFx(() -> area(loader.getRoot(), "JTA_dst").getText()));
    }

    static Parent load(String path) {
        return loadLoader(path).getRoot();
    }

    static FXMLLoader loadLoader(String path) {
        return runFx(() -> {
            FXMLLoader loader = new FXMLLoader(NewViewsTest.class.getResource(path));
            loader.setResources(myxfc.Init.Init.getLanguageResourceBundle());
            loader.load();
            return loader;
        });
    }

    private static <T> T runFx(Callable<T> callable) {
        if (Platform.isFxApplicationThread()) {
            try {
                return callable.call();
            } catch (Exception e) {
                throw new AssertionError(e);
            }
        }
        try {
            FutureTask<T> task = new FutureTask<>(callable);
            Platform.runLater(task);
            return task.get(20, TimeUnit.SECONDS);
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    private static JFXTextArea area(Parent root, String id) {
        return (JFXTextArea) root.lookup("#" + id);
    }

    private static JFXTextField field(Parent root, String id) {
        return (JFXTextField) root.lookup("#" + id);
    }

    @SuppressWarnings("unchecked")
    private static JFXComboBox<String> combo(Parent root, String id) {
        return (JFXComboBox<String>) root.lookup("#" + id);
    }

    private static void privateField(Object controller, String name, String value) throws Exception {
        Field field = controller.getClass().getDeclaredField(name);
        field.setAccessible(true);
        ((JFXTextField) field.get(controller)).setText(value);
    }

    @SuppressWarnings("unchecked")
    private static void privateCombo(Object controller, String name, String value) throws Exception {
        Field field = controller.getClass().getDeclaredField(name);
        field.setAccessible(true);
        ((JFXComboBox<String>) field.get(controller)).setValue(value);
    }
}
