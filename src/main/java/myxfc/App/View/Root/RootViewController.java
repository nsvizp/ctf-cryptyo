package myxfc.App.View.Root;

import com.jfoenix.controls.JFXButton;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.control.TreeView;
import javafx.scene.image.ImageView;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.BorderPane;
import myxfc.Init.ConfigListInit;
import myxfc.Init.ImageListInit;
import myxfc.Init.Init;
import myxfc.Kit.Utils.ConfigUtils;
import myxfc.Kit.Utils.ViewUtils;
import myxfc.Main;

import java.io.IOException;
import java.util.Objects;

public class RootViewController {
    private AutoRootTreeNode autoRootTreeNode;
    @FXML private BorderPane borderPane;
    @FXML private AnchorPane indexpane;
    @FXML private TreeView<String> RootTree;
    @FXML private ImageView IV_Logo;
    @FXML private JFXButton JBT_StyleChange;
    private int styleMode;
    private AnchorPane selectedAnchorPane;

    @FXML
    private void initialize() {
        autoRootTreeNode = new AutoRootTreeNode();
        RootTree.setRoot(autoRootTreeNode.rootItem);
        setImage();
        changeStyle();
    }

    @FXML
    private void checkView() {
        try {
            if (RootTree.getSelectionModel().getSelectedItem() != null
                    && RootTree.getSelectionModel().getSelectedItem().getValue().equals(Init.getLanguage("Root"))) {
                borderPane.setCenter(indexpane);
            }
            if (RootTree.getSelectionModel().getSelectedItem() != null
                    && RootTree.getSelectionModel().getSelectedItem().isLeaf()) {
                if (!"".equals(autoRootTreeNode.nodeMap.get(RootTree.getSelectionModel().getSelectedItem()))) {
                    FXMLLoader loader = new FXMLLoader();
                    loader.setLocation(RootViewController.class.getResource(
                            autoRootTreeNode.nodeMap.get(RootTree.getSelectionModel().getSelectedItem())));
                    loader.setResources(Init.getLanguageResourceBundle());
                    try {
                        selectedAnchorPane = loader.load();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                    borderPane.setCenter(selectedAnchorPane);
                    try {
                        RootTree.getSelectionModel().select(RootTree.getSelectionModel().getSelectedItem().getParent());
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
        } catch (NullPointerException e) {
            e.printStackTrace();
        }
    }

    private void setImage() {
        IV_Logo.setImage(ViewUtils.getImage(ImageListInit.LOGO));
    }

    private void changeStyle() {
        styleMode = Init.getConfig(ConfigListInit.AppStyle).equals("dark") ? 2 : 3;
        JBT_StyleChange.setOnAction(event -> {
            if (styleMode == 100) {
                styleMode = 2;
            }
            if (styleMode % 2 == 0) {
                borderPane.getScene().getStylesheets().clear();
                borderPane.getScene().getStylesheets().add(Objects.requireNonNull(
                        Main.class.getResource("/css/MainCSS_light.css")).toExternalForm());
                ConfigUtils.editConfigFile(ConfigListInit.AppStyle, "light");
                setImage();
                JBT_StyleChange.setText(Init.getLanguage("LightMode"));
            } else {
                borderPane.getScene().getStylesheets().clear();
                borderPane.getScene().getStylesheets().add(Objects.requireNonNull(
                        Main.class.getResource("/css/MainCSS_dark.css")).toExternalForm());
                ConfigUtils.editConfigFile(ConfigListInit.AppStyle, "dark");
                setImage();
                JBT_StyleChange.setText(Init.getLanguage("DarkMode"));
            }
            autoRootTreeNode = new AutoRootTreeNode();
            RootTree.setRoot(autoRootTreeNode.rootItem);
            styleMode++;
        });
    }
}
