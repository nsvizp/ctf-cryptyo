# myxfc 开发说明

myxfc 基于 JDK 17、JavaFX 17 和 JFoenix，使用 Maven 构建，通过 jlink 与 jpackage 生成桌面应用。

## 目录结构

```text
myxfc
├── pom.xml
├── src/main/java
│   ├── module-info.java
│   └── myxfc
│       ├── App/View/Modules       功能页面、控制器和算法实现
│       ├── App/View/Root          首页与功能树
│       ├── App/View/Viewobj       页面基类
│       ├── Init                   全局与控件初始化
│       ├── Kit                    通用工具与页面模板
│       └── Main.java              JavaFX 入口
├── src/main/resources             语言、样式、图片和 JSON 配置
├── src/test/java                  自动测试与实验代码
└── jpackage                       各平台打包脚本和图标
```

## 新增功能页面

每个功能模块通常包含：

- `XxxImpl.java`：算法实现，尽量独立于 JavaFX。
- `XxxController.java`：处理输入、输出和控件事件。
- `XxxView.fxml`：页面布局。

控制器使用 `@ViewNode` 声明菜单位置：

```java
@ViewNode(
    name = "Example",
    folderPath = "Root/Encryption/Classical/",
    fxmlName = "ExampleView.fxml"
)
```

`AutoRootTreeNode` 会扫描 `myxfc.App.View.Modules`，无需再手工修改功能树。`name` 和目录名称应同时添加到 `Language.properties` 与 `Language_zh.properties`。

页面可继承：

- `ViewController`：文本输入输出。
- `ViewControllerFileMode`：需要文件输入输出时。

算法测试放入 `src/test/java`，使用 JUnit 5，并覆盖公开已知向量、往返及非法参数。

## 常用命令

```bash
mvn clean test
mvn clean package
mvn javafx:jlink
```

macOS Apple Silicon 打包：

```bash
MVN=mvn bash jpackage/macPack 1.14.2
```

打包脚本要求 arm64 JDK 17，可通过 `JDK17_HOME` 指定 JDK，通过 `MVN` 指定 Maven 可执行文件。
