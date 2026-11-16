<p align="center"><img src="./assets/img/myxfc_Banner.png" width="80%"></p>
<p align="center"><a href="README.md">English</a> | <a href="README-zh.md">中文</a></p>

# myxfc

myxfc 是一个基于 JDK 17、JavaFX 和 JFoenix 的 CTF 加解密与编码工具，支持文本和文件处理，并提供 macOS Apple Silicon 原生应用包。

## 主要功能

- 现代密码：RSA、RC4、AES、DES、3DES、SM4、Blowfish、Serpent、Twofish、TEA/XTEA 等。
- 摘要与认证：MD5、MD5-16、SHA 系列、SM3、CRC32、HMAC、NTLM Hash、JWT。
- 古典密码：凯撒、ROT、栅栏及 W 型栅栏、Atbash、Vigenere、仿射、培根、Playfair、Hill。
- 编码：Base16/32/58/62/64/85/91/92、自定义 Base16/32/64 字母表、URL、ASCII、HEX、Unicode、HTML 实体、摩斯电码、Brainfuck。
- XOR：标准循环密钥 XOR、Text/HEX/Base64 输入输出、单字节密钥爆破与候选排序。
- 其他工具：二维码、像素置换、文本处理、时间戳、文件头检测及红队辅助工具。

## 构建

需要 JDK 17 和 Maven：

```bash
mvn clean test
mvn clean package
```

macOS arm64 可使用 `jpackage/macPack`，产物位于 `target/myxfc.app` 和 `target/myxfc-mac-arm64.zip`。应用内嵌 Java 运行时和 BouncyCastle，不要求安装到 `/Applications`，也不需要单独配置 Provider。

##  macOS 打开说明

未提供 Developer ID 时，应用使用 ad-hoc 签名且未经过 Apple 公证。在其他 Mac 上首次打开时，可能需要在“隐私与安全性”中手动允许。

## 许可

项目基于 MIT License 发布，详见 `LICENSE`。第三方组件的许可信息保留在应用运行时法律声明中。
