<p align="center"><img src="./assets/img/myxfc_Banner.png" width="80%"></p>
<p align="center"><a href="README.md">English</a> | <a href="README-zh.md">中文</a></p>

# myxfc

myxfc is a CTF cryptography and encoding toolkit built with JDK 17, JavaFX and JFoenix. It supports text and file processing and provides a native Apple Silicon macOS application.

## Features

- Modern cryptography: RSA, RC4, AES, DES, 3DES, SM4, Blowfish, Serpent, Twofish, TEA/XTEA and more.
- Hashes and authentication: MD5, MD5-16, SHA families, SM3, CRC32, HMAC, NTLM Hash and JWT.
- Classical cryptography: Caesar, ROT, Rail Fence and W Rail Fence, Atbash, Vigenere, Affine, Bacon, Playfair and Hill.
- Encodings: Base16/32/58/62/64/85/91/92, custom Base16/32/64 alphabets, URL, ASCII, HEX, Unicode, HTML entities, Morse and Brainfuck.
- XOR: standard repeating-key XOR, Text/HEX/Base64 formats, single-byte brute force and ranked candidates.
- CTF toolkit: one-click automatic file analysis, nested encoding/JWT/Base/URL auto-decoding, XOR/RC4/SM4/AES/DES key-candidate analysis, ZIP/Office/PDF inspection and embedded-object extraction, PDF/Office encryption and corruption diagnosis/repair, binwalk integration, WAV LSB/spectrum/automatic DTMF decoding, PCAP/PCAPNG stream reassembly and HTTP object export, protocol/DNS/TCP/SQLi/XSS/LFI/RCE/authentication anomaly analysis, RSA attacks, Vigenere and repeating-key XOR cracking.
- Image steganography: LSB, palette, pixel-value mapping, reversible Haar DWT, RGBA/bit-plane analysis, image difference/XOR/overlay, EXIF, PNG chunks, trailing-data extraction, file carving, FFT/DCT/histograms, and steghide/OutGuess integration.
- Additional utilities: QR codes, pixel replacement, text editing, timestamps, file-header checks and red-team helpers.

## Build

JDK 17 and Maven are required:

```bash
mvn clean test
mvn clean package
```

On macOS arm64, run `jpackage/macPack`. Outputs are written to `target/myxfc.app` and `target/myxfc-mac-arm64.zip`. The app embeds its Java runtime and BouncyCastle, so it does not need to be installed in `/Applications` and does not require external Provider configuration.

## macOS opening note

Without a Developer ID certificate, the app is ad-hoc signed and is not notarized by Apple. On another Mac, the first launch may require explicit approval under Privacy & Security.

## License

Distributed under the MIT License. See `LICENSE`. Third-party license notices are retained in the packaged runtime.
