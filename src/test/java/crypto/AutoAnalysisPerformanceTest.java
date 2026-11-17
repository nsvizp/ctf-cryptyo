package crypto;

import myxfc.App.View.Modules.Tools.CTF.Engine.Analysis.AutoAnalysisService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AutoAnalysisPerformanceTest {
    @TempDir
    Path temp;

    @Test
    void largeCaptureWithManyTextStreamsCompletesWithinBudget() throws Exception {
        String encoded = Base64.getEncoder().encodeToString("flag{performance} ".getBytes(StandardCharsets.UTF_8));
        String block = encoded.repeat(4096);
        byte[][] packets = new byte[40][];
        for (int i = 0; i < packets.length; i++) {
            String request = "POST /upload HTTP/1.1\r\nHost: test\r\nContent-Length: " + block.length()
                    + "\r\n\r\n" + block;
            packets[i] = tcpPacket(12000 + i, 80, request.getBytes(StandardCharsets.ISO_8859_1));
        }
        Path pcap = temp.resolve("large.pcap");
        Files.write(pcap, pcap(packets));

        var findings = assertTimeoutPreemptively(Duration.ofSeconds(8), () -> AutoAnalysisService.analyze(pcap));
        assertTrue(findings.toString().contains("flag{performance}"));
    }

    private static byte[] tcpPacket(int sourcePort, int destinationPort, byte[] payload) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.write(new byte[12]);
        output.write(0x08);
        output.write(0);
        output.write(0x45);
        output.write(0);
        write16be(output, 40 + payload.length);
        write16be(output, 1);
        write16be(output, 0);
        output.write(64);
        output.write(6);
        write16be(output, 0);
        output.write(new byte[]{1, 1, 1, 1});
        output.write(new byte[]{2, 2, 2, 2});
        write16be(output, sourcePort);
        write16be(output, destinationPort);
        write32be(output, 100);
        write32be(output, 0);
        output.write(0x50);
        output.write(0x18);
        write16be(output, 65535);
        write16be(output, 0);
        write16be(output, 0);
        output.write(payload);
        return output.toByteArray();
    }

    private static byte[] pcap(byte[][] packets) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.write(new byte[]{(byte) 0xD4, (byte) 0xC3, (byte) 0xB2, (byte) 0xA1});
        write16le(output, 2);
        write16le(output, 4);
        write32le(output, 0);
        write32le(output, 0);
        write32le(output, 65535);
        write32le(output, 1);
        for (byte[] packet : packets) {
            write32le(output, 1);
            write32le(output, 0);
            write32le(output, packet.length);
            write32le(output, packet.length);
            output.write(packet);
        }
        return output.toByteArray();
    }

    private static void write16le(ByteArrayOutputStream output, int value) {
        output.write(value & 0xFF);
        output.write(value >>> 8 & 0xFF);
    }

    private static void write32le(ByteArrayOutputStream output, long value) {
        output.write((int) (value & 0xFF));
        output.write((int) (value >>> 8 & 0xFF));
        output.write((int) (value >>> 16 & 0xFF));
        output.write((int) (value >>> 24 & 0xFF));
    }

    private static void write16be(ByteArrayOutputStream output, int value) {
        output.write(value >>> 8 & 0xFF);
        output.write(value & 0xFF);
    }

    private static void write32be(ByteArrayOutputStream output, long value) {
        output.write((int) (value >>> 24 & 0xFF));
        output.write((int) (value >>> 16 & 0xFF));
        output.write((int) (value >>> 8 & 0xFF));
        output.write((int) (value & 0xFF));
    }
}
