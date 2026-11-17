package crypto;

import myxfc.App.View.Modules.Tools.CTF.Engine.Analysis.AutoAnalysisService;
import myxfc.App.View.Modules.Tools.CTF.Engine.Pcap.PcapAnalysisService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PcapAnalysisServiceTest {
    @TempDir
    Path temp;

    @Test
    void pcapAndPcapngHttpObjectsWork() throws Exception {
        byte[] request = tcpPacket(12345, 80, 100, "GET /flag.txt HTTP/1.1\r\nHost: test\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
        byte[] response = tcpPacket(80, 12345, 200, ("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                + "Transfer-Encoding: chunked\r\n\r\nA\r\nflag{pcap}\r\n0\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
        Path pcap = temp.resolve("test.pcap");
        Files.write(pcap, pcap(new byte[][]{request, response}));
        var capture = PcapAnalysisService.read(pcap);
        assertEquals(2, capture.packets().size());
        var streams = PcapAnalysisService.tcpStreams(capture);
        assertEquals(1, streams.size());
        var objects = PcapAnalysisService.httpObjects(streams);
        assertEquals(2, objects.size());
        assertEquals("flag{pcap}", new String(objects.get(1).body(), StandardCharsets.UTF_8));
        assertEquals("/flag.txt", objects.get(1).uri());

        Path pcapng = temp.resolve("test.pcapng");
        byte[] pcapngData = pcapng(new byte[][]{request, response});
        Files.write(pcapng, pcapngData);
        assertEquals(2, PcapAnalysisService.read(pcapng).packets().size());
    }

    @Test
    void anomaliesIncludeSqlInjectionJwtAndLongUri() throws Exception {
        String token = "eyJhbGciOiJub25lIn0.eyJmbGFnIjoiZmxhZ3tqd3R9In0.";
        String requestText = "GET /" + "A".repeat(2100) + "?q=union%20select HTTP/1.1\r\n"
                + "Authorization: Bearer " + token + "\r\nCookie: session=abc\r\n\r\n";
        byte[] request = tcpPacket(12345, 80, 100, requestText.getBytes(StandardCharsets.ISO_8859_1));
        Path path = temp.resolve("anomalies.pcap");
        Files.write(path, pcap(new byte[][]{request}));
        var capture = PcapAnalysisService.read(path);
        String findings = myxfc.App.View.Modules.Tools.CTF.Engine.Analysis.TrafficAnomalyService.analyze(capture).toString();
        assertTrue(findings.contains("SQL injection UNION SELECT"), findings);
        assertTrue(findings.contains("JWT detected"), findings);
        assertTrue(findings.contains("Abnormally long URI"), findings);
        assertTrue(findings.contains("alg=none"), findings);

        var smart = myxfc.App.View.Modules.Tools.CTF.Engine.Analysis.TrafficIntelligenceService.analyze(capture);
        String grouped = myxfc.App.View.Modules.Tools.CTF.Engine.Analysis.AnalysisReportFormatter.format(smart.findings());
        assertTrue(grouped.contains("===== SQL Injection "), grouped);
        assertTrue(grouped.contains("===== Authentication / JWT / Tokens "), grouped);
        assertTrue(grouped.contains("===== HTTP "), grouped);
        assertTrue(grouped.contains("===== TCP "), grouped);
        String jwtEvidence = smart.findings().stream()
                .filter(finding -> finding.method().contains("JWT"))
                .map(AutoAnalysisService.Finding::result).reduce("", (a, b) -> a + b);
        assertTrue(jwtEvidence.contains(token), jwtEvidence);
    }

    @Test
    void smartReportDecodesCompressionAuthenticationAndTls() throws Exception {
        byte[] compressed = gzip("union select flag{gzip_http}".getBytes(StandardCharsets.UTF_8));
        String responseText = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\nContent-Length: "
                + compressed.length + "\r\n\r\n";
        byte[] response = tcpPacket(80, 12345, 200, join(responseText.getBytes(StandardCharsets.ISO_8859_1), compressed));
        byte[] request = tcpPacket(12345, 80, 100,
                "GET /login HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
        Path path = temp.resolve("smart.pcap");
        Files.write(path, pcap(new byte[][]{request, response, tcpPacket(12345, 443, 300, tlsClientHello("example.com"))}));
        var report = myxfc.App.View.Modules.Tools.CTF.Engine.Analysis.TrafficIntelligenceService.analyze(
                PcapAnalysisService.read(path));
        String output = report.summary() + report.findings();
        assertTrue(output.contains("Decoded gzip body"), output);
        assertTrue(output.contains("user:pass"), output);
        assertTrue(output.contains("example.com"), output);
        assertTrue(output.contains("Smart traffic report"), output);
    }

    @Test
    void smartSummaryKeepsEveryJwtBeyondTwenty() throws Exception {
        byte[][] packets = new byte[25][];
        String[] tokens = new String[25];
        for (int i = 0; i < packets.length; i++) {
            String header = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
                    "{\"alg\":\"HS256\"}".getBytes(StandardCharsets.UTF_8));
            String payload = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
                    ("{\"id\":" + i + "}").getBytes(StandardCharsets.UTF_8));
            tokens[i] = header + "." + payload + ".signature";
            String request = "GET / HTTP/1.1\r\nAuthorization: Bearer " + tokens[i] + "\r\n\r\n";
            packets[i] = tcpPacket(12000 + i, 80, 100, request.getBytes(StandardCharsets.ISO_8859_1));
        }
        Path path = temp.resolve("many-jwts.pcap");
        Files.write(path, pcap(packets));
        var report = myxfc.App.View.Modules.Tools.CTF.Engine.Analysis.TrafficIntelligenceService.analyze(
                PcapAnalysisService.read(path));
        for (String token : tokens) {
            assertTrue(report.summary().contains(token), report.summary());
        }
    }

    @Test
    void smartTcpPayloadKeepsContentBeyondPreviewLimits() throws Exception {
        String payload = "START " + "A".repeat(1400) + " END flag{complete}";
        Path path = temp.resolve("long-stream.pcap");
        Files.write(path, pcap(new byte[][]{tcpPacket(12345, 9000, 100,
                payload.getBytes(StandardCharsets.ISO_8859_1))}));
        var report = myxfc.App.View.Modules.Tools.CTF.Engine.Analysis.TrafficIntelligenceService.analyze(
                PcapAnalysisService.read(path));
        String tcp = report.findings().stream()
                .filter(finding -> finding.source().equals("TCP") && finding.method().equals("Stream payload"))
                .map(AutoAnalysisService.Finding::result).findFirst().orElseThrow();
        assertTrue(tcp.contains("END flag{complete}"), tcp);
        assertTrue(AutoAnalysisService.analyze(path).toString().contains("END flag{complete}"));
    }

    private static byte[] gzip(byte[] data) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (var gzip = new java.util.zip.GZIPOutputStream(output)) {
            gzip.write(data);
        }
        return output.toByteArray();
    }

    private static byte[] join(byte[] first, byte[] second) {
        byte[] result = java.util.Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    private static byte[] tlsClientHello(String host) throws Exception {
        byte[] hostname = host.getBytes(StandardCharsets.ISO_8859_1);
        ByteArrayOutputStream extensions = new ByteArrayOutputStream();
        write16be(extensions, 0);
        write16be(extensions, 5 + hostname.length);
        write16be(extensions, 3 + hostname.length);
        extensions.write(0);
        write16be(extensions, hostname.length);
        extensions.write(hostname);

        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(new byte[]{3, 3});
        body.write(new byte[32]);
        body.write(0);
        write16be(body, 2);
        write16be(body, 0x1301);
        body.write(0);
        write16be(body, extensions.size());
        extensions.writeTo(body);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.write(22);
        output.write(new byte[]{3, 3});
        write16be(output, body.size() + 4);
        output.write(1);
        output.write(new byte[]{0, 0, 0});
        output.write(body.size());
        body.writeTo(output);
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

    private static byte[] pcapng(byte[][] packets) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        write32le(output, 0x0A0D0D0A);
        write32le(output, 28);
        write32le(output, 0x1A2B3C4D);
        write16le(output, 1);
        write16le(output, 0);
        output.write(new byte[]{-1, -1, -1, -1, -1, -1, -1, -1});
        write32le(output, 28);
        write32le(output, 1);
        write32le(output, 20);
        write16le(output, 1);
        write16le(output, 0);
        write32le(output, 65535);
        write32le(output, 20);
        for (byte[] packet : packets) {
            int padding = (4 - packet.length % 4) % 4;
            int length = 32 + packet.length + padding;
            write32le(output, 6);
            write32le(output, length);
            write32le(output, 0);
            write32le(output, 0);
            write32le(output, 1);
            write32le(output, packet.length);
            write32le(output, packet.length);
            output.write(packet);
            output.write(new byte[padding]);
            write32le(output, length);
        }
        return output.toByteArray();
    }

    private static byte[] tcpPacket(int sourcePort, int destinationPort, int sequence, byte[] payload) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.write(new byte[12]);
        output.write(0x08);
        output.write(0x00);
        output.write(0x45);
        output.write(0);
        write16be(output, 40 + payload.length);
        write16be(output, 1);
        write16be(output, 0);
        output.write(64);
        output.write(6);
        write16be(output, 0);
        output.write(sourcePort == 80 ? new byte[]{2, 2, 2, 2} : new byte[]{1, 1, 1, 1});
        output.write(sourcePort == 80 ? new byte[]{1, 1, 1, 1} : new byte[]{2, 2, 2, 2});
        write16be(output, sourcePort);
        write16be(output, destinationPort);
        write32be(output, sequence);
        write32be(output, 0);
        output.write(0x50);
        output.write(0x18);
        write16be(output, 65535);
        write16be(output, 0);
        write16be(output, 0);
        output.write(payload);
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
