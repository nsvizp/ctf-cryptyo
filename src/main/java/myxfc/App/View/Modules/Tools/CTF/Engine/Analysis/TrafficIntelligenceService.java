package myxfc.App.View.Modules.Tools.CTF.Engine.Analysis;

import myxfc.App.View.Modules.Tools.CTF.Engine.Decode.JwtAnalysisService;
import myxfc.App.View.Modules.Tools.CTF.Engine.Decode.MultiDecodeService;
import myxfc.App.View.Modules.Tools.CTF.Engine.Pcap.PcapAnalysisService;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;
import java.util.zip.Inflater;

public class TrafficIntelligenceService {
    public record SmartReport(String summary, List<AutoAnalysisService.Finding> findings) {
    }

    public static SmartReport analyze(PcapAnalysisService.Capture capture) {
        List<AutoAnalysisService.Finding> findings = new ArrayList<>(TrafficAnomalyService.analyze(capture));
        var streams = PcapAnalysisService.tcpStreams(capture);
        var objects = PcapAnalysisService.httpObjects(streams);
        Set<String> tlsHosts = new LinkedHashSet<>();
        Set<String> iocs = new LinkedHashSet<>();
        for (var stream : streams) {
            stream.directions().forEach((direction, data) -> {
                analyzeService(direction, data, tlsHosts, findings);
                String text = new String(data, StandardCharsets.ISO_8859_1);
                if (data.length > 0) {
                    add(findings, "TCP", "Stream payload", direction + " bytes=" + data.length
                            + "\n" + preview(text), 20);
                }
                collectIocs(text, iocs);
            });
        }
        for (var object : objects) {
            analyzeHttpEncoding(object, findings);
            analyzeAuthentication(object, findings);
            add(findings, "HTTP", object.method() + " " + object.uri(),
                    object.status() + " " + object.contentType() + " body=" + object.body().length, 30);
            collectIocs(object.uri() + " " + object.headers() + " "
                    + new String(object.body(), StandardCharsets.ISO_8859_1), iocs);
        }
        for (String datagram : PcapAnalysisService.udpSummaries(capture)) {
            add(findings, "UDP", "Datagram", datagram, 20);
            analyzeDnsEncoding(datagram, findings);
        }

        Map<String, AutoAnalysisService.Finding> unique = new LinkedHashMap<>();
        for (var finding : findings) {
            String key = finding.source() + "|" + finding.method() + "|" + finding.result().replaceAll("\\s+", " ").trim();
            unique.merge(key, finding, (first, second) -> first.score() >= second.score() ? first : second);
        }
        List<AutoAnalysisService.Finding> ordered = new ArrayList<>(unique.values());
        ordered.sort(Comparator.comparingDouble(AutoAnalysisService.Finding::score).reversed());
        long high = ordered.stream().filter(finding -> finding.score() >= 80).count();
        StringBuilder summary = new StringBuilder("Smart traffic report\n");
        summary.append("Packets: ").append(capture.packets().size())
                .append(", TCP streams: ").append(streams.size())
                .append(", HTTP objects: ").append(objects.size())
                .append(", high-priority findings: ").append(high).append('\n');
        if (!tlsHosts.isEmpty()) {
            summary.append("TLS SNI: ").append(String.join(", ", tlsHosts)).append('\n');
        }
        if (!iocs.isEmpty()) {
            summary.append("IOC candidates: ").append(String.join(", ", iocs)).append('\n');
        }
        summary.append("Top conclusions:\n");
        ordered.stream().limit(5).forEach(finding -> summary.append("- ").append(finding.method())
                .append(" [").append(finding.source()).append("] score=")
                .append(String.format("%.0f", finding.score())).append('\n'));
        return new SmartReport(summary.toString(), List.copyOf(ordered));
    }

    private static void analyzeService(String direction, byte[] data, Set<String> tlsHosts,
                                       List<AutoAnalysisService.Finding> findings) {
        if (data.length == 0) {
            return;
        }
        String sni = tlsSni(data);
        if (sni != null) {
            tlsHosts.add(sni);
            add(findings, "TLS", "ClientHello SNI", direction + " " + sni, 55);
        }
        String text = new String(data, StandardCharsets.ISO_8859_1);
        if (text.startsWith("SSH-")) {
            add(findings, "SSH", "SSH banner", direction + " " + preview(text), 45);
        } else if (text.startsWith("220 ") || text.startsWith("220-")) {
            add(findings, "FTP/SMTP", "Service greeting", direction + " " + preview(text), 40);
        } else if (text.matches("(?s).*(?:USER|PASS|AUTH|EHLO|HELO|MAIL FROM|RCPT TO|STARTTLS).*")) {
            add(findings, "Service", "Authentication/mail protocol", direction + " " + preview(text), 55);
        } else if (text.startsWith("PING") || text.startsWith("+PONG") || text.startsWith("$")) {
            add(findings, "Redis", "Possible Redis protocol", direction + " " + preview(text), 40);
        } else if (data.length > 64 && entropy(data) > 7.5) {
            add(findings, "TCP", "High-entropy payload", direction + " bytes=" + data.length
                    + " entropy=" + String.format("%.2f", entropy(data)), 30);
        }
    }

    private static void analyzeHttpEncoding(PcapAnalysisService.HttpObject object,
                                            List<AutoAnalysisService.Finding> findings) {
        String encoding = object.headers().getOrDefault("content-encoding", "").toLowerCase();
        if (encoding.isEmpty()) {
            return;
        }
        try {
            byte[] decoded = switch (encoding) {
                case "gzip" -> gunzip(object.body());
                case "deflate" -> inflate(object.body());
                default -> object.body();
            };
            String text = new String(decoded, StandardCharsets.UTF_8);
            add(findings, "HTTP", "Decoded " + encoding + " body", preview(text), 55);
            for (MultiDecodeService.Result result : MultiDecodeService.decode(text, 5)) {
                add(findings, "HTTP decoded", result.chain(), result.output(), result.score());
            }
            String lower = text.toLowerCase();
            for (String keyword : List.of("union select", "or 1=1", "information_schema", "<script", "flag{", "ctf{")) {
                if (lower.contains(keyword)) {
                    add(findings, "HTTP decoded", "Suspicious decoded content: " + keyword, preview(text), 110);
                }
            }
        } catch (Exception e) {
            add(findings, "HTTP", "Invalid " + encoding + " body", e.getMessage(), 65);
        }
    }

    private static void analyzeAuthentication(PcapAnalysisService.HttpObject object,
                                              List<AutoAnalysisService.Finding> findings) {
        String authorization = object.headers().getOrDefault("authorization", "");
        if (authorization.startsWith("Basic ")) {
            try {
                String credentials = new String(Base64.getDecoder().decode(authorization.substring(6).trim()),
                        StandardCharsets.UTF_8);
                add(findings, "Authentication", "HTTP Basic credentials", credentials, 115);
            } catch (Exception e) {
                add(findings, "Authentication", "Invalid Basic authorization", authorization, 65);
            }
        }
        String body = new String(object.body(), StandardCharsets.ISO_8859_1);
        Matcher credentials = Pattern.compile("(?i)(?:user(?:name)?|login|pass(?:word)?|passwd)=([^&\\s]{1,256})")
                .matcher(object.uri() + "&" + body);
        while (credentials.find()) {
            add(findings, "Authentication", "Credential parameter", credentials.group(), 85);
        }
        for (JwtAnalysisService.Report report : JwtAnalysisService.find(authorization + " " + object.uri() + " " + body)) {
            add(findings, "Authentication", "JWT analysis", report.toString(),
                    report.issues().isEmpty() ? 60 : 110);
        }
    }

    private static void analyzeDnsEncoding(String summary, List<AutoAnalysisService.Finding> findings) {
        for (String label : summary.split("[.\\s]")) {
            if (label.length() < 8 || label.length() > 120) {
                continue;
            }
            for (MultiDecodeService.Result result : MultiDecodeService.decode(label, 2)) {
                if (!result.steps().isEmpty() && !result.output().equals(label)) {
                    add(findings, "DNS", "Encoded label " + result.chain(), label + " -> " + result.output(), 75);
                }
            }
        }
    }

    private static void collectIocs(String text, Set<String> iocs) {
        Matcher url = Pattern.compile("https?://[^\\s\"'<>]{4,500}").matcher(text);
        while (url.find()) {
            iocs.add(url.group());
        }
        Matcher flag = Pattern.compile("(?:flag|ctf)\\{[^}\\s]{1,200}}").matcher(text);
        while (flag.find()) {
            iocs.add(flag.group());
        }
        Matcher jwt = Pattern.compile("[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*").matcher(text);
        while (jwt.find()) {
            try {
                JwtAnalysisService.analyze(jwt.group());
                iocs.add(jwt.group());
            } catch (Exception ignored) {
            }
        }
    }

    private static String tlsSni(byte[] data) {
        try {
            if (data.length < 5 || (data[0] & 0xFF) != 22 || data[5] != 1) {
                return null;
            }
            int offset = 5 + 4 + 2 + 32;
            int sessionLength = data[offset++] & 0xFF;
            offset += sessionLength;
            int cipherLength = u16(data, offset);
            offset += 2 + cipherLength;
            int compressionLength = data[offset++] & 0xFF;
            offset += compressionLength;
            int extensionsLength = u16(data, offset);
            offset += 2;
            int end = Math.min(data.length, offset + extensionsLength);
            while (offset + 4 <= end) {
                int type = u16(data, offset);
                int length = u16(data, offset + 2);
                offset += 4;
                if (type == 0 && offset + 5 <= end) {
                    int nameType = data[offset + 2] & 0xFF;
                    int nameLength = u16(data, offset + 3);
                    if (nameType == 0 && offset + 5 + nameLength <= end) {
                        return new String(data, offset + 5, nameLength, StandardCharsets.ISO_8859_1);
                    }
                }
                offset += length;
            }
        } catch (Exception ignored) {
        }
        for (int i = 5; i + 9 < data.length; i++) {
            if (u16(data, i) != 0 || (data[i + 6] & 0xFF) != 0) {
                continue;
            }
            int nameLength = u16(data, i + 7);
            if (nameLength > 0 && i + 9 + nameLength <= data.length) {
                String host = new String(data, i + 9, nameLength, StandardCharsets.ISO_8859_1);
                if (host.matches("[A-Za-z0-9._-]+")) {
                    return host;
                }
            }
        }
        return null;
    }

    private static byte[] gunzip(byte[] input) throws Exception {
        try (GZIPInputStream gzip = new GZIPInputStream(new ByteArrayInputStream(input))) {
            return gzip.readAllBytes();
        }
    }

    private static byte[] inflate(byte[] input) throws Exception {
        Inflater inflater = new Inflater();
        inflater.setInput(input);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        while (!inflater.finished()) {
            int count = inflater.inflate(buffer);
            if (count == 0 && inflater.needsInput()) {
                throw new IllegalArgumentException("Truncated deflate stream");
            }
            output.write(buffer, 0, count);
        }
        inflater.end();
        return output.toByteArray();
    }

    private static double entropy(byte[] data) {
        int[] counts = new int[256];
        for (byte value : data) {
            counts[value & 0xFF]++;
        }
        double entropy = 0;
        for (int count : counts) {
            if (count > 0) {
                double p = (double) count / data.length;
                entropy -= p * Math.log(p) / Math.log(2);
            }
        }
        return entropy;
    }

    private static void add(List<AutoAnalysisService.Finding> findings, String source, String method,
                            String evidence, double score) {
        findings.add(new AutoAnalysisService.Finding(source, method, evidence, score));
    }

    private static String preview(String text) {
        return text.replace("\r", " ").replace("\n", " ");
    }

    private static int u16(byte[] data, int offset) {
        return (data[offset] & 0xFF) << 8 | (data[offset + 1] & 0xFF);
    }
}
