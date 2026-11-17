package myxfc.App.View.Modules.Tools.CTF.Engine.Analysis;

import myxfc.App.View.Modules.Tools.CTF.Engine.Decode.JwtAnalysisService;
import myxfc.App.View.Modules.Tools.CTF.Engine.Pcap.PcapAnalysisService;
import myxfc.App.View.Modules.Tools.Image.Steganography.Engine.ImageStructureService;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class TrafficAnomalyService {
    public static List<AutoAnalysisService.Finding> analyze(PcapAnalysisService.Capture capture) {
        List<AutoAnalysisService.Finding> result = new ArrayList<>();
        Map<String, Integer> protocols = new LinkedHashMap<>();
        Map<String, Set<Integer>> synPorts = new HashMap<>();
        Map<String, Integer> retransmissions = new HashMap<>();
        Set<String> seenSegments = new HashSet<>();
        for (var packet : capture.packets()) {
            PacketInfo info = packetInfo(packet.data());
            if (info == null) {
                continue;
            }
            protocols.merge(info.protocol, 1, Integer::sum);
            if (info.protocol.equals("TCP")) {
                if ((info.flags & 0x02) != 0 && (info.flags & 0x10) == 0) {
                    synPorts.computeIfAbsent(info.source, ignored -> new HashSet<>()).add(info.destinationPort);
                }
                String segment = info.source + info.destination + info.sourcePort + info.destinationPort
                        + info.sequence + new String(info.payload, StandardCharsets.ISO_8859_1);
                if (!seenSegments.add(segment) && info.payload.length > 0) {
                    retransmissions.merge(info.source + ":" + info.sourcePort + " > "
                            + info.destination + ":" + info.destinationPort, 1, Integer::sum);
                }
            }
            if (info.sourcePort == 53 || info.destinationPort == 53) {
                analyzeDns(info.payload, result);
            }
        }
        add(result, "Capture", "Protocol overview", protocols.toString(), 15);
        synPorts.forEach((source, ports) -> {
            if (ports.size() >= 10) {
                add(result, "TCP", "Possible SYN port scan", source + " contacted " + ports.size()
                        + " ports: " + ports, 85);
            }
        });
        retransmissions.forEach((stream, count) -> add(result, "TCP", "Retransmission", stream + " count=" + count, 30));

        var streams = PcapAnalysisService.tcpStreams(capture);
        var objects = PcapAnalysisService.httpObjects(streams);
        for (var object : objects) {
            analyzeHttp(object, result);
        }
        for (var stream : streams) {
            stream.directions().forEach((direction, data) -> {
                if (data.length == 0) {
                    return;
                }
                String text = new String(data, StandardCharsets.ISO_8859_1);
                if (!text.matches("(?s)^(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|HTTP/).*")) {
                    analyzeSecurityText(direction, text, result);
                }
                if (data.length <= 20_000_000) {
                    for (ImageStructureService.CarvedFile carved : ImageStructureService.carve(data)) {
                        add(result, "TCP Stream", "Embedded file", direction + " offset=" + carved.offset()
                                + " type=" + carved.extension() + " bytes=" + carved.data().length, 90);
                    }
                }
            });
        }
        return result;
    }

    private static void analyzeHttp(PcapAnalysisService.HttpObject object, List<AutoAnalysisService.Finding> result) {
        String uri = object.uri() == null ? "" : object.uri();
        String headers = object.headers().toString();
        String body = new String(object.body(), StandardCharsets.ISO_8859_1);
        String all = uri + "\n" + headers + "\n" + body;
        if (uri.length() > 2048) {
            add(result, "HTTP", "Abnormally long URI", "length=" + uri.length() + " " + preview(uri), 65);
        }
        for (String parameter : uri.split("[?&]")) {
            if (parameter.length() > 512) {
                add(result, "HTTP", "Abnormally long parameter", "length=" + parameter.length(), 65);
            }
        }
        if (object.body().length > 1_000_000) {
            add(result, "HTTP", "Large HTTP body", object.body().length + " bytes " + object.contentType(), 40);
        }
        String authorization = object.headers().getOrDefault("authorization", "");
        if (!authorization.isEmpty()) {
            add(result, "Authentication", "Authorization header", preview(authorization), 75);
        }
        String cookie = object.headers().getOrDefault("cookie", "");
        if (!cookie.isEmpty()) {
            add(result, "Authentication", "Cookie/session data", preview(cookie), 55);
        }
        if (body.matches("(?i).*filename\\s*=\\s*\"?[^\\r\\n\"]+\\.(?:php|jsp|asp|aspx|phtml|sh|py|pl|cgi|exe|dll).*")) {
            add(result, "HTTP", "Suspicious file upload", preview(body), 95);
        }
        analyzeSecurityText(uri + " " + object.status(), all, result);
    }

    private static void analyzeSecurityText(String source, String text, List<AutoAnalysisService.Finding> result) {
        String decoded = text;
        try {
            decoded = URLDecoder.decode(text, StandardCharsets.UTF_8);
        } catch (Exception ignored) {
        }
        String analyzedText = decoded;
        String lower = analyzedText.toLowerCase();
        Map<String, String> signatures = new LinkedHashMap<>();
        signatures.put("union select", "SQL injection UNION SELECT");
        signatures.put("or 1=1", "SQL injection tautology");
        signatures.put("and 1=1", "SQL injection tautology");
        signatures.put("information_schema", "SQL injection schema access");
        signatures.put("drop table", "SQL destructive statement");
        signatures.put("sleep(", "Time-based SQL injection");
        signatures.put("benchmark(", "Time-based SQL injection");
        signatures.put("xp_cmdshell", "SQL command execution");
        signatures.put("<script", "XSS script tag");
        signatures.put("javascript:", "XSS JavaScript URI");
        signatures.put("onerror=", "XSS event handler");
        signatures.put("../", "Path traversal");
        signatures.put("/etc/passwd", "Local file inclusion");
        signatures.put("cmd.exe", "OS command injection");
        signatures.put("system(", "Possible code execution");
        signatures.put("eval(", "Possible code execution");
        signatures.put("base64_decode", "Encoded code execution");
        signatures.put("password=", "Credential parameter");
        signatures.put("passwd=", "Credential parameter");
        signatures.put("access_token", "Access token");
        signatures.put("refresh_token", "Refresh token");
        signatures.put("api_key", "API key");
        signatures.put("flag{", "Flag candidate");
        signatures.put("ctf{", "Flag candidate");
        signatures.forEach((keyword, description) -> {
            if (lower.contains(keyword)) {
                int score = keyword.equals("flag{") || keyword.equals("ctf{") ? 200 : 85;
                add(result, source, description, preview(analyzedText), score);
            }
        });
        for (JwtAnalysisService.Report report : JwtAnalysisService.find(decoded)) {
            add(result, source, "JWT detected", report.toString(),
                    report.issues().stream().anyMatch(issue -> issue.startsWith("HIGH")) ? 120 : 75);
        }
    }

    private static void analyzeDns(byte[] data, List<AutoAnalysisService.Finding> result) {
        if (data.length < 12) {
            return;
        }
        int questions = u16(data, 4);
        int answers = u16(data, 6);
        int offset = 12;
        for (int i = 0; i < questions && offset < data.length; i++) {
            Name name = dnsName(data, offset);
            offset = name.next;
            if (offset + 4 > data.length) {
                return;
            }
            int type = u16(data, offset);
            offset += 4;
            add(result, "DNS", "Query " + dnsType(type), name.value, 25);
            if (name.value.length() > 60 || name.value.matches(".*[A-Za-z0-9_-]{35,}.*")) {
                add(result, "DNS", "Possible encoded/exfiltrated hostname", name.value, 85);
            }
        }
        for (int i = 0; i < answers && offset + 12 <= data.length; i++) {
            Name name = dnsName(data, offset);
            offset = name.next;
            int type = u16(data, offset);
            int length = u16(data, offset + 8);
            offset += 10;
            if (offset + length > data.length) {
                return;
            }
            if (type == 16) {
                int textOffset = offset;
                StringBuilder text = new StringBuilder();
                while (textOffset < offset + length) {
                    int size = data[textOffset++] & 0xFF;
                    if (textOffset + size > offset + length) {
                        break;
                    }
                    text.append(new String(data, textOffset, size, StandardCharsets.ISO_8859_1));
                    textOffset += size;
                }
                add(result, "DNS", "TXT record", name.value + " " + text, 70);
                analyzeSecurityText("DNS TXT", text.toString(), result);
            } else if (type == 1 && length == 4) {
                add(result, "DNS", "A record", name.value + " -> " + (data[offset] & 0xFF) + "."
                        + (data[offset + 1] & 0xFF) + "." + (data[offset + 2] & 0xFF) + "." + (data[offset + 3] & 0xFF), 25);
            }
            offset += length;
        }
    }

    private static Name dnsName(byte[] data, int offset) {
        StringBuilder name = new StringBuilder();
        int next = offset;
        while (next < data.length) {
            int length = data[next++] & 0xFF;
            if (length == 0) {
                break;
            }
            if ((length & 0xC0) == 0xC0) {
                if (next < data.length) {
                    int pointer = ((length & 0x3F) << 8) | (data[next++] & 0xFF);
                    return new Name(name + dnsName(data, pointer).value, next);
                }
                break;
            }
            if (next + length > data.length) {
                break;
            }
            if (!name.isEmpty()) {
                name.append('.');
            }
            name.append(new String(data, next, length, StandardCharsets.ISO_8859_1));
            next += length;
        }
        return new Name(name.toString(), next);
    }

    private static PacketInfo packetInfo(byte[] packet) {
        if (packet.length < 34) {
            return null;
        }
        int ethernet = 14;
        int type = u16(packet, 12);
        if (type == 0x8100) {
            ethernet += 4;
            type = u16(packet, 16);
        }
        if (type != 0x0800 || ethernet + 20 > packet.length) {
            return null;
        }
        int header = (packet[ethernet] & 0xF) * 4;
        int total = Math.min(u16(packet, ethernet + 2), packet.length - ethernet);
        int protocolNumber = packet[ethernet + 9] & 0xFF;
        String protocol = switch (protocolNumber) {
            case 6 -> "TCP";
            case 17 -> "UDP";
            case 1 -> "ICMP";
            default -> "IP-" + protocolNumber;
        };
        String source = ip(packet, ethernet + 12);
        String destination = ip(packet, ethernet + 16);
        int sourcePort = 0;
        int destinationPort = 0;
        long sequence = 0;
        int flags = 0;
        int payloadOffset = ethernet + header;
        if (protocolNumber == 6 && payloadOffset + 20 <= packet.length) {
            sourcePort = u16(packet, payloadOffset);
            destinationPort = u16(packet, payloadOffset + 2);
            sequence = Integer.toUnsignedLong(int32(packet, payloadOffset + 4));
            flags = packet[payloadOffset + 13] & 0xFF;
            payloadOffset += ((packet[payloadOffset + 12] >>> 4) & 0xF) * 4;
        } else if (protocolNumber == 17 && payloadOffset + 8 <= packet.length) {
            sourcePort = u16(packet, payloadOffset);
            destinationPort = u16(packet, payloadOffset + 2);
            payloadOffset += 8;
        }
        int end = Math.min(packet.length, ethernet + total);
        byte[] payload = payloadOffset < end ? java.util.Arrays.copyOfRange(packet, payloadOffset, end) : new byte[0];
        return new PacketInfo(protocol, source, destination, sourcePort, destinationPort, sequence, flags, payload);
    }

    private static String ip(byte[] data, int offset) {
        return (data[offset] & 0xFF) + "." + (data[offset + 1] & 0xFF) + "."
                + (data[offset + 2] & 0xFF) + "." + (data[offset + 3] & 0xFF);
    }

    private static String dnsType(int type) {
        return switch (type) {
            case 1 -> "A";
            case 2 -> "NS";
            case 5 -> "CNAME";
            case 6 -> "SOA";
            case 12 -> "PTR";
            case 15 -> "MX";
            case 16 -> "TXT";
            case 28 -> "AAAA";
            case 255 -> "ANY";
            default -> "TYPE" + type;
        };
    }

    private static String preview(String text) {
        return text.replace("\r", " ").replace("\n", " ");
    }

    private static void add(List<AutoAnalysisService.Finding> result, String source, String method,
                            String evidence, double score) {
        result.add(new AutoAnalysisService.Finding(source, method, evidence, score));
    }

    private static int u16(byte[] data, int offset) {
        return (data[offset] & 0xFF) << 8 | (data[offset + 1] & 0xFF);
    }

    private static int int32(byte[] data, int offset) {
        return (data[offset] & 0xFF) << 24 | (data[offset + 1] & 0xFF) << 16
                | (data[offset + 2] & 0xFF) << 8 | (data[offset + 3] & 0xFF);
    }

    private record PacketInfo(String protocol, String source, String destination, int sourcePort,
                              int destinationPort, long sequence, int flags, byte[] payload) {
    }

    private record Name(String value, int next) {
    }
}
