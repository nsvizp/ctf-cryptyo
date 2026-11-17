package myxfc.App.View.Modules.Tools.CTF.Engine.Pcap;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public class PcapAnalysisService {
    public record Packet(double timestamp, byte[] data) {
    }

    public record Capture(List<Packet> packets, int linkType) {
    }

    public record TcpStream(String key, Map<String, byte[]> directions) {
    }

    public record HttpObject(String method, String uri, String status, String contentType,
                             Map<String, String> headers, byte[] body) {
        public String extension() {
            if (contentType.contains("html")) return "html";
            if (contentType.contains("json")) return "json";
            if (contentType.contains("png")) return "png";
            if (contentType.contains("jpeg")) return "jpg";
            if (contentType.contains("gif")) return "gif";
            if (contentType.contains("pdf")) return "pdf";
            if (contentType.contains("zip")) return "zip";
            return "bin";
        }
    }

    public static Capture read(Path path) throws IOException {
        byte[] bytes = Files.readAllBytes(path);
        if (bytes.length < 12) {
            throw new IOException("Capture file is too short");
        }
        if ((bytes[0] & 0xFF) == 0x0A && (bytes[1] & 0xFF) == 0x0D
                && (bytes[2] & 0xFF) == 0x0D && (bytes[3] & 0xFF) == 0x0A) {
            return readPcapng(bytes);
        }
        ByteOrder order;
        double fraction;
        if (matches(bytes, 0, 0xD4, 0xC3, 0xB2, 0xA1)) {
            order = ByteOrder.LITTLE_ENDIAN;
            fraction = 1_000_000;
        } else if (matches(bytes, 0, 0xA1, 0xB2, 0xC3, 0xD4)) {
            order = ByteOrder.BIG_ENDIAN;
            fraction = 1_000_000;
        } else if (matches(bytes, 0, 0x4D, 0x3C, 0xB2, 0xA1)) {
            order = ByteOrder.LITTLE_ENDIAN;
            fraction = 1_000_000_000;
        } else if (matches(bytes, 0, 0xA1, 0xB2, 0x3C, 0x4D)) {
            order = ByteOrder.BIG_ENDIAN;
            fraction = 1_000_000_000;
        } else {
            throw new IOException("Unsupported pcap format");
        }
        ByteBuffer buffer = ByteBuffer.wrap(bytes).order(order);
        int linkType = buffer.getInt(20);
        List<Packet> packets = new ArrayList<>();
        int offset = 24;
        while (offset + 16 <= bytes.length) {
            int seconds = buffer.getInt(offset);
            int subsecond = buffer.getInt(offset + 4);
            int length = buffer.getInt(offset + 8);
            if (length < 0 || offset + 16L + length > bytes.length) {
                throw new IOException("Truncated pcap packet");
            }
            packets.add(new Packet(seconds + subsecond / fraction,
                    Arrays.copyOfRange(bytes, offset + 16, offset + 16 + length)));
            offset += 16 + length;
        }
        return new Capture(packets, linkType);
    }

    private static Capture readPcapng(byte[] bytes) {
        List<Packet> packets = new ArrayList<>();
        int linkType = 1;
        int offset = 0;
        ByteOrder order = ByteOrder.LITTLE_ENDIAN;
        while (offset + 12 <= bytes.length) {
            int type = int32(bytes, offset, order);
            int length = int32(bytes, offset + 4, order);
            if (type == 0x0A0D0D0A) {
                int magic = int32(bytes, offset + 8, ByteOrder.LITTLE_ENDIAN);
                order = magic == 0x1A2B3C4D ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN;
                length = int32(bytes, offset + 4, order);
            }
            if (length < 12 || offset + length > bytes.length) {
                throw new IllegalArgumentException("Invalid pcapng block at offset " + offset
                        + ", type=" + type + ", length=" + length);
            }
            if (type == 1) {
                linkType = uint16(bytes, offset + 8, order);
            } else if (type == 6) {
                long high = Integer.toUnsignedLong(int32(bytes, offset + 12, order));
                long low = Integer.toUnsignedLong(int32(bytes, offset + 16, order));
                int packetLength = int32(bytes, offset + 20, order);
                if (packetLength < 0 || offset + 28L + packetLength > bytes.length) {
                    throw new IllegalArgumentException("Truncated pcapng packet");
                }
                double timestamp = ((high << 32) | low) / 1_000_000.0;
                packets.add(new Packet(timestamp, Arrays.copyOfRange(bytes, offset + 28, offset + 28 + packetLength)));
            }
            offset += length;
        }
        return new Capture(packets, linkType);
    }

    public static List<TcpStream> tcpStreams(Capture capture) {
        Map<String, Map<String, List<Segment>>> grouped = new LinkedHashMap<>();
        for (Packet packet : capture.packets()) {
            Segment segment = tcpSegment(packet.data());
            if (segment == null) {
                continue;
            }
            String forward = segment.source + ":" + segment.sourcePort + " > " + segment.destination + ":" + segment.destinationPort;
            String reverse = segment.destination + ":" + segment.destinationPort + " > " + segment.source + ":" + segment.sourcePort;
            String key = forward.compareTo(reverse) < 0 ? forward + " | " + reverse : reverse + " | " + forward;
            grouped.computeIfAbsent(key, ignored -> new LinkedHashMap<>())
                    .computeIfAbsent(forward, ignored -> new ArrayList<>()).add(segment);
        }
        List<TcpStream> result = new ArrayList<>();
        grouped.forEach((key, directions) -> {
            Map<String, byte[]> assembled = new LinkedHashMap<>();
            directions.forEach((direction, segments) -> assembled.put(direction, assemble(segments)));
            result.add(new TcpStream(key, assembled));
        });
        return result;
    }

    public static List<HttpObject> httpObjects(List<TcpStream> streams) {
        List<HttpObject> result = new ArrayList<>();
        for (TcpStream stream : streams) {
            String requestUri = "";
            for (var direction : stream.directions().entrySet()) {
                byte[] data = direction.getValue();
                if (new String(data, 0, Math.min(16, data.length), StandardCharsets.ISO_8859_1).matches("(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) .*")) {
                    requestUri = requestUri(data);
                }
            }
            for (byte[] data : stream.directions().values()) {
                parseHttp(data, requestUri, result);
            }
        }
        return result;
    }

    public static List<String> udpSummaries(Capture capture) {
        List<String> result = new ArrayList<>();
        for (Packet packet : capture.packets()) {
            UdpDatagram udp = udpDatagram(packet.data());
            if (udp != null) {
                result.add(String.format(Locale.ROOT, "%s:%d > %s:%d length=%d %s", udp.source, udp.sourcePort,
                        udp.destination, udp.destinationPort, udp.payload.length, printable(udp.payload)));
            }
        }
        return result;
    }

    public static String printable(byte[] data) {
        StringBuilder output = new StringBuilder();
        for (byte value : data) {
            int c = value & 0xFF;
            output.append(c >= 32 && c < 127 ? (char) c : '.');
            if (output.length() >= 160) {
                break;
            }
        }
        return output.toString();
    }

    private static void parseHttp(byte[] data, String requestUri, List<HttpObject> result) {
        int offset = 0;
        while (offset + 12 < data.length) {
            int headerEnd = indexOf(data, offset, "\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
            if (headerEnd < 0) {
                return;
            }
            String headerText = new String(data, offset, headerEnd - offset, StandardCharsets.ISO_8859_1);
            String[] lines = headerText.split("\\r\\n");
            String firstLine = lines[0];
            if (!firstLine.startsWith("HTTP/") && !firstLine.matches("(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) .*")) {
                offset = headerEnd + 4;
                continue;
            }
            Map<String, String> headers = new LinkedHashMap<>();
            for (int i = 1; i < lines.length; i++) {
                int colon = lines[i].indexOf(':');
                if (colon > 0) {
                    headers.put(lines[i].substring(0, colon).trim().toLowerCase(), lines[i].substring(colon + 1).trim());
                }
            }
            int bodyStart = headerEnd + 4;
            byte[] body;
            int next;
            if ("chunked".equalsIgnoreCase(headers.getOrDefault("transfer-encoding", ""))) {
                Chunked chunked = decodeChunked(data, bodyStart);
                body = chunked.data;
                next = chunked.end;
            } else {
                int length = headers.containsKey("content-length") ? Integer.parseInt(headers.get("content-length"))
                        : firstLine.startsWith("HTTP/") ? data.length - bodyStart : 0;
                int end = Math.min(data.length, bodyStart + length);
                body = Arrays.copyOfRange(data, bodyStart, end);
                next = end;
            }
            String method = firstLine.startsWith("HTTP/") ? "RESPONSE" : firstLine.split(" ")[0];
            String status = firstLine.startsWith("HTTP/") ? firstLine : "";
            String uri = firstLine.startsWith("HTTP/") ? requestUri : firstLine.split(" ")[1];
            result.add(new HttpObject(method, uri, status, headers.getOrDefault("content-type", ""), headers, body));
            offset = Math.max(next, bodyStart);
        }
    }

    private static String requestUri(byte[] data) {
        String text = new String(data, StandardCharsets.ISO_8859_1);
        int end = text.indexOf("\r\n");
        String first = end < 0 ? text : text.substring(0, end);
        String[] parts = first.split(" ");
        return parts.length >= 2 ? parts[1] : "";
    }

    private record Chunked(byte[] data, int end) {
    }

    private static Chunked decodeChunked(byte[] data, int offset) {
        java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
        while (offset + 5 < data.length) {
            int lineEnd = indexOf(data, offset, "\r\n".getBytes(StandardCharsets.ISO_8859_1));
            if (lineEnd < 0) {
                break;
            }
            String sizeText = new String(data, offset, lineEnd - offset, StandardCharsets.ISO_8859_1).split(";")[0];
            int size = Integer.parseInt(sizeText.trim(), 16);
            offset = lineEnd + 2;
            if (size == 0) {
                return new Chunked(output.toByteArray(), offset + 2);
            }
            if (offset + size > data.length) {
                break;
            }
            output.write(data, offset, size);
            offset += size + 2;
        }
        return new Chunked(output.toByteArray(), offset);
    }

    private static byte[] assemble(List<Segment> segments) {
        if (segments.isEmpty()) {
            return new byte[0];
        }
        List<Segment> sorted = new ArrayList<>(segments);
        sorted.sort(Comparator.comparingLong(segment -> segment.sequence));
        long expected = sorted.get(0).sequence;
        java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
        for (Segment segment : sorted) {
            if (segment.payload.length == 0 || segment.sequence + segment.payload.length <= expected) {
                continue;
            }
            int skip = (int) Math.max(0, expected - segment.sequence);
            output.write(segment.payload, skip, segment.payload.length - skip);
            expected = segment.sequence + segment.payload.length;
        }
        return output.toByteArray();
    }

    private record Segment(String source, String destination, int sourcePort, int destinationPort,
                           long sequence, byte[] payload) {
    }

    private record UdpDatagram(String source, String destination, int sourcePort, int destinationPort, byte[] payload) {
    }

    private static Segment tcpSegment(byte[] packet) {
        int[] ip = ipPacket(packet);
        if (ip == null || packet[ip[0] + 9] != 6) {
            return null;
        }
        int start = ip[0] + ip[1];
        if (start + 20 > packet.length) {
            return null;
        }
        int sourcePort = uint16(packet, start, ByteOrder.BIG_ENDIAN);
        int destinationPort = uint16(packet, start + 2, ByteOrder.BIG_ENDIAN);
        long sequence = Integer.toUnsignedLong(int32(packet, start + 4, ByteOrder.BIG_ENDIAN));
        int headerLength = ((packet[start + 12] >>> 4) & 0xF) * 4;
        int payloadStart = start + headerLength;
        int end = Math.min(packet.length, ip[0] + ip[2]);
        if (payloadStart > end) {
            return null;
        }
        return new Segment(ipAddress(packet, ip[0] + 12), ipAddress(packet, ip[0] + 16), sourcePort, destinationPort,
                sequence, Arrays.copyOfRange(packet, payloadStart, end));
    }

    private static UdpDatagram udpDatagram(byte[] packet) {
        int[] ip = ipPacket(packet);
        if (ip == null || packet[ip[0] + 9] != 17) {
            return null;
        }
        int start = ip[0] + ip[1];
        if (start + 8 > packet.length) {
            return null;
        }
        int length = uint16(packet, start + 4, ByteOrder.BIG_ENDIAN);
        int end = Math.min(packet.length, start + length);
        return new UdpDatagram(ipAddress(packet, ip[0] + 12), ipAddress(packet, ip[0] + 16),
                uint16(packet, start, ByteOrder.BIG_ENDIAN), uint16(packet, start + 2, ByteOrder.BIG_ENDIAN),
                Arrays.copyOfRange(packet, start + 8, end));
    }

    private static int[] ipPacket(byte[] packet) {
        if (packet.length < 34) {
            return null;
        }
        int ethernet = 14;
        int type = uint16(packet, 12, ByteOrder.BIG_ENDIAN);
        if (type == 0x8100) {
            ethernet += 4;
            type = uint16(packet, 16, ByteOrder.BIG_ENDIAN);
        }
        if (type != 0x0800 || ethernet + 20 > packet.length) {
            return null;
        }
        int headerLength = (packet[ethernet] & 0xF) * 4;
        int totalLength = uint16(packet, ethernet + 2, ByteOrder.BIG_ENDIAN);
        int fragment = uint16(packet, ethernet + 6, ByteOrder.BIG_ENDIAN) & 0x1FFF;
        if (headerLength < 20 || totalLength < headerLength || fragment != 0) {
            return null;
        }
        return new int[]{ethernet, headerLength, Math.min(totalLength, packet.length - ethernet)};
    }

    private static String ipAddress(byte[] data, int offset) {
        return (data[offset] & 0xFF) + "." + (data[offset + 1] & 0xFF) + "."
                + (data[offset + 2] & 0xFF) + "." + (data[offset + 3] & 0xFF);
    }

    private static int indexOf(byte[] data, int start, byte[] target) {
        for (int i = Math.max(0, start); i + target.length <= data.length; i++) {
            if (matches(data, i, target)) {
                return i;
            }
        }
        return -1;
    }

    private static boolean matches(byte[] data, int offset, int... values) {
        if (offset + values.length > data.length) {
            return false;
        }
        for (int i = 0; i < values.length; i++) {
            if ((data[offset + i] & 0xFF) != values[i]) {
                return false;
            }
        }
        return true;
    }

    private static boolean matches(byte[] data, int offset, byte[] target) {
        if (offset + target.length > data.length) {
            return false;
        }
        for (int i = 0; i < target.length; i++) {
            if (data[offset + i] != target[i]) {
                return false;
            }
        }
        return true;
    }

    private static int uint16(byte[] data, int offset, ByteOrder order) {
        return order == ByteOrder.LITTLE_ENDIAN ? (data[offset] & 0xFF) | (data[offset + 1] & 0xFF) << 8
                : (data[offset] & 0xFF) << 8 | (data[offset + 1] & 0xFF);
    }

    private static int int32(byte[] data, int offset, ByteOrder order) {
        return order == ByteOrder.LITTLE_ENDIAN ? (data[offset] & 0xFF) | (data[offset + 1] & 0xFF) << 8
                | (data[offset + 2] & 0xFF) << 16 | (data[offset + 3] & 0xFF) << 24
                : (data[offset] & 0xFF) << 24 | (data[offset + 1] & 0xFF) << 16
                | (data[offset + 2] & 0xFF) << 8 | (data[offset + 3] & 0xFF);
    }
}
