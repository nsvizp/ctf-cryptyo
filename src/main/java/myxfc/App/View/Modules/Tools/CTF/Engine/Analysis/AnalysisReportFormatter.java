package myxfc.App.View.Modules.Tools.CTF.Engine.Analysis;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class AnalysisReportFormatter {
    private static final List<String> CATEGORY_ORDER = List.of(
            "Summary", "Flags / Secrets", "SQL Injection", "XSS", "Path Traversal / File Inclusion",
            "Command / Code Execution", "Authentication / JWT / Tokens", "HTTP", "DNS", "TLS",
            "TCP", "UDP", "ICMP", "Image / LSB", "Image / Palette & Pixels", "Image / DWT",
            "Image / Structure", "Archive / ZIP", "Audio / WAV & LSB", "Audio / DTMF",
            "Document / PDF", "Document / Office", "File Structure", "Encoding / Text", "Other");

    private AnalysisReportFormatter() {
    }

    public static String format(List<AutoAnalysisService.Finding> findings) {
        if (findings == null || findings.isEmpty()) {
            return "No supported payload found";
        }
        List<AutoAnalysisService.Finding> ordered = new ArrayList<>(findings);
        ordered.sort(Comparator.comparingDouble(AutoAnalysisService.Finding::score).reversed());
        Map<String, List<AutoAnalysisService.Finding>> groups = new LinkedHashMap<>();
        for (AutoAnalysisService.Finding finding : ordered) {
            groups.computeIfAbsent(category(finding), ignored -> new ArrayList<>()).add(finding);
        }
        List<String> categories = new ArrayList<>(groups.keySet());
        categories.sort(Comparator.comparingInt(AnalysisReportFormatter::categoryRank).thenComparing(String::compareTo));
        StringBuilder output = new StringBuilder();
        for (String category : categories) {
            List<AutoAnalysisService.Finding> group = groups.get(category);
            output.append("===== ").append(category).append(" (").append(group.size()).append(") =====\n");
            for (AutoAnalysisService.Finding finding : group) {
                output.append(finding).append("\n\n");
            }
        }
        return output.toString().trim();
    }

    private static String category(AutoAnalysisService.Finding finding) {
        String source = finding.source().toLowerCase();
        String method = finding.method().toLowerCase();
        String text = source + " " + method;
        if (method.contains("executive summary") || source.equals("capture") || source.equals("pcap")) {
            return "Summary";
        }
        if (method.contains("flag candidate") || method.contains("flag{") || method.contains("ctf{")) {
            return "Flags / Secrets";
        }
        if (text.contains("sql injection") || text.contains("sql destructive") || text.contains("sql command")) {
            return "SQL Injection";
        }
        if (text.contains("xss")) {
            return "XSS";
        }
        if (text.contains("path traversal") || text.contains("file inclusion")) {
            return "Path Traversal / File Inclusion";
        }
        if (text.contains("command injection") || text.contains("code execution") || text.contains("file upload")) {
            return "Command / Code Execution";
        }
        if (text.contains("authentication") || text.contains("authorization") || text.contains("credential")
                || text.contains("jwt") || text.contains("token") || text.contains("cookie")
                || text.contains("basic") || text.contains("session")) {
            return "Authentication / JWT / Tokens";
        }
        if (source.startsWith("http")) {
            return "HTTP";
        }
        if (source.startsWith("dns")) {
            return "DNS";
        }
        if (source.startsWith("tls")) {
            return "TLS";
        }
        if (source.startsWith("udp")) {
            return "UDP";
        }
        if (source.startsWith("icmp")) {
            return "ICMP";
        }
        if (source.startsWith("tcp") || source.startsWith("ssh") || source.startsWith("redis")
                || source.startsWith("ftp") || source.startsWith("service")) {
            return "TCP";
        }
        if (source.startsWith("image lsb")) {
            return "Image / LSB";
        }
        if (source.startsWith("palette") || source.startsWith("pixel")) {
            return "Image / Palette & Pixels";
        }
        if (source.startsWith("dwt")) {
            return "Image / DWT";
        }
        if (source.startsWith("image")) {
            return "Image / Structure";
        }
        if (source.startsWith("office")) {
            return "Document / Office";
        }
        if (source.startsWith("pdf")) {
            return "Document / PDF";
        }
        if (source.startsWith("zip") || source.startsWith("archive") || source.startsWith("binwalk")) {
            return "Archive / ZIP";
        }
        if (source.startsWith("dtmf")) {
            return "Audio / DTMF";
        }
        if (source.startsWith("wav") || source.startsWith("audio")) {
            return "Audio / WAV & LSB";
        }
        if (source.startsWith("file") || source.contains("trailing")) {
            return "File Structure";
        }
        if (source.startsWith("text") || method.contains("base") || method.contains("url")
                || method.contains("hex") || method.contains("unicode") || method.contains("html")
                || method.contains("batch")) {
            return "Encoding / Text";
        }
        return "Other";
    }

    private static int categoryRank(String category) {
        int index = CATEGORY_ORDER.indexOf(category);
        return index < 0 ? CATEGORY_ORDER.size() : index;
    }
}
