package crypto;

import myxfc.App.View.Modules.Tools.CTF.Engine.Analysis.AnalysisReportFormatter;
import myxfc.App.View.Modules.Tools.CTF.Engine.Analysis.AutoAnalysisService.Finding;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

class AnalysisReportFormatterTest {
    @Test
    void groupsTrafficByAttackProtocolAndAuthentication() {
        String report = AnalysisReportFormatter.format(List.of(
                new Finding("TCP stream", "Stream payload", "tcp-data", 20),
                new Finding("UDP", "Datagram", "udp-data", 20),
                new Finding("HTTP", "GET /login", "http-data", 30),
                new Finding("/search", "SQL injection UNION SELECT", "union select", 85),
                new Finding("HTTP", "JWT analysis", "jwt-data", 110),
                new Finding("DNS", "Query A", "example.com", 25)));

        assertSectionContains(report, "TCP", "tcp-data");
        assertSectionContains(report, "UDP", "udp-data");
        assertSectionContains(report, "HTTP", "http-data");
        assertSectionContains(report, "SQL Injection", "union select");
        assertSectionContains(report, "Authentication / JWT / Tokens", "jwt-data");
        assertSectionContains(report, "DNS", "example.com");
    }

    @Test
    void groupsAutomaticFileAnalysisByContentType() {
        String report = AnalysisReportFormatter.format(List.of(
                new Finding("Image LSB", "RGB", "image-data", 80),
                new Finding("ZIP", "Entries", "zip-data", 20),
                new Finding("DTMF", "HEX", "audio-data", 60),
                new Finding("PDF", "Structure", "pdf-data", 20),
                new Finding("Office", "Macros", "office-data", 90)));

        assertSectionContains(report, "Image / LSB", "image-data");
        assertSectionContains(report, "Archive / ZIP", "zip-data");
        assertSectionContains(report, "Audio / DTMF", "audio-data");
        assertSectionContains(report, "Document / PDF", "pdf-data");
        assertSectionContains(report, "Document / Office", "office-data");
    }

    private static void assertSectionContains(String report, String section, String evidence) {
        String header = "===== " + section + " ";
        int start = report.indexOf(header);
        assertTrue(start >= 0, report);
        int end = report.indexOf("===== ", start + header.length());
        String body = end < 0 ? report.substring(start) : report.substring(start, end);
        assertTrue(body.contains(evidence), report);
    }
}
