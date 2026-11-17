package myxfc.App.View.Modules.Tools.CTF.Engine.Decode;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JwtAnalysisService {
    private static final Pattern TOKEN = Pattern.compile("(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*");

    public record Report(String token, String header, String payload, List<String> issues) {
        @Override
        public String toString() {
            return "Token: " + token + "\nHeader: " + header + "\nPayload: " + payload
                    + "\nIssues: " + (issues.isEmpty() ? "none" : String.join("; ", issues));
        }
    }

    public static List<Report> find(String text) {
        List<Report> result = new ArrayList<>();
        Matcher matcher = TOKEN.matcher(text);
        while (matcher.find()) {
            try {
                result.add(analyze(matcher.group()));
            } catch (Exception ignored) {
            }
        }
        return result;
    }

    public static Report analyze(String token) {
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) {
            throw new IllegalArgumentException("JWT must have three segments");
        }
        String header = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        if (!header.trim().startsWith("{") || !payload.trim().startsWith("{")) {
            throw new IllegalArgumentException("Invalid JWT JSON");
        }
        List<String> issues = new ArrayList<>();
        String algorithm = claim(header, "alg");
        if (algorithm.equalsIgnoreCase("none")) {
            issues.add("HIGH: alg=none allows unsigned tokens");
        }
        if (parts[2].isEmpty() && !algorithm.equalsIgnoreCase("none")) {
            issues.add("HIGH: signature is empty");
        }
        String expiration = numericClaim(payload, "exp");
        if (expiration == null) {
            issues.add("MEDIUM: exp is missing");
        } else if (Long.parseLong(expiration) < Instant.now().getEpochSecond()) {
            issues.add("MEDIUM: token is expired");
        }
        String notBefore = numericClaim(payload, "nbf");
        if (notBefore != null && Long.parseLong(notBefore) > Instant.now().getEpochSecond()) {
            issues.add("MEDIUM: token is not valid yet");
        }
        if (payload.matches("(?i).*(password|passwd|secret|private[_-]?key|credit[_-]?card).*")) {
            issues.add("HIGH: payload may contain sensitive data");
        }
        return new Report(token, header, payload, issues);
    }

    private static String claim(String json, String name) {
        Matcher matcher = Pattern.compile("\\\"" + name + "\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"").matcher(json);
        return matcher.find() ? matcher.group(1) : "";
    }

    private static String numericClaim(String json, String name) {
        Matcher matcher = Pattern.compile("\\\"" + name + "\\\"\\s*:\\s*(\\d+)").matcher(json);
        return matcher.find() ? matcher.group(1) : null;
    }
}
