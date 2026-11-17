package myxfc.App.View.Modules.Tools.CTF.Engine.Audio;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;

public class DtmfDecodeService {
    private static final String[] T9 = {" ", "", "ABC", "DEF", "GHI", "JKL", "MNO", "PQRS", "TUV", "WXYZ"};

    public record Candidate(String encoding, String text, double score) {
    }

    public record AutoResult(int channel, String symbols, List<AudioAnalysisService.DTMF> detections,
                             List<Candidate> candidates) {
    }

    public static AutoResult autoDetect(WavSteganography.WavData wav) {
        int bestChannel = 0;
        double bestScore = -1;
        List<AudioAnalysisService.DTMF> bestDetections = List.of();
        for (int channel = 0; channel < wav.channels(); channel++) {
            List<AudioAnalysisService.DTMF> detections = AudioAnalysisService.detectDTMF(wav, channel);
            double confidence = detections.stream().mapToDouble(AudioAnalysisService.DTMF::confidence).average().orElse(0);
            double score = detections.size() * 10 + confidence;
            if (score > bestScore) {
                bestScore = score;
                bestChannel = channel;
                bestDetections = detections;
            }
        }
        StringBuilder symbols = new StringBuilder();
        bestDetections.forEach(detection -> symbols.append(detection.symbol()));
        return new AutoResult(bestChannel, symbols.toString(), bestDetections, decodeCandidates(symbols.toString()));
    }

    public static List<Candidate> decodeCandidates(String symbols) {
        List<Candidate> candidates = new ArrayList<>();
        candidates.add(new Candidate("DTMF symbols", symbols, 0));
        if (symbols.matches("[0-9A-Fa-f]+") && symbols.length() >= 4 && symbols.length() % 2 == 0) {
            try {
                String text = new String(HexFormat.of().parseHex(symbols), StandardCharsets.UTF_8);
                addIfPrintable(candidates, "HEX bytes", text);
            } catch (Exception ignored) {
            }
        }
        if (symbols.matches("[0-9]+")) {
            if (symbols.length() % 2 == 0) {
                addIfPrintable(candidates, "Decimal ASCII pairs", decimal(symbols, 2));
            }
            if (symbols.length() % 3 == 0) {
                addIfPrintable(candidates, "Decimal ASCII triples", decimal(symbols, 3));
            }
        }
        addIfPrintable(candidates, "Phone T9", t9(symbols));
        candidates.sort(Comparator.comparingDouble(Candidate::score).reversed());
        return candidates;
    }

    private static String decimal(String symbols, int width) {
        StringBuilder output = new StringBuilder();
        for (int offset = 0; offset < symbols.length(); offset += width) {
            int value = Integer.parseInt(symbols.substring(offset, offset + width));
            if (value > 127) {
                return "";
            }
            output.append((char) value);
        }
        return output.toString();
    }

    private static String t9(String symbols) {
        StringBuilder output = new StringBuilder();
        for (int i = 0; i < symbols.length();) {
            char symbol = symbols.charAt(i);
            int end = i + 1;
            while (end < symbols.length() && symbols.charAt(end) == symbol) {
                end++;
            }
            int count = end - i;
            if (symbol == '*') {
                output.append(' ');
            } else if (symbol == '#') {
                output.append('\n');
            } else if (symbol == '1') {
                output.append('.');
            } else if (symbol >= '2' && symbol <= '9') {
                String letters = T9[symbol - '0'];
                output.append(letters.charAt((count - 1) % letters.length()));
            } else if (symbol == '0') {
                output.append(' ');
            }
            i = end;
        }
        return output.toString();
    }

    private static void addIfPrintable(List<Candidate> candidates, String encoding, String text) {
        if (text == null || text.isEmpty()) {
            return;
        }
        int printable = 0;
        for (char c : text.toCharArray()) {
            if (c == 9 || c == 10 || c == 13 || c >= 32 && c < 127) {
                printable++;
            }
        }
        double ratio = (double) printable / text.length();
        if (ratio < 0.75) {
            return;
        }
        double score = ratio * 100;
        String lower = text.toLowerCase();
        if (lower.contains("flag{") || lower.contains("ctf{")) {
            score += 100;
        }
        if (lower.matches(".*\\b(the|flag|this|is|hello|key|password|ctf)\\b.*")) {
            score += 20;
        }
        candidates.add(new Candidate(encoding, text, score));
    }
}
