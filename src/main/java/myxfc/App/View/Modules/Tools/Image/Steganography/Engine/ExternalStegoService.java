package myxfc.App.View.Modules.Tools.Image.Steganography.Engine;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class ExternalStegoService {
    public record Result(boolean success, String output) {
    }

    public static String toolStatus(String tool) {
        String executable = executable(tool);
        if (executable == null) {
            return tool + ": not installed (install with: brew install " + tool + ")";
        }
        Result version = run(List.of(executable, "--version"), 15);
        return tool + ": " + executable + "\n" + version.output();
    }

    public static Result steghideEmbed(Path cover, Path payload, Path output, String passphrase) {
        String tool = requireTool("steghide");
        return run(List.of(tool, "embed", "-cf", cover.toString(), "-ef", payload.toString(),
                "-p", passphrase, "-sf", output.toString(), "-f"), 120);
    }

    public static Result steghideExtract(Path input, Path output, String passphrase) {
        String tool = requireTool("steghide");
        return run(List.of(tool, "extract", "-sf", input.toString(), "-xf", output.toString(),
                "-p", passphrase, "-f"), 120);
    }

    public static Result outguessEmbed(Path cover, Path payload, Path output, String passphrase) {
        String tool = requireTool("outguess");
        return run(List.of(tool, "-k", passphrase, "-d", payload.toString(),
                cover.toString(), output.toString()), 120);
    }

    public static Result outguessExtract(Path input, Path output, String passphrase) {
        String tool = requireTool("outguess");
        return run(List.of(tool, "-r", "-k", passphrase, input.toString(), output.toString()), 120);
    }

    private static String requireTool(String tool) {
        String executable = executable(tool);
        if (executable == null) {
            throw new IllegalStateException(tool + " is not installed. Install it with: brew install " + tool);
        }
        return executable;
    }

    private static String executable(String tool) {
        List<String> candidates = new ArrayList<>();
        candidates.add("/opt/homebrew/bin/" + tool);
        candidates.add("/Volumes/safe/Homebrew/bin/" + tool);
        candidates.add("/usr/local/bin/" + tool);
        String path = System.getenv("PATH");
        if (path != null) {
            for (String directory : path.split(":")) {
                candidates.add(directory + "/" + tool);
            }
        }
        for (String candidate : candidates) {
            Path pathCandidate = Path.of(candidate);
            if (Files.isRegularFile(pathCandidate) && Files.isExecutable(pathCandidate)) {
                return pathCandidate.toAbsolutePath().toString();
            }
        }
        return null;
    }

    private static Result run(List<String> command, long timeoutSeconds) {
        try {
            Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
            if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                return new Result(false, "Command timed out: " + String.join(" ", command));
            }
            String output;
            try (var stream = process.getInputStream()) {
                output = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
            }
            return new Result(process.exitValue() == 0, output);
        } catch (IOException e) {
            return new Result(false, e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new Result(false, "Command interrupted");
        }
    }
}
