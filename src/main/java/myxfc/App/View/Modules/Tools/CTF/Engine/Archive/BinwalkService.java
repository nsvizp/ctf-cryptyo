package myxfc.App.View.Modules.Tools.CTF.Engine.Archive;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class BinwalkService {
    public record Result(boolean success, String output) {
    }

    public static boolean available() {
        return executable() != null;
    }

    public static String status() {
        String executable = executable();
        return executable == null ? "binwalk: not installed" : "binwalk: " + executable;
    }

    public static Result extract(Path input, Path outputDirectory) {
        String executable = executable();
        if (executable == null) {
            return new Result(false, "binwalk is not installed. Install binwalk and Python 3, then retry.");
        }
        try {
            Files.createDirectories(outputDirectory);
            Process process = new ProcessBuilder(executable, "-e", "-C", outputDirectory.toString(), input.toString())
                    .redirectErrorStream(true).start();
            if (!process.waitFor(180, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                return new Result(false, "binwalk timed out");
            }
            String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            return new Result(process.exitValue() == 0, output);
        } catch (IOException e) {
            return new Result(false, e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new Result(false, "binwalk interrupted");
        }
    }

    private static String executable() {
        for (String directory : List.of("/opt/homebrew/bin", "/Volumes/safe/Homebrew/bin", "/usr/local/bin", "/usr/bin")) {
            Path candidate = Path.of(directory, "binwalk");
            if (Files.isRegularFile(candidate) && Files.isExecutable(candidate)) {
                return candidate.toString();
            }
        }
        String path = System.getenv("PATH");
        if (path != null) {
            for (String directory : path.split(":")) {
                Path candidate = Path.of(directory, "binwalk");
                if (Files.isRegularFile(candidate) && Files.isExecutable(candidate)) {
                    return candidate.toString();
                }
            }
        }
        return null;
    }
}
