package in.slashmark.maven.watch;

import in.slashmark.maven.util.Hash;
import in.slashmark.maven.util.Json;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Small persistent JSON documents for watch tools (what was already seen/alerted) and snapshots
 * (drift baselines). Stored under the config folder, keyed by tool and by project.
 */
public final class State {
    private final Path file;
    private Map<String, Object> data;

    public State(Path file) { this.file = file; }

    /** State for a tool and a scope (usually the project path or coordinates). */
    public static State of(Path configDir, String tool, String scope) {
        String key = Hash.sha256Hex(scope.getBytes(StandardCharsets.UTF_8)).substring(0, 16);
        return new State(configDir.resolve("state").resolve(tool).resolve(key + ".json"));
    }

    public Path file() { return file; }

    public boolean exists() { return Files.isRegularFile(file); }

    @SuppressWarnings("unchecked")
    public Map<String, Object> data() {
        if (data != null) return data;
        data = new LinkedHashMap<>();
        if (Files.isRegularFile(file)) {
            try {
                Object o = Json.parse(Files.readString(file, StandardCharsets.UTF_8));
                if (o instanceof Map) data = (Map<String, Object>) o;
            } catch (IOException | IllegalArgumentException e) {
                // corrupt state is treated as empty; it will be rewritten
            }
        }
        return data;
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> map(String key) {
        Object o = data().get(key);
        if (o instanceof Map) return (Map<String, Object>) o;
        Map<String, Object> m = new LinkedHashMap<>();
        data().put(key, m);
        return m;
    }

    public void save() throws IOException {
        Files.createDirectories(file.getParent());
        Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
        Files.writeString(tmp, Json.write(data()), StandardCharsets.UTF_8);
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    public void reset() throws IOException {
        data = new LinkedHashMap<>();
        Files.deleteIfExists(file);
    }
}
