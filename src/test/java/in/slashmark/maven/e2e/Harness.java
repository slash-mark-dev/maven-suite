package in.slashmark.maven.e2e;

import in.slashmark.maven.Main;
import in.slashmark.maven.mock.FixtureData;
import in.slashmark.maven.mock.Fixtures;
import in.slashmark.maven.mock.MockServer;
import in.slashmark.maven.util.Env;
import in.slashmark.maven.util.Json;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * End-to-end test harness: builds the fixture repository, starts the mock services, copies and
 * compiles the planted-problem project, and runs sm-maven commands in-process against it.
 */
public final class Harness implements AutoCloseable {
    public final Path root;
    public final Fixtures fx;
    public final MockServer mock;
    /** The fixture project's pom.xml (multi-module: app + lib). */
    public final Path project;
    public final Path home;
    public final Map<String, String> env;
    public int passed, failed;
    public final List<String> failures = new ArrayList<>();
    public String group = "";

    private Harness(Path root) throws Exception {
        this.root = root;
        fx = new Fixtures(root);
        FixtureData.build(fx);
        mock = new MockServer(fx);
        home = root.resolve("home");
        Files.createDirectories(home);
        env = new LinkedHashMap<>(mock.env(home));
        // Copy and compile the fixture project.
        Path src = Path.of("tests/fixture-project");
        Path dst = root.resolve("shop");
        copy(src, dst);
        project = dst.resolve("pom.xml");
        fx.compileInto(dst.resolve("app/src/main/java"), dst.resolve("app/target/classes"),
                List.of("org.apache.logging.log4j:log4j-api:2.14.1", "com.acme:acme-core:1.0.0", "javax.xml.bind:jaxb-api:2.3.1"), "11");
        fx.compileInto(dst.resolve("lib/src/main/java"), dst.resolve("lib/target/classes"), List.of("com.google.guava:guava:31.1-jre"), "11");
    }

    public static Harness start() throws Exception {
        return new Harness(Files.createTempDirectory("sm-maven-e2e"));
    }

    static void copy(Path src, Path dst) throws IOException {
        try (var s = Files.walk(src)) {
            for (Path p : (Iterable<Path>) s::iterator) {
                Path t = dst.resolve(src.relativize(p).toString());
                if (Files.isDirectory(p)) Files.createDirectories(t);
                else Files.copy(p, t, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
        }
    }

    public static final class Result {
        public final int code;
        public final String out, err;

        Result(int code, String out, String err) {
            this.code = code;
            this.out = out;
            this.err = err;
        }

        /** stdout parsed as JSON (null when it is not JSON). */
        public Object json() {
            try {
                return Json.parse(out.trim());
            } catch (IllegalArgumentException e) {
                return null;
            }
        }

        /** NDJSON documents (one per line), for watch loops. */
        public List<Object> jsonLines() {
            List<Object> l = new ArrayList<>();
            StringBuilder cur = new StringBuilder();
            int depth = 0;
            boolean inStr = false, esc = false;
            for (char c : out.toCharArray()) {
                cur.append(c);
                if (inStr) {
                    if (esc) esc = false;
                    else if (c == '\\') esc = true;
                    else if (c == '"') inStr = false;
                    continue;
                }
                if (c == '"') inStr = true;
                else if (c == '{' || c == '[') depth++;
                else if (c == '}' || c == ']') {
                    depth--;
                    if (depth == 0) {
                        l.add(Json.parse(cur.toString().trim()));
                        cur.setLength(0);
                    }
                }
            }
            return l;
        }

        public boolean has(String s) { return out.contains(s) || err.contains(s); }

        @Override
        public String toString() { return "exit " + code + "\n--- stdout\n" + out + "\n--- stderr\n" + err; }
    }

    /** Runs sm-maven with the harness environment. */
    public Result run(String... args) { return runWith(Map.of(), args); }

    public Result runWith(Map<String, String> extraEnv, String... args) {
        Map<String, String> e = new LinkedHashMap<>(env);
        e.putAll(extraEnv);
        ByteArrayOutputStream o = new ByteArrayOutputStream(), r = new ByteArrayOutputStream();
        PrintStream out = new PrintStream(o, true, StandardCharsets.UTF_8), err = new PrintStream(r, true, StandardCharsets.UTF_8);
        int code;
        try {
            code = Main.run(args, out, err, new Env(e));
        } catch (Throwable t) {
            t.printStackTrace(err);
            code = 99;
        }
        return new Result(code, o.toString(StandardCharsets.UTF_8), r.toString(StandardCharsets.UTF_8));
    }

    /** Project-relative helper: ["tool", "-f", pom, ...args]. */
    public Result onProject(String tool, String... args) {
        List<String> a = new ArrayList<>();
        a.add(tool);
        a.add("-f");
        a.add(project.toString());
        a.addAll(List.of(args));
        return run(a.toArray(new String[0]));
    }

    public void check(String name, boolean ok, Object detail) {
        if (ok) {
            passed++;
        } else {
            failed++;
            String d = detail == null ? "" : String.valueOf(detail);
            if (d.length() > 4000) d = d.substring(0, 4000) + "...";
            failures.add(group + " :: " + name + "\n" + d);
            System.out.println("  FAIL " + group + " :: " + name);
        }
    }

    /** POSTs JSON to the mock (admin endpoints). */
    public void post(String path, Object body) throws Exception {
        HttpClient c = HttpClient.newHttpClient();
        HttpResponse<String> r = c.send(HttpRequest.newBuilder(URI.create(mock.base() + path))
                .POST(HttpRequest.BodyPublishers.ofString(Json.write(body, false))).header("Content-Type", "application/json").build(),
                HttpResponse.BodyHandlers.ofString());
        if (r.statusCode() != 200) throw new IOException("mock admin call failed: " + r.body());
    }

    public Object hookLog() throws Exception {
        HttpClient c = HttpClient.newHttpClient();
        return Json.parse(c.send(HttpRequest.newBuilder(URI.create(mock.base() + "/hooks/_log")).build(), HttpResponse.BodyHandlers.ofString()).body());
    }

    public void clearHooks() throws Exception {
        HttpClient c = HttpClient.newHttpClient();
        c.send(HttpRequest.newBuilder(URI.create(mock.base() + "/hooks/_log")).DELETE().build(), HttpResponse.BodyHandlers.ofString());
    }

    @Override
    public void close() { mock.close(); }
}
