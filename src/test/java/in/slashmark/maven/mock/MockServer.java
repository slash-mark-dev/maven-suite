package in.slashmark.maven.mock;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import in.slashmark.maven.data.Osv;
import in.slashmark.maven.model.MavenVersion;
import in.slashmark.maven.util.Json;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;

/**
 * Local stand-in for every live service the suite talks to, backed by {@link Fixtures}:
 *   /maven2/           Maven Central layout (also /mirror/maven2 with latency, /flaky/maven2 returning 503,
 *                      /secure/maven2 requiring basic auth deploy:s3cret)
 *   /search/solrsearch Central search API
 *   /osv/v1/...        OSV querybatch, query, vulns/{id}
 *   /kev.json          CISA KEV catalog
 *   /epss              FIRST EPSS API
 *   /depsdev/v3...     deps.dev versions, version, dependents (v3alpha), projects
 *   /github/...        GitHub REST (repos, releases, commits, trees, contents, org repos)
 *   /javadoc/doc/...   javadoc.io pages
 *   /hooks/{name}      webhook sink (GET /hooks/_log lists received payloads)
 *   /_admin/publish    publish a new version at runtime (JSON body: gav, deps, license, key)
 *   /_admin/advisory   add an advisory at runtime (JSON body: OSV record)
 */
public final class MockServer implements AutoCloseable {
    public final Fixtures fx;
    private final HttpServer server;
    public final int port;
    public final List<Map<String, Object>> hooks = new CopyOnWriteArrayList<>();
    public volatile int requests;

    public MockServer(Fixtures fx) throws IOException {
        this.fx = fx;
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(Executors.newFixedThreadPool(16));
        server.createContext("/", this::handle);
        server.start();
        port = server.getAddress().getPort();
    }

    public String base() { return "http://127.0.0.1:" + port; }

    /** Environment variables pointing the suite at this server. */
    public Map<String, String> env(Path home) {
        Map<String, String> e = new LinkedHashMap<>();
        e.put("SM_MAVEN_CENTRAL", base() + "/maven2");
        e.put("SM_MAVEN_SEARCH", base() + "/search");
        e.put("SM_MAVEN_OSV", base() + "/osv");
        e.put("SM_MAVEN_KEV", base() + "/kev.json");
        e.put("SM_MAVEN_EPSS", base() + "/epss");
        e.put("SM_MAVEN_DEPSDEV", base() + "/depsdev");
        e.put("SM_MAVEN_GITHUB", base() + "/github");
        e.put("SM_MAVEN_JAVADOC", base() + "/javadoc");
        e.put("SM_MAVEN_HOME", home.toString());
        e.put("SM_MAVEN_CACHE", home.resolve("cache").toString());
        e.put("SM_MAVEN_CONFIG", home.resolve("config").toString());
        e.put("SM_MAVEN_LOCAL_REPO", home.resolve("m2").toString());
        e.put("SM_MAVEN_SETTINGS", home.resolve("settings.xml").toString());
        e.put("NO_COLOR", "1");
        return e;
    }

    @Override
    public void close() { server.stop(0); }

    private void handle(HttpExchange ex) throws IOException {
        requests++;
        try {
            String path = ex.getRequestURI().getRawPath();
            String query = ex.getRequestURI().getRawQuery();
            Map<String, String> q = parseQuery(query);
            if (path.startsWith("/maven2/")) { repo(ex, path.substring(8)); return; }
            if (path.startsWith("/mirror/maven2/")) { Thread.sleep(250); repo(ex, path.substring(15)); return; }
            if (path.startsWith("/flaky/maven2/")) { send(ex, 503, "text/plain", "Service Unavailable"); return; }
            if (path.startsWith("/secure/maven2/")) {
                String auth = ex.getRequestHeaders().getFirst("Authorization");
                String want = "Basic " + Base64.getEncoder().encodeToString("deploy:s3cret".getBytes(StandardCharsets.UTF_8));
                if (!want.equals(auth)) { send(ex, 401, "text/plain", "Unauthorized"); return; }
                repo(ex, path.substring(15));
                return;
            }
            if (path.equals("/search/solrsearch/select")) { search(ex, q); return; }
            if (path.startsWith("/osv/")) { osv(ex, path.substring(4)); return; }
            if (path.equals("/kev.json")) {
                sendJson(ex, 200, Json.obj("title", "CISA Catalog of Known Exploited Vulnerabilities", "catalogVersion", "2026.10.24", "count", FixtureData.KEV.size(), "vulnerabilities", FixtureData.KEV));
                return;
            }
            if (path.equals("/epss")) { epss(ex, q); return; }
            if (path.startsWith("/depsdev/")) { depsDev(ex, path.substring(8)); return; }
            if (path.startsWith("/github/")) { github(ex, path.substring(7), q); return; }
            if (path.startsWith("/javadoc/doc/")) {
                String key = path.substring(13);
                if (key.endsWith("/")) key = key.substring(0, key.length() - 1);
                send(ex, FixtureData.JAVADOC.contains(key) ? 200 : 404, "text/html", "<html>" + key + "</html>");
                return;
            }
            if (path.startsWith("/hooks/")) { hooks(ex, path.substring(7)); return; }
            if (path.equals("/_admin/publish")) { adminPublish(ex); return; }
            if (path.equals("/_admin/advisory")) {
                Object rec = Json.parse(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
                FixtureData.ADVISORIES.put(Json.str(rec, "id"), rec);
                sendJson(ex, 200, Json.obj("ok", true));
                return;
            }
            send(ex, 404, "text/plain", "not found: " + path);
        } catch (Exception e) {
            send(ex, 500, "text/plain", "mock error: " + e);
        }
    }

    // ---------------------------------------------------------------- repository

    private void repo(HttpExchange ex, String rel) throws IOException {
        String p = URLDecoder.decode(rel, StandardCharsets.UTF_8);
        if (p.contains("..")) { send(ex, 400, "text/plain", "bad path"); return; }
        Path f = fx.repo.resolve(p);
        if (p.isEmpty() || Files.isDirectory(f)) {
            send(ex, 200, "text/html", "<html><body>index</body></html>");
            return;
        }
        if (!Files.isRegularFile(f)) { send(ex, 404, "text/plain", "Not Found"); return; }
        byte[] b = Files.readAllBytes(f);
        String ct = p.endsWith(".xml") || p.endsWith(".pom") ? "text/xml" : p.endsWith(".jar") ? "application/java-archive" : "text/plain";
        ex.getResponseHeaders().add("Last-Modified", java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME.format(
                java.time.ZonedDateTime.ofInstant(Files.getLastModifiedTime(f).toInstant(), java.time.ZoneOffset.UTC)));
        if ("HEAD".equals(ex.getRequestMethod())) {
            ex.getResponseHeaders().add("Content-Type", ct);
            ex.sendResponseHeaders(200, -1);
            ex.close();
            return;
        }
        send(ex, 200, ct, b);
    }

    // ---------------------------------------------------------------- search

    private void search(HttpExchange ex, Map<String, String> q) throws IOException {
        String query = q.getOrDefault("q", "");
        String core = q.get("core");
        int rows = Integer.parseInt(q.getOrDefault("rows", "20"));
        Map<String, String> terms = new LinkedHashMap<>();
        for (String part : query.split(" AND ")) {
            int c = part.indexOf(':');
            if (c > 0) terms.put(part.substring(0, c).trim(), part.substring(c + 1).trim().replace("\"", ""));
        }
        List<Object> docs = new ArrayList<>();
        if ("gav".equals(core)) {
            for (Map.Entry<String, Long> e : fx.published.entrySet()) {
                String[] gav = e.getKey().split(":");
                if (terms.containsKey("g") && !terms.get("g").equals(gav[0])) continue;
                if (terms.containsKey("a") && !terms.get("a").equals(gav[1])) continue;
                if (terms.containsKey("v") && !terms.get("v").equals(gav[2])) continue;
                docs.add(Json.obj("id", e.getKey(), "g", gav[0], "a", gav[1], "v", gav[2], "p", "jar", "timestamp", e.getValue(), "ec", List.of(".jar", ".pom", "-sources.jar", "-javadoc.jar")));
            }
            docs.sort((x, y) -> Long.compare(Json.num(y, 0, "timestamp"), Json.num(x, 0, "timestamp")));
        } else if (terms.containsKey("1")) {
            // checksum search not modelled: no hits
        } else {
            for (Map.Entry<String, List<String>> e : fx.versions.entrySet()) {
                String[] ga = e.getKey().split(":");
                if (terms.containsKey("g") && !terms.get("g").equals(ga[0])) continue;
                if (terms.containsKey("a") && !terms.get("a").equals(ga[1])) continue;
                List<String> vs = e.getValue();
                String latest = vs.get(vs.size() - 1);
                docs.add(Json.obj("id", e.getKey(), "g", ga[0], "a", ga[1], "latestVersion", latest, "p", "jar",
                        "timestamp", fx.published.getOrDefault(e.getKey() + ":" + latest, 0L), "versionCount", vs.size()));
            }
        }
        long found = docs.size();
        if (docs.size() > rows) docs = docs.subList(0, rows);
        sendJson(ex, 200, Json.obj("responseHeader", Json.obj("status", 0), "response", Json.obj("numFound", found, "start", 0, "docs", docs)));
    }

    // ---------------------------------------------------------------- OSV

    private List<String> vulnsFor(String ga, String version) {
        List<String> out = new ArrayList<>();
        for (Map.Entry<String, Object> e : FixtureData.ADVISORIES.entrySet()) {
            Osv.Vuln v = Osv.parse(e.getValue());
            if (version == null ? v.affected.containsKey(ga) : v.affects(ga, version)) out.add(e.getKey());
        }
        return out;
    }

    private void osv(HttpExchange ex, String p) throws IOException {
        if (p.equals("/v1/querybatch") && "POST".equals(ex.getRequestMethod())) {
            Object body = Json.parse(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            List<Object> results = new ArrayList<>();
            for (Object query : Json.list(body, "queries")) {
                List<Object> vs = new ArrayList<>();
                for (String id : vulnsFor(Json.str(query, "package", "name"), Json.str(query, "version"))) {
                    vs.add(Json.obj("id", id, "modified", Json.str(FixtureData.ADVISORIES.get(id), "modified")));
                }
                results.add(vs.isEmpty() ? Json.obj() : Json.obj("vulns", vs));
            }
            sendJson(ex, 200, Json.obj("results", results));
            return;
        }
        if (p.equals("/v1/query") && "POST".equals(ex.getRequestMethod())) {
            Object body = Json.parse(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            List<Object> vs = new ArrayList<>();
            for (String id : vulnsFor(Json.str(body, "package", "name"), Json.str(body, "version"))) vs.add(FixtureData.ADVISORIES.get(id));
            sendJson(ex, 200, vs.isEmpty() ? Json.obj() : Json.obj("vulns", vs));
            return;
        }
        if (p.startsWith("/v1/vulns/")) {
            String id = URLDecoder.decode(p.substring(10), StandardCharsets.UTF_8);
            Object rec = FixtureData.ADVISORIES.get(id);
            if (rec == null) {
                // CVE ids resolve to the advisory that aliases them
                for (Object r : FixtureData.ADVISORIES.values()) if (Json.list(r, "aliases").contains(id)) { rec = r; break; }
            }
            if (rec == null) sendJson(ex, 404, Json.obj("code", 5, "message", "Bug not found."));
            else sendJson(ex, 200, rec);
            return;
        }
        send(ex, 404, "text/plain", "not found");
    }

    private void epss(HttpExchange ex, Map<String, String> q) throws IOException {
        List<Object> data = new ArrayList<>();
        for (String c : q.getOrDefault("cve", "").split(",")) {
            double[] s = FixtureData.EPSS.get(c.trim());
            if (s != null) data.add(Json.obj("cve", c.trim(), "epss", String.format(java.util.Locale.ROOT, "%.5f", s[0]), "percentile", String.format(java.util.Locale.ROOT, "%.5f", s[1]), "date", "2026-10-23"));
        }
        sendJson(ex, 200, Json.obj("status", "OK", "status-code", 200, "total", data.size(), "data", data));
    }

    // ---------------------------------------------------------------- deps.dev

    private void depsDev(HttpExchange ex, String p) throws IOException {
        // /v3/systems/maven/packages/{name}[/versions/{v}] ; /v3alpha/.../versions/{v}:dependents ; /v3/projects/{id}
        if (p.startsWith("/v3/projects/")) {
            String id = URLDecoder.decode(p.substring(13), StandardCharsets.UTF_8);
            Object pr = FixtureData.PROJECTS.get(id);
            if (pr == null) sendJson(ex, 404, Json.obj("code", 5, "message", "project not found"));
            else sendJson(ex, 200, pr);
            return;
        }
        boolean alpha = p.startsWith("/v3alpha/");
        String rest = p.substring(alpha ? "/v3alpha/systems/maven/packages/".length() : "/v3/systems/maven/packages/".length());
        String name, version = null;
        int vi = rest.indexOf("/versions/");
        if (vi >= 0) {
            name = URLDecoder.decode(rest.substring(0, vi), StandardCharsets.UTF_8);
            version = URLDecoder.decode(rest.substring(vi + 10), StandardCharsets.UTF_8);
        } else name = URLDecoder.decode(rest, StandardCharsets.UTF_8);
        List<String> vs = fx.versions.get(name);
        if (vs == null) { sendJson(ex, 404, Json.obj("code", 5, "message", "package not found")); return; }
        if (version == null) {
            List<Object> list = new ArrayList<>();
            String newest = null;
            for (String v : vs) if (newest == null || MavenVersion.compare(v, newest) > 0) newest = v;
            for (String v : vs) list.add(Json.obj("versionKey", Json.obj("system", "MAVEN", "name", name, "version", v),
                    "publishedAt", java.time.Instant.ofEpochMilli(fx.published.get(name + ":" + v)).toString(), "isDefault", v.equals(newest)));
            sendJson(ex, 200, Json.obj("packageKey", Json.obj("system", "MAVEN", "name", name), "versions", list));
            return;
        }
        if (version.endsWith(":dependents")) {
            String v = version.substring(0, version.length() - 11);
            long[] d = FixtureData.DEPENDENTS.getOrDefault(name + ":" + v, new long[] {0, 0});
            sendJson(ex, 200, Json.obj("dependentCount", d[0], "directDependentCount", d[1], "indirectDependentCount", d[0] - d[1]));
            return;
        }
        if (!vs.contains(version)) { sendJson(ex, 404, Json.obj("code", 5, "message", "version not found")); return; }
        String gav = name + ":" + version;
        List<Object> adv = new ArrayList<>();
        for (String id : vulnsFor(name, version)) adv.add(Json.obj("id", id));
        String gh = fx.scm.get(gav);
        Map<String, Object> m = Json.obj("versionKey", Json.obj("system", "MAVEN", "name", name, "version", version),
                "publishedAt", java.time.Instant.ofEpochMilli(fx.published.get(gav)).toString(),
                "licenses", fx.licenses.containsKey(gav) ? List.of(fx.licenses.get(gav)) : List.of(),
                "advisoryKeys", adv,
                "links", gh == null ? List.of() : List.of(Json.obj("label", "SOURCE_REPO", "url", "https://github.com/" + gh)),
                "relatedProjects", gh == null ? List.of() : List.of(Json.obj("projectKey", Json.obj("id", "github.com/" + gh), "relationProvenance", "UNVERIFIED_METADATA", "relationType", "SOURCE_REPO")));
        sendJson(ex, 200, m);
    }

    // ---------------------------------------------------------------- GitHub

    @SuppressWarnings("unchecked")
    private void github(HttpExchange ex, String p, Map<String, String> q) throws IOException {
        if (p.startsWith("/orgs/") || p.startsWith("/users/")) {
            String owner = p.split("/")[2];
            List<Object> out = new ArrayList<>();
            for (Map.Entry<String, Map<String, Object>> e : FixtureData.REPOS.entrySet()) {
                if (!e.getKey().startsWith(owner + "/")) continue;
                Map<String, Object> r = new LinkedHashMap<>(e.getValue());
                r.remove("_releases");
                r.remove("_commits");
                out.add(r);
            }
            if (out.isEmpty() && p.startsWith("/orgs/")) { sendJson(ex, 404, Json.obj("message", "Not Found")); return; }
            int page = Integer.parseInt(q.getOrDefault("page", "1"));
            sendJson(ex, 200, page > 1 ? List.of() : out);
            return;
        }
        if (!p.startsWith("/repos/")) { sendJson(ex, 404, Json.obj("message", "Not Found")); return; }
        String[] parts = p.substring(7).split("/", 4);
        if (parts.length < 2) { sendJson(ex, 404, Json.obj("message", "Not Found")); return; }
        String full = parts[0] + "/" + parts[1];
        Map<String, Object> repo = null;
        for (Map.Entry<String, Map<String, Object>> e : FixtureData.REPOS.entrySet()) if (e.getKey().equalsIgnoreCase(full)) repo = e.getValue();
        if (repo == null) { sendJson(ex, 404, Json.obj("message", "Not Found")); return; }
        String sub = parts.length > 2 ? parts[2] + (parts.length > 3 ? "/" + parts[3] : "") : "";
        if (sub.isEmpty()) {
            Map<String, Object> r = new LinkedHashMap<>(repo);
            r.remove("_releases");
            r.remove("_commits");
            sendJson(ex, 200, r);
        } else if (sub.equals("releases")) {
            sendJson(ex, 200, repo.get("_releases"));
        } else if (sub.equals("commits")) {
            long since = q.containsKey("since") ? Osv.parseTime(URLDecoder.decode(q.get("since"), StandardCharsets.UTF_8)) : 0;
            int page = Integer.parseInt(q.getOrDefault("page", "1"));
            List<Object> out = new ArrayList<>();
            for (Object c : (List<Object>) repo.get("_commits")) if (Osv.parseTime(Json.str(c, "commit", "author", "date")) >= since) out.add(c);
            int from = (page - 1) * 100;
            sendJson(ex, 200, from >= out.size() ? List.of() : out.subList(from, Math.min(out.size(), from + 100)));
        } else if (sub.startsWith("git/trees/")) {
            List<Object> tree = new ArrayList<>();
            for (String k : FixtureData.REPO_FILES.keySet()) {
                if (k.startsWith(full + ":")) tree.add(Json.obj("path", k.substring(full.length() + 1), "type", "blob"));
            }
            sendJson(ex, 200, Json.obj("sha", "abc", "tree", tree, "truncated", false));
        } else if (sub.startsWith("contents/")) {
            String path = URLDecoder.decode(sub.substring(9), StandardCharsets.UTF_8);
            String content = FixtureData.REPO_FILES.get(full + ":" + path);
            if (content == null) { sendJson(ex, 404, Json.obj("message", "Not Found")); return; }
            sendJson(ex, 200, Json.obj("name", path, "path", path, "encoding", "base64",
                    "content", Base64.getMimeEncoder().encodeToString(content.getBytes(StandardCharsets.UTF_8))));
        } else {
            sendJson(ex, 404, Json.obj("message", "Not Found"));
        }
    }

    // ---------------------------------------------------------------- hooks + admin

    private void hooks(HttpExchange ex, String name) throws IOException {
        if (name.equals("_log")) {
            if ("DELETE".equals(ex.getRequestMethod())) hooks.clear();
            sendJson(ex, 200, new ArrayList<>(hooks));
            return;
        }
        if (name.startsWith("fail")) { send(ex, 500, "text/plain", "hook failure"); return; }
        String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        Map<String, Object> h = new LinkedHashMap<>();
        h.put("hook", name);
        h.put("signature", ex.getRequestHeaders().getFirst("X-SM-Maven-Signature"));
        h.put("contentType", ex.getRequestHeaders().getFirst("Content-Type"));
        try { h.put("body", Json.parse(body)); } catch (IllegalArgumentException e) { h.put("raw", body); }
        hooks.add(h);
        send(ex, 200, "text/plain", "ok");
    }

    private void adminPublish(HttpExchange ex) throws IOException {
        Object body = Json.parse(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
        Fixtures.Lib l = fx.lib(Json.str(body, "gav")).days((int) Json.num(body, 0, "daysAgo"));
        for (Object d : Json.list(body, "deps")) l.dep(String.valueOf(d));
        if (Json.str(body, "license") != null) l.license(Json.str(body, "license"));
        if (Json.str(body, "key") != null) l.key(Json.str(body, "key"));
        if (Json.str(body, "github") != null) l.github(Json.str(body, "github"));
        String cls = Json.str(body, "class");
        String pkg = "pub" + Math.abs(Json.str(body, "gav").hashCode());
        l.src(pkg + ".P", "package " + pkg + ";\npublic class P { }" + (cls == null ? "" : ""));
        fx.publish(l);
        sendJson(ex, 200, Json.obj("ok", true));
    }

    // ---------------------------------------------------------------- helpers

    static Map<String, String> parseQuery(String q) {
        Map<String, String> m = new LinkedHashMap<>();
        if (q == null) return m;
        for (String kv : q.split("&")) {
            int i = kv.indexOf('=');
            if (i < 0) m.put(URLDecoder.decode(kv, StandardCharsets.UTF_8), "");
            else m.put(URLDecoder.decode(kv.substring(0, i), StandardCharsets.UTF_8), URLDecoder.decode(kv.substring(i + 1), StandardCharsets.UTF_8));
        }
        return m;
    }

    private static void sendJson(HttpExchange ex, int status, Object o) throws IOException {
        send(ex, status, "application/json", Json.write(o, false));
    }

    private static void send(HttpExchange ex, int status, String ct, String body) throws IOException {
        send(ex, status, ct, body.getBytes(StandardCharsets.UTF_8));
    }

    private static void send(HttpExchange ex, int status, String ct, byte[] body) throws IOException {
        ex.getResponseHeaders().add("Content-Type", ct);
        ex.sendResponseHeaders(status, body.length == 0 ? -1 : body.length);
        if (body.length > 0) try (OutputStream o = ex.getResponseBody()) { o.write(body); }
        ex.close();
    }

    /** Starts a standalone server for manual runs: java ... MockServer <workdir> */
    public static void main(String[] a) throws Exception {
        Path root = Path.of(a.length > 0 ? a[0] : "build/mock");
        Fixtures fx = new Fixtures(root);
        FixtureData.build(fx);
        MockServer s = new MockServer(fx);
        System.out.println("mock listening on " + s.base());
        for (Map.Entry<String, String> e : s.env(root.resolve("home")).entrySet()) System.out.println("export " + e.getKey() + "=" + e.getValue());
        Thread.currentThread().join();
    }
}
