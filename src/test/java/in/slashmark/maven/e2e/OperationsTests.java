package in.slashmark.maven.e2e;

import in.slashmark.maven.util.Json;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/** Operations and compliance tools: gate, repo-status, publish-track, dashboard, alerts. */
public final class OperationsTests {
    private OperationsTests() {}

    public static void run(Harness h) throws Exception {
        gate(h);
        repoStatus(h);
        publishTrack(h);
        dashboard(h);
        alerts(h);
    }

    // ---------------------------------------------------------------- helpers

    static Map<String, String> config(Path dir) { return Map.of("SM_MAVEN_CONFIG", dir.toString()); }

    @SuppressWarnings("unchecked")
    static List<Object> list(Object root, Object... path) {
        Object v = Json.get(root, path);
        return v instanceof List ? (List<Object>) v : new ArrayList<>();
    }

    static Object rule(Object doc, String id) {
        for (Object r : list(doc, "rules")) if (id.equals(Json.str(r, "id"))) return r;
        return null;
    }

    static Set<String> field(List<Object> items, String key) {
        Set<String> s = new LinkedHashSet<>();
        for (Object o : items) s.add(Json.str(o, key));
        return s;
    }

    static Object repo(Object doc, String id) {
        for (Object r : list(doc, "repositories")) if (id.equals(Json.str(r, "id")) || id.equals(Json.str(r, "name"))) return r;
        return null;
    }

    static Document xml(String s) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return f.newDocumentBuilder().parse(new ByteArrayInputStream(s.getBytes(StandardCharsets.UTF_8)));
    }

    static List<Object> hooks(Harness h, String name) throws Exception {
        List<Object> out = new ArrayList<>();
        for (Object o : list(h.hookLog())) if (name.equals(Json.str(o, "hook"))) out.add(o);
        return out;
    }

    // ---------------------------------------------------------------- gate

    static void gate(Harness h) throws Exception {
        Harness.Result r = h.onProject("gate", "--json");
        Object j = r.json();
        Object kev = rule(j, "kev");
        h.check("gate: default policy (critical + KEV) fails with exit 1", r.code == 1 && Boolean.FALSE.equals(Json.get(j, "passed"))
                && "default".equals(Json.str(j, "policy", "source")), r);
        Set<String> kevArts = field(list(kev, "violations"), "artifact");
        h.check("gate: KEV rule lists log4j-core 2.14.1 and spring-beans 5.3.17",
                kevArts.contains("org.apache.logging.log4j:log4j-core:2.14.1") && kevArts.contains("org.springframework:spring-beans:5.3.17")
                        && field(list(kev, "violations"), "cve").contains("CVE-2021-44228"), r);
        Set<String> sevCves = field(list(rule(j, "severity"), "violations"), "cve");
        h.check("gate: severity rule only reports critical advisories by default",
                sevCves.contains("CVE-2022-22965") && !sevCves.contains("CVE-2020-36518") && !sevCves.contains("CVE-2021-44832"), r);
        Object v0 = list(kev, "violations").isEmpty() ? null : list(kev, "violations").get(0);
        h.check("gate: violations carry module pom location and fix version",
                v0 != null && Json.str(v0, "file") != null && Json.str(v0, "file").endsWith("pom.xml") && Json.num(v0, 0, "line") > 0 && Json.str(v0, "fixedIn") != null, r);
        h.check("gate: unconfigured rules are off", "off".equals(Json.str(rule(j, "license"), "status")) && "off".equals(Json.str(rule(j, "deny"), "status")), r);

        r = h.onProject("gate");
        h.check("gate: human output shows rule results and verdict", r.code == 1 && r.out.contains("Policy FAILED") && r.out.contains("CVE-2021-44228")
                && r.out.contains("app/pom.xml"), r);

        r = h.onProject("gate", "--kev", "--allow-vuln", "CVE-2021-44228@2099-12-31", "--json");
        j = r.json();
        Set<String> kevCves = field(list(rule(j, "kev"), "violations"), "cve");
        h.check("gate: --allow-vuln with future expiry suppresses that CVE only", !kevCves.contains("CVE-2021-44228") && kevCves.contains("CVE-2022-22965")
                && field(list(j, "suppressed"), "cve").contains("CVE-2021-44228"), r);

        r = h.onProject("gate", "--kev", "--allow-vuln", "CVE-2021-44228:2020-01-01", "--json");
        j = r.json();
        h.check("gate: expired allowance stops applying and is reported", field(list(rule(j, "kev"), "violations"), "cve").contains("CVE-2021-44228")
                && list(j, "expiredAllowances").size() == 1 && Boolean.TRUE.equals(Json.get(list(j, "expiredAllowances").get(0), "expired")), r);

        r = h.onProject("gate", "--epss", "0.5", "--json");
        j = r.json();
        Set<String> epssCves = field(list(rule(j, "epss"), "violations"), "cve");
        h.check("gate: --epss 0.5 flags likely-exploited CVEs (incl. high CVE-2021-45105) but not low-EPSS ones",
                epssCves.contains("CVE-2021-45105") && epssCves.contains("CVE-2022-22965") && !epssCves.contains("CVE-2021-44832") && !epssCves.contains("CVE-2020-36518")
                        && "off".equals(Json.str(rule(j, "kev"), "status")), r);

        r = h.onProject("gate", "--deny-license", "strong-copyleft,AGPL-*", "--json");
        j = r.json();
        Set<String> licArts = field(list(rule(j, "license"), "violations"), "artifact");
        h.check("gate: --deny-license finds the GPL-3.0 dependency only", r.code == 1 && licArts.contains("org.example:gpl-lib:1.0") && licArts.size() == 1, r);

        r = h.onProject("gate", "--max-age-days", "2000", "--json");
        j = r.json();
        Set<String> old = field(list(rule(j, "maintenance"), "violations"), "artifact");
        h.check("gate: --max-age-days flags unmaintained commons-logging and jaxb-api", old.contains("commons-logging:commons-logging:1.2")
                && old.contains("javax.xml.bind:jaxb-api:2.3.1") && !old.contains("org.apache.logging.log4j:log4j-core:2.14.1"), r);

        r = h.onProject("gate", "--deny", "commons-logging:*,org.apache.logging.log4j:log4j-core:[2.0,2.17.1)", "--deny-archived", "--json");
        j = r.json();
        Set<String> denied = field(list(rule(j, "deny"), "violations"), "artifact");
        h.check("gate: --deny matches globs and version ranges", denied.contains("commons-logging:commons-logging:1.2")
                && denied.contains("org.apache.logging.log4j:log4j-core:2.14.1") && !denied.contains("org.apache.logging.log4j:log4j-api:2.14.1"), r);
        h.check("gate: --deny-archived finds acme-utils (archived on GitHub)",
                field(list(rule(j, "archived"), "violations"), "artifact").contains("com.acme:acme-utils:1.2.0"), r);

        r = h.onProject("gate", "--fail-on", "none", "--deny", "org.nothing:*", "--json");
        h.check("gate: a policy without violations passes with exit 0", r.code == 0 && Boolean.TRUE.equals(Json.get(r.json(), "passed")), r);
        r = h.onProject("gate", "--warn-only");
        h.check("gate: --warn-only reports but exits 0", r.code == 0 && r.out.contains("Policy FAILED"), r);

        r = h.onProject("gate", "--format", "github");
        String firstError = null;
        for (String line : r.out.split("\n")) if (line.startsWith("::error file=")) { firstError = line; break; }
        h.check("gate: --format github prints ::error annotations with file, line and escaped title",
                r.code == 1 && firstError != null && firstError.matches("::error file=(app|lib)/pom\\.xml,line=\\d+,title=sm-maven gate%3A [^:]+::\\[CRITICAL\\] .*")
                        && r.out.trim().endsWith("2 rule(s), 6 violation(s)") && r.out.trim().split("\n").length == 7, r);

        r = h.onProject("gate", "--junit", "--deny-license", "GPL-3.0-only", "--kev");
        Document d = xml(r.out);
        Element suites = d.getDocumentElement();
        NodeList cases = d.getElementsByTagName("testcase");
        NodeList failures = d.getElementsByTagName("failure");
        boolean classOk = false;
        for (int i = 0; i < cases.getLength(); i++) if ("sm-maven.gate.license".equals(((Element) cases.item(i)).getAttribute("classname"))) classOk = true;
        h.check("gate: --junit emits valid JUnit XML whose counts match its testcases", "testsuites".equals(suites.getTagName())
                && Integer.parseInt(suites.getAttribute("tests")) == cases.getLength() && cases.getLength() == 2
                && Integer.parseInt(suites.getAttribute("failures")) == failures.getLength() && failures.getLength() == 2 && classOk
                && failures.item(0).getTextContent().contains("pom.xml"), r);

        Path sarif = h.root.resolve("gate.sarif");
        r = h.onProject("gate", "--kev", "--fail-on", "high", "--allow-vuln", "CVE-2021-45046", "--sarif", "-o", sarif.toString());
        Object s = Files.isRegularFile(sarif) ? Json.parse(Files.readString(sarif)) : null;
        boolean sarifOk = s != null && "2.1.0".equals(Json.str(s, "version")) && Json.str(s, "$schema").contains("sarif-2.1.0")
                && "sm-maven".equals(Json.str(s, "runs", 0, "tool", "driver", "name"));
        List<Object> rulesDef = list(s, "runs", 0, "tool", "driver", "rules");
        List<Object> results = list(s, "runs", 0, "results");
        int suppressedResults = 0;
        for (Object res : results) {
            int ix = (int) Json.num(res, -1, "ruleIndex");
            if (ix < 0 || ix >= rulesDef.size() || !Json.str(rulesDef.get(ix), "id").equals(Json.str(res, "ruleId"))) sarifOk = false;
            if (Json.str(res, "message", "text") == null || !List.of("error", "warning", "note").contains(Json.str(res, "level"))) sarifOk = false;
            String uri = Json.str(res, "locations", 0, "physicalLocation", "artifactLocation", "uri");
            if (uri == null || !uri.endsWith("pom.xml")) sarifOk = false;
            Object line = Json.get(res, "locations", 0, "physicalLocation", "region", "startLine");
            if (line != null && ((Number) line).intValue() < 1) sarifOk = false;
            if (Json.str(res, "partialFingerprints", "smMavenGate/v1") == null) sarifOk = false;
            if (!list(res, "suppressions").isEmpty()) suppressedResults++;
        }
        h.check("gate: --sarif -o writes a structurally valid SARIF 2.1.0 log (rules, ruleIndex, locations, fingerprints)",
                r.code == 1 && sarifOk && rulesDef.size() == 2 && results.size() >= 5 && r.out.contains("Report written to"), r + "\n" + s);
        h.check("gate: accepted risks appear as suppressed SARIF results", suppressedResults >= 1, s);

        Path pol = h.root.resolve("policy.json");
        Files.writeString(pol, "{\"policy\":{\"failOn\":\"none\",\"kev\":false,\"denyLicense\":[\"source-available\"],\"allowVuln\":[{\"id\":\"CVE-2021-44228\",\"until\":\"2099-01-01\",\"reason\":\"patched JndiLookup\"}]}}");
        r = h.onProject("gate", "--policy", pol.toString(), "--json");
        j = r.json();
        h.check("gate: JSON policy file is honoured (licence rule only; widgets 1.0.0 is Apache so it passes)", r.code == 0
                && "pass".equals(Json.str(rule(j, "license"), "status")) && "off".equals(Json.str(rule(j, "kev"), "status"))
                && "patched JndiLookup".equals(Json.str(j, "policy", "allowVuln", 0, "reason")), r);

        Path copy = h.root.resolve("gate-shop");
        Harness.copy(h.project.getParent(), copy);
        Files.createDirectories(copy.resolve(".sm-maven"));
        Files.writeString(copy.resolve(".sm-maven/policy.properties"), "# team policy\nfail-on=none\nkev=false\ndeny=org.example:gpl-lib\n");
        r = h.run("gate", "-f", copy.resolve("pom.xml").toString(), "--json");
        j = r.json();
        h.check("gate: .sm-maven/policy.properties next to the pom is discovered", r.code == 1 && Json.str(j, "policy", "source").endsWith("policy.properties")
                && field(list(rule(j, "deny"), "violations"), "artifact").equals(Set.of("org.example:gpl-lib:1.0")), r);
        Files.writeString(copy.resolve(".sm-maven/policy.properties"), "fail-onn=high\n");
        r = h.run("gate", "-f", copy.resolve("pom.xml").toString());
        h.check("gate: unknown policy keys are a usage error (exit 2)", r.code == 2 && r.err.contains("fail-onn"), r);

        r = h.onProject("gate", "--fail-on", "severe");
        h.check("gate: bad --fail-on -> exit 2", r.code == 2, r);
        r = h.onProject("gate", "--format", "pdf");
        h.check("gate: bad --format -> exit 2", r.code == 2, r);
        r = h.run("gate", "org.apache.logging.log4j:log4j-core:2.14.1", "--kev", "--json");
        h.check("gate: published coordinates can be gated", r.code == 1 && "org.apache.logging.log4j:log4j-core:2.14.1".equals(Json.str(r.json(), "target"))
                && list(rule(r.json(), "kev"), "violations").size() == 2, r);
    }

    // ---------------------------------------------------------------- repo-status

    static Path settings(Harness h) throws Exception {
        String b = h.mock.base();
        Path f = h.root.resolve("ops-settings.xml");
        Files.writeString(f, "<settings>\n"
                + "  <servers><server><id>secure</id><username>deploy</username><password>s3cret</password></server></servers>\n"
                + "  <mirrors><mirror><id>corp-mirror</id><url>" + b + "/mirror/maven2</url><mirrorOf>legacy-repo</mirrorOf></mirror></mirrors>\n"
                + "  <profiles><profile><id>extra</id><repositories>\n"
                + "    <repository><id>secure</id><url>" + b + "/secure/maven2</url></repository>\n"
                + "    <repository><id>flaky</id><url>" + b + "/flaky/maven2</url></repository>\n"
                + "  </repositories></profile></profiles>\n"
                + "  <activeProfiles><activeProfile>extra</activeProfile></activeProfiles>\n"
                + "</settings>\n");
        return f;
    }

    static void repoStatus(Harness h) throws Exception {
        Path st = settings(h);
        Path cfg = h.root.resolve("ops-repo-cfg");
        Harness.Result r = h.runWith(config(cfg), "repo-status", "--settings", st.toString(), "--samples", "3",
                "-r", "anon=" + h.mock.base() + "/secure/maven2", "-r", "http://ops:hunter2@" + "127.0.0.1:" + h.mock.port + "/maven2/", "--json");
        Object j = r.json();
        Object central = repo(j, "central"), secure = repo(j, "secure"), flaky = repo(j, "flaky"), mirror = repo(j, "corp-mirror"), anon = repo(j, "anon");
        h.check("repo-status: probes central, settings repositories, settings mirror and -r URLs", central != null && secure != null && flaky != null
                && mirror != null && anon != null && list(j, "repositories").size() == 6 && "settings mirror".equals(Json.str(mirror, "source")), r);
        h.check("repo-status: central is up with latency percentiles over the samples", "up".equals(Json.str(central, "state"))
                && list(central, "latency", "samples").size() == 3 && Json.num(central, -1, "latency", "p95") >= Json.num(central, -1, "latency", "p50")
                && Json.num(central, 0, "httpStatus") == 200, r);
        h.check("repo-status: flaky repository answering 503 is down (exit 1)", r.code == 1 && "down".equals(Json.str(flaky, "state"))
                && Json.num(flaky, 0, "httpStatus") == 503 && Json.str(flaky, "error").contains("503"), r);
        h.check("repo-status: secure repository accepts settings.xml credentials and requires them",
                "up".equals(Json.str(secure, "state")) && Boolean.TRUE.equals(Json.get(secure, "auth", "ok")) && Boolean.TRUE.equals(Json.get(secure, "auth", "required")), r);
        h.check("repo-status: same repository without credentials is auth-required", "auth-required".equals(Json.str(anon, "state"))
                && Boolean.FALSE.equals(Json.get(anon, "auth", "configured")) && Json.num(anon, 0, "httpStatus") == 401, r);
        h.check("repo-status: mirror latency (250 ms) is measured", Json.num(mirror, 0, "latency", "p50") >= 240, r);
        h.check("repo-status: metadata freshness reported (lastUpdated, newest version, lag)", Json.str(central, "metadata", "lastUpdated") != null
                && "2.24.3".equals(Json.str(central, "metadata", "newestVersion")) && Json.num(central, -1, "metadata", "lagMinutes") == 0, r);
        h.check("repo-status: passwords from settings.xml and URLs are never printed", !r.out.contains("s3cret") && !r.err.contains("s3cret")
                && !r.out.contains("hunter2") && !r.err.contains("hunter2") && r.out.contains("***@"), r);

        r = h.runWith(config(cfg), "repo-status", "--settings", st.toString(), "--samples", "2", "--slow", "100ms");
        h.check("repo-status: human table, slow mirror degraded and flaky down", r.code == 1 && r.out.contains("p95") && r.out.contains("degraded")
                && r.out.contains("flaky") && r.out.contains("503") && !r.out.contains("s3cret"), r);

        r = h.runWith(config(h.root.resolve("ops-repo-cfg2")), "repo-status", "--samples", "1", "-r", "ext=http://repo.example.invalid/maven2", "--fail-on", "none", "--json");
        Object ext = repo(r.json(), "ext");
        h.check("repo-status: plain-HTTP external repositories get an insecure warning; --fail-on none exits 0", r.code == 0
                && Boolean.TRUE.equals(Json.get(ext, "insecure")) && list(ext, "warnings").toString().contains("insecure"), r);

        // Alerts on state changes: the first run sees flaky go down, the next run (no change) stays quiet.
        Path acfg = h.root.resolve("ops-repo-alerts");
        h.runWith(config(acfg), "alerts", "add", "ops-hook", "--type", "webhook", "--url", h.mock.base() + "/hooks/ops-repo");
        h.clearHooks();
        r = h.runWith(config(acfg), "repo-status", "--settings", st.toString(), "--samples", "1");
        List<Object> first = hooks(h, "ops-repo");
        r = h.runWith(config(acfg), "repo-status", "--settings", st.toString(), "--samples", "1", "--json");
        List<Object> second = hooks(h, "ops-repo");
        h.check("repo-status: alert sent when a repository changes state, not again when unchanged", first.size() == 1
                && Json.str(first.get(0), "body", "title").contains("unhealthy") && String.valueOf(Json.get(first.get(0), "body", "lines")).contains("flaky")
                && second.size() == 1 && list(r.json(), "changes").isEmpty(), first + "\n" + r);

        r = h.run("repo-status", "--samples", "0");
        h.check("repo-status: bad --samples -> exit 2", r.code == 2, r);
        r = h.run("repo-status", "-r", "ftp://example.com/repo");
        h.check("repo-status: non-http -r URL -> exit 2", r.code == 2, r);
        r = h.runWith(config(h.root.resolve("ops-repo-cfg3")), "repo-status", "--samples", "1", "--watch", "--cycles", "2", "--interval", "1s", "--json");
        h.check("repo-status: --watch --cycles 2 emits one JSON document per probe", r.jsonLines().size() == 2 && r.code == 0
                && Json.num(r.jsonLines().get(1), 0, "cycle") == 2, r);
    }

    // ---------------------------------------------------------------- publish-track

    static Object stage(Object artifact, String id) {
        for (Object s : list(artifact, "stages")) if (id.equals(Json.str(s, "id"))) return s;
        return null;
    }

    static void publishTrack(Harness h) throws Exception {
        Path cfg = h.root.resolve("ops-track-cfg");
        Harness.Result r = h.runWith(config(cfg), "publish-track", "org.apache.logging.log4j:log4j-core:2.24.3", "--json");
        Object a = list(r.json(), "artifacts").isEmpty() ? null : list(r.json(), "artifacts").get(0);
        boolean allDone = a != null;
        for (String s : List.of("artifact", "metadata", "search", "javadoc")) if (!"done".equals(Json.str(stage(a, s), "status"))) allDone = false;
        h.check("publish-track: fully published release passes all four stages (exit 0)", r.code == 0 && allDone && Boolean.TRUE.equals(Json.get(r.json(), "complete")), r);
        List<Object> files = list(stage(a, "artifact"), "files");
        boolean signed = files.size() == 4;
        for (Object f : files) if (!Boolean.TRUE.equals(Json.get(f, "signature")) || !Boolean.TRUE.equals(Json.get(f, "sha1"))) signed = false;
        h.check("publish-track: pom, jar, sources, javadoc with .asc and checksums are verified", signed
                && Json.str(stage(a, "artifact"), "detail").contains("sha1 verified") && Json.str(a, "uploadedAt") != null, r);
        h.check("publish-track: stage timestamps from the data sources", Json.str(stage(a, "metadata"), "at") != null && Json.str(stage(a, "search"), "at") != null
                && Json.str(stage(a, "artifact"), "firstSeenGreen") != null, r);
        String seen1 = Json.str(stage(a, "artifact"), "firstSeenGreen");
        r = h.runWith(config(cfg), "publish-track", "org.apache.logging.log4j:log4j-core:2.24.3", "--json");
        h.check("publish-track: first-seen-green times persist across runs", seen1 != null
                && seen1.equals(Json.str(stage(list(r.json(), "artifacts").get(0), "artifact"), "firstSeenGreen")), r);

        r = h.runWith(config(cfg), "publish-track", "com.acme:acme-agent:1.0.1");
        h.check("publish-track: missing javadoc.io keeps the release pending (exit 1)", r.code == 1 && r.out.contains("javadoc.io")
                && r.out.contains("pending") && r.out.contains("Not fully published"), r);
        r = h.runWith(config(cfg), "publish-track", "com.acme:acme-agent:1.0.1", "--stages", "artifact,metadata,search", "--json");
        h.check("publish-track: --stages limits what must be green", r.code == 0 && Boolean.FALSE.equals(Json.get(stage(list(r.json(), "artifacts").get(0), "javadoc"), "required")), r);
        r = h.runWith(config(cfg), "publish-track", "mysql:mysql-connector-java:8.0.33", "--json");
        a = list(r.json(), "artifacts").get(0);
        h.check("publish-track: pom packaging skips the jar files and javadoc.io", r.code == 0 && "pom".equals(Json.str(a, "packaging"))
                && "skipped".equals(Json.str(stage(a, "javadoc"), "status")) && list(stage(a, "artifact"), "files").size() == 1, r);
        r = h.runWith(config(cfg), "publish-track", "com.acme:acme-core:7.7.7", "--json");
        a = list(r.json(), "artifacts").get(0);
        h.check("publish-track: unpublished version is pending at the artifact stage", r.code == 1 && "pending".equals(Json.str(stage(a, "artifact"), "status"))
                && list(stage(a, "artifact"), "missing").contains(".pom") && "pending".equals(Json.str(stage(a, "metadata"), "status")), r);

        r = h.runWith(config(cfg), "publish-track", "com.acme:acme-agent:1.0.1", "--wait", "--interval", "1s", "--timeout", "2s", "--json");
        h.check("publish-track: --wait gives up after --timeout (exit 1)", r.code == 1 && Boolean.TRUE.equals(Json.get(r.json(), "timedOut")), r);

        // A release that appears while we wait: published 1.5 s after polling starts; alert when done.
        Path acfg = h.root.resolve("ops-track-alerts");
        h.runWith(config(acfg), "alerts", "add", "release-hook", "--type", "webhook", "--url", h.mock.base() + "/hooks/ops-release");
        h.clearHooks();
        Thread publisher = new Thread(() -> {
            try {
                Thread.sleep(1500);
                h.post("/_admin/publish", Json.obj("gav", "in.slashmark:track-demo:1.0.0", "daysAgo", 0, "license", "MIT"));
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
        publisher.start();
        r = h.runWith(config(acfg), "publish-track", "in.slashmark:track-demo:1.0.0", "--wait", "--interval", "1s", "--timeout", "60s",
                "--stages", "artifact,metadata,search", "--json");
        publisher.join();
        List<Object> hk = hooks(h, "ops-release");
        h.check("publish-track: --wait polls until a new release is live, then alerts", r.code == 0 && Boolean.TRUE.equals(Json.get(r.json(), "complete"))
                && Json.num(r.json(), 0, "polls") >= 2 && hk.size() == 1 && Json.str(hk.get(0), "body", "title").contains("is live"), r + "\n" + hk);

        r = h.onProject("publish-track", "--stages", "artifact", "--json");
        h.check("publish-track: without coordinates it tracks the project's modules", r.code == 1 && list(r.json(), "artifacts").size() == 3
                && field(list(r.json(), "artifacts"), "artifact").contains("com.acme.shop:shop-app:3.2.0"), r);
        r = h.run("publish-track", "com.acme:acme-core:1.0.0", "--stages", "artifact,docs");
        h.check("publish-track: unknown stage -> exit 2", r.code == 2, r);
    }

    // ---------------------------------------------------------------- dashboard

    static void dashboard(Harness h) throws Exception {
        String token = "ghp_TopSecretToken0123456789";
        Harness.Result r = h.runWith(Map.of("GITHUB_TOKEN", token), "dashboard", "--org", "slash-mark-dev", "--json");
        Object j = r.json();
        Object api = repo(j, "slash-mark-dev/api-service"), web = repo(j, "slash-mark-dev/web-portal");
        h.check("dashboard: scans the org's Maven repositories (exit 1: P1 findings)", r.code == 1 && api != null && web != null && list(j, "repositories").size() == 2, r);
        h.check("dashboard: api-service has log4j KEV findings and grade F", Json.num(api, 0, "kev") == 2 && Json.num(api, 0, "vulnerabilities", "byPriority", "P1") >= 2
                && "F".equals(Json.str(api, "grade")) && String.valueOf(Json.get(api, "topFindings")).contains("CVE-2021-44228"), r);
        h.check("dashboard: web-portal is clean (grade A, no KEV)", "A".equals(Json.str(web, "grade")) && Json.num(web, -1, "kev") == 0
                && Json.num(web, -1, "vulnerabilities", "total") == 0 && Json.num(web, 0, "dependencies") >= 2, r);
        h.check("dashboard: outdated dependencies counted (log4j 2.14.1 -> 2.24.3)", Json.num(api, 0, "outdated") >= 1
                && String.valueOf(Json.get(api, "outdatedDependencies")).contains("2.24.3"), r);
        h.check("dashboard: repositories without pom.xml are skipped", String.valueOf(Json.get(j, "skipped")).contains("composer-suite")
                && Json.num(j, 0, "totals", "kev") == 2, r);
        h.check("dashboard: the GitHub token is never printed", !r.out.contains(token) && !r.err.contains(token), r);

        Path page = h.root.resolve("dash/index.html");
        r = h.runWith(Map.of("GITHUB_TOKEN", token), "dashboard", "--org", "slash-mark-dev", "--format", "html", "-o", page.toString());
        String html = Files.isRegularFile(page) ? Files.readString(page) : "";
        h.check("dashboard: --format html writes a self-contained page", html.startsWith("<!DOCTYPE html>") && html.contains("api-service")
                && html.contains("g-F") && html.contains("CVE-2021-44228") && !html.contains("<script") && !html.contains("<link")
                && !html.contains(token) && html.trim().endsWith("</html>") && r.out.contains("Dashboard written to"), r);

        r = h.run("dashboard", "--org", "slash-mark-dev", "--repos", "web-*");
        h.check("dashboard: --repos filter and human table (no P1 -> exit 0)", r.code == 0 && r.out.contains("web-portal") && !r.out.contains("api-service ")
                && r.out.contains("Grade") && r.out.contains("Top risk"), r);

        Path local = h.root.resolve("dash-local/portal");
        Files.createDirectories(local);
        Files.writeString(local.resolve("pom.xml"), "<project><modelVersion>4.0.0</modelVersion><groupId>in.slashmark</groupId><artifactId>local-portal</artifactId>"
                + "<version>1.0</version><dependencies><dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>31.1-jre</version></dependency>"
                + "</dependencies></project>");
        r = h.run("dashboard", h.project.getParent().toString(), local.toString(), "--json");
        j = r.json();
        Object shop = repo(j, "shop-parent"), portal = repo(j, "local-portal");
        h.check("dashboard: local multi-path mode summarises each project", list(j, "repositories").size() == 2 && shop != null && portal != null
                && "local".equals(Json.str(portal, "source")) && Json.num(shop, 0, "kev") >= 3
                && Json.num(portal, 0, "vulnerabilities", "total") == 2 && Json.num(shop, 0, "licenseIssues") == 1, r);

        r = h.run("dashboard", "--org", "no-such-org-xyz");
        h.check("dashboard: unknown organisation -> exit 2", r.code == 2, r);
        r = h.run("dashboard", "--org", "slash-mark-dev", "--format", "pdf");
        h.check("dashboard: bad --format -> exit 2", r.code == 2, r);
    }

    // ---------------------------------------------------------------- alerts

    /** Minimal SMTP server (no TLS) recording what it receives. */
    static final class FakeSmtp implements AutoCloseable {
        final ServerSocket server;
        final StringBuffer log = new StringBuffer();
        final Thread thread;

        FakeSmtp() throws Exception {
            server = new ServerSocket(0, 5, InetAddress.getLoopbackAddress());
            thread = new Thread(this::serve, "fake-smtp");
            thread.setDaemon(true);
            thread.start();
        }

        int port() { return server.getLocalPort(); }

        private void serve() {
            while (!server.isClosed()) {
                try (Socket s = server.accept()) {
                    BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
                    OutputStream out = s.getOutputStream();
                    out.write("220 fake ESMTP\r\n".getBytes(StandardCharsets.US_ASCII));
                    String line;
                    boolean data = false;
                    while ((line = in.readLine()) != null) {
                        log.append(line).append('\n');
                        String reply;
                        if (data) {
                            if (!line.equals(".")) continue;
                            data = false;
                            reply = "250 queued";
                        } else if (line.startsWith("EHLO")) reply = "250-fake\r\n250 AUTH PLAIN";
                        else if (line.startsWith("AUTH")) reply = "235 ok";
                        else if (line.startsWith("MAIL") || line.startsWith("RCPT")) reply = "250 ok";
                        else if (line.equals("DATA")) { data = true; reply = "354 go"; }
                        else if (line.equals("QUIT")) { out.write("221 bye\r\n".getBytes(StandardCharsets.US_ASCII)); break; }
                        else reply = "500 what";
                        out.write((reply + "\r\n").getBytes(StandardCharsets.US_ASCII));
                        out.flush();
                    }
                } catch (Exception e) {
                    // closed
                }
            }
        }

        @Override
        public void close() throws Exception { server.close(); }
    }

    static String hmac(String secret, String body) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        StringBuilder b = new StringBuilder();
        for (byte x : mac.doFinal(body.getBytes(StandardCharsets.UTF_8))) b.append(String.format("%02x", x));
        return b.toString();
    }

    static void alerts(Harness h) throws Exception {
        Path cfg = h.root.resolve("ops-alerts-cfg");
        Map<String, String> env = config(cfg);
        String hookSecret = "whsec-ops-123456";
        Harness.Result r = h.runWith(env, "alerts", "list");
        h.check("alerts: list with no channels explains how to add one", r.code == 0 && r.out.contains("No alert channels"), r);

        r = h.runWith(env, "alerts", "add", "siem", "--type", "webhook", "--url", h.mock.base() + "/hooks/ops-hmac", "--secret", hookSecret);
        h.check("alerts: add webhook channel with HMAC secret", r.code == 0 && r.out.contains("siem") && !r.out.contains(hookSecret) && !r.out.contains("/hooks/ops-hmac"), r);
        r = h.runWith(env, "alerts", "add", "team-slack", "--type", "slack", "--url", h.mock.base() + "/hooks/ops-slack");
        Path alertFile = h.root.resolve("ops-alerts.ndjson");
        Harness.Result r2 = h.runWith(env, "alerts", "add", "audit", "--type", "file", "--file", alertFile.toString());
        h.check("alerts: add slack and file channels", r.code == 0 && r2.code == 0, r + "\n" + r2);
        r = h.runWith(env, "alerts", "add", "team-slack", "--type", "slack", "--url", h.mock.base() + "/hooks/ops-slack");
        h.check("alerts: duplicate channel name without --force -> exit 2", r.code == 2 && r.err.contains("--force"), r);
        r = h.runWith(env, "alerts", "add", "x", "--type", "pager");
        Harness.Result r3 = h.runWith(env, "alerts", "add", "y", "--type", "teams");
        h.check("alerts: unknown type or missing --url -> exit 2", r.code == 2 && r3.code == 2, r + "\n" + r3);

        try (FakeSmtp smtp = new FakeSmtp()) {
            String pw = "smtp-Pa55word!";
            r = h.runWith(env, "alerts", "add", "oncall", "--type", "email", "--host", "127.0.0.1", "--port", String.valueOf(smtp.port()), "--tls", "none",
                    "--user", "bot", "--password", pw, "--from", "sm-maven <bot@slashmark.in>", "--to", "ops@slashmark.in,sec@slashmark.in");
            h.check("alerts: add e-mail channel", r.code == 0 && !r.out.contains(pw), r);

            r = h.runWith(env, "alerts", "list", "--json");
            Object j = r.json();
            Object siem = null, mail = null;
            for (Object c : list(j, "channels")) {
                if ("siem".equals(Json.str(c, "name"))) siem = c;
                if ("oncall".equals(Json.str(c, "name"))) mail = c;
            }
            h.check("alerts: list --json masks webhook URLs, secrets and passwords", list(j, "channels").size() == 4 && "***".equals(Json.str(siem, "secret"))
                    && Json.str(siem, "url").endsWith("/…") && !Json.str(siem, "url").contains("hooks") && "***".equals(Json.str(mail, "password"))
                    && !r.out.contains(hookSecret) && !r.out.contains(pw) && !r.out.contains("/hooks/"), r);
            r = h.runWith(env, "alerts", "list");
            h.check("alerts: human list shows channels without secrets", r.code == 0 && r.out.contains("team-slack") && r.out.contains("HMAC")
                    && !r.out.contains(hookSecret) && !r.out.contains(pw) && !r.out.contains("/hooks/"), r);

            h.clearHooks();
            r = h.runWith(env, "alerts", "test", "--json");
            j = r.json();
            boolean allOk = list(j, "deliveries").size() == 4;
            for (Object d : list(j, "deliveries")) if (!Boolean.TRUE.equals(Json.get(d, "ok"))) allOk = false;
            h.check("alerts: test delivers to every channel", r.code == 0 && allOk, r);
            List<Object> hm = hooks(h, "ops-hmac");
            Object body = hm.isEmpty() ? null : Json.get(hm.get(0), "body");
            String sig = hm.isEmpty() ? null : Json.str(hm.get(0), "signature");
            h.check("alerts: webhook test is HMAC-SHA256 signed over the payload", sig != null && sig.equals("sha256=" + hmac(hookSecret, Json.write(body, false)))
                    && "sm-maven".equals(Json.str(body, "source")) && Boolean.TRUE.equals(Json.get(body, "data", "test")), hm);
            List<Object> sl = hooks(h, "ops-slack");
            h.check("alerts: Slack test uses Block Kit", sl.size() == 1 && !list(sl.get(0), "body", "blocks").isEmpty()
                    && "Test alert from sm-maven".equals(Json.str(sl.get(0), "body", "text")), sl);
            String fileLog = Files.isRegularFile(alertFile) ? Files.readString(alertFile) : "";
            h.check("alerts: file channel appends JSON lines", fileLog.contains("Test alert from sm-maven") && Json.parse(fileLog.trim().split("\n")[0]) != null, fileLog);
            String mailLog = smtp.log.toString();
            h.check("alerts: e-mail test goes through SMTP with AUTH, recipients and subject", mailLog.contains("AUTH PLAIN") && mailLog.contains("RCPT TO:<ops@slashmark.in>")
                    && mailLog.contains("RCPT TO:<sec@slashmark.in>") && mailLog.contains("Subject: =?UTF-8?B?") && mailLog.contains("Test alert from sm-maven")
                    && !r.out.contains(pw), mailLog);

            r = h.runWith(env, "alerts", "route", "team-slack", "high");
            h.clearHooks();
            Harness.Result s1 = h.runWith(env, "alerts", "send", "--title", "Gate failed on main", "--severity", "medium", "--line", "build #42, see CI", "--json");
            Harness.Result s2 = h.runWith(env, "alerts", "send", "--title", "Log4Shell in prod", "--severity", "critical", "--channel", "team-slack,siem", "--json");
            List<Object> slackHooks = hooks(h, "ops-slack");
            List<Object> siemHooks = hooks(h, "ops-hmac");
            h.check("alerts: route + send honour each channel's minimum severity", r.code == 0 && s1.code == 0 && Json.num(s1.json(), 0, "skipped") == 1
                    && slackHooks.size() == 1 && Json.str(slackHooks.get(0), "body", "text").equals("Log4Shell in prod") && siemHooks.size() == 2
                    && List.of("build #42, see CI").equals(Json.get(siemHooks.get(0), "body", "lines")), s1 + "\n" + s2 + "\n" + slackHooks);
            h.check("alerts: send --channel limits delivery", Json.num(s2.json(), 0, "delivered") == 2 && list(s2.json(), "deliveries").size() == 2, s2);
        }

        r = h.runWith(env, "alerts", "remove", "oncall");
        Harness.Result l = h.runWith(env, "alerts", "list", "--json");
        h.check("alerts: remove deletes a channel", r.code == 0 && list(l.json(), "channels").size() == 3 && !l.out.contains("oncall"), r + "\n" + l);

        r = h.runWith(env, "alerts", "add", "broken", "--type", "webhook", "--url", h.mock.base() + "/hooks/fail-ops");
        r = h.runWith(env, "alerts", "test", "broken");
        h.check("alerts: failed delivery is reported with exit 1", r.code == 1 && r.out.contains("broken") && r.out.contains("500"), r);

        Map<String, String> envCh = new LinkedHashMap<>(config(h.root.resolve("ops-alerts-env")));
        envCh.put("SM_MAVEN_WEBHOOK", h.mock.base() + "/hooks/ops-env-secret-path");
        envCh.put("SM_MAVEN_WEBHOOK_SECRET", "env-secret-xyz");
        r = h.runWith(envCh, "alerts", "list");
        Harness.Result rm = h.runWith(envCh, "alerts", "remove", "webhook-env");
        h.check("alerts: environment channels are listed (masked) and cannot be removed", r.code == 0 && r.out.contains("webhook-env") && r.out.contains("environment")
                && !r.out.contains("ops-env-secret-path") && !r.out.contains("env-secret-xyz") && rm.code == 2, r + "\n" + rm);

        r = h.runWith(env, "alerts", "send", "--severity", "high");
        Harness.Result bad = h.runWith(env, "alerts", "frobnicate");
        h.check("alerts: send without --title and unknown sub-command -> exit 2", r.code == 2 && bad.code == 2, r + "\n" + bad);
    }
}
