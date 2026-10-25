package in.slashmark.maven.e2e;

import in.slashmark.maven.util.Json;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** Live dependency analysis: graph, blast, drift, resolve, classpath. */
public final class DependencyTests {
    private DependencyTests() {}

    public static void run(Harness h) throws Exception {
        graph(h);
        resolve(h);
        blast(h);
        drift(h);
        classpath(h);
    }

    // ---------------------------------------------------------------- helpers

    /** Every node of a graph JSON tree (depth first). */
    static List<Object> nodes(Object list) {
        List<Object> out = new ArrayList<>();
        for (Object n : Json.list(list)) {
            out.add(n);
            out.addAll(nodes(Json.get(n, "dependencies")));
        }
        return out;
    }

    static Object module(Object doc, String artifactId) {
        for (Object m : Json.list(doc, "modules")) if (String.valueOf(Json.str(m, "module")).contains(":" + artifactId + ":")) return m;
        return null;
    }

    static Object find(List<Object> l, String key, String value) {
        for (Object o : l) if (value.equals(Json.str(o, key))) return o;
        return null;
    }

    static Object node(Object module, String ga, String version) {
        for (Object n : nodes(Json.get(module, "dependencies"))) {
            if ((Json.str(n, "groupId") + ":" + Json.str(n, "artifactId")).equals(ga) && (version == null || version.equals(Json.str(n, "version")))) return n;
        }
        return null;
    }

    static void publish(Harness h, String gav, String... deps) throws Exception {
        h.post("/_admin/publish", Json.obj("gav", gav, "deps", List.of(deps), "daysAgo", 0));
    }

    static Path pom(Harness h, String dir, String deps) throws Exception {
        Path d = h.root.resolve(dir);
        Files.createDirectories(d);
        Path p = d.resolve("pom.xml");
        Files.writeString(p, "<project><modelVersion>4.0.0</modelVersion><groupId>org.smtest</groupId><artifactId>" + dir + "</artifactId><version>1.0</version>"
                + "<dependencies>" + deps + "</dependencies></project>", StandardCharsets.UTF_8);
        return p;
    }

    static String dep(String g, String a, String v) {
        return "<dependency><groupId>" + g + "</groupId><artifactId>" + a + "</artifactId><version>" + v + "</version></dependency>";
    }

    // ---------------------------------------------------------------- graph

    static void graph(Harness h) throws Exception {
        Harness.Result r = h.onProject("graph", "--ascii");
        h.check("graph: tree exit 0", r.code == 0, r);
        h.check("graph: tree shows the downgrade winner and the omitted newer version",
                r.out.contains("com.fasterxml.jackson.core:jackson-databind:2.9.10.1") && r.out.contains("jackson-databind:2.18.2 [compile] omitted for conflict with 2.9.10.1"), r);
        h.check("graph: tree marks relocation, range and runtime scope",
                r.out.contains("relocated from mysql:mysql-connector-java:8.0.33") && r.out.contains("range [1.0,2.0)") && r.out.contains("8.0.33 [runtime]"), r);
        h.check("graph: tree has per-module statistics", r.out.contains("2 conflicts (2 downgrades)") && r.out.contains("com.acme.shop:shop-lib:3.2.0"), r);

        r = h.onProject("graph", "--json");
        Object doc = r.json();
        Object app = module(doc, "shop-app"), lib = module(doc, "shop-lib");
        h.check("graph: json has both modules", r.code == 0 && app != null && lib != null && Json.list(doc, "modules").size() == 2, r);
        Object mysql = node(app, "com.mysql:mysql-connector-j", "8.0.33");
        h.check("graph: json relocation + scope", mysql != null && "mysql:mysql-connector-java:8.0.33".equals(Json.str(mysql, "relocatedFrom")) && "runtime".equals(Json.str(mysql, "scope")), mysql);
        Object lost = node(app, "com.fasterxml.jackson.core:jackson-databind", "2.18.2");
        h.check("graph: json omitted node with winner", lost != null && "conflict".equals(Json.str(lost, "omitted")) && "2.9.10.1".equals(Json.str(lost, "winnerVersion")), lost);
        h.check("graph: json stats + conflicts", Json.num(app, -1, "stats", "downgrades") == 2 && Json.list(app, "conflicts").size() == 2
                && Json.bool(Json.list(app, "conflicts").get(0), false, "downgrade"), app);
        h.check("graph: json test scope in lib", "test".equals(Json.str(node(lib, "org.apache.logging.log4j:log4j-api", "2.17.1"), "scope")), lib);

        r = h.onProject("graph", "--json", "--filter", "com.fasterxml.jackson.core:jackson-databind");
        doc = r.json();
        app = module(doc, "shop-app");
        boolean onlyPaths = true;
        for (Object n : nodes(Json.get(app, "dependencies"))) {
            String a = Json.str(n, "artifactId");
            if (!a.equals("jackson-databind") && !a.equals("acme-utils")) onlyPaths = false;
        }
        h.check("graph: --filter keeps only paths to the match", r.code == 0 && onlyPaths && nodes(Json.get(app, "dependencies")).size() == 3
                && Json.list(module(doc, "shop-lib"), "dependencies").isEmpty(), r);

        r = h.onProject("graph", "--json", "--depth", "1");
        boolean flat = true;
        for (Object m : Json.list(r.json(), "modules")) for (Object n : Json.list(m, "dependencies")) if (Json.get(n, "dependencies") != null) flat = false;
        h.check("graph: --depth 1 shows direct dependencies only", r.code == 0 && flat, r);

        r = h.onProject("graph", "--json", "--scope", "runtime", "--module", "app");
        doc = r.json();
        List<Object> rt = nodes(Json.get(Json.list(doc, "modules").get(0), "dependencies"));
        h.check("graph: --scope runtime --module app", r.code == 0 && Json.list(doc, "modules").size() == 1 && rt.size() == 1
                && "mysql-connector-j".equals(Json.str(rt.get(0), "artifactId")), r);

        r = h.onProject("graph", "--format", "dot");
        h.check("graph: dot output", r.code == 0 && r.out.startsWith("digraph") && r.out.contains("\"com.acme.shop:shop-app:3.2.0\" -> \"com.mysql:mysql-connector-j:8.0.33\"")
                && r.out.contains("style=dashed") && r.out.trim().endsWith("}"), r);

        r = h.onProject("graph", "--format", "mermaid", "--module", "app");
        h.check("graph: mermaid output", r.code == 0 && r.out.startsWith("graph LR") && r.out.contains("-.->|omitted conflict|") && r.out.contains("classDef omitted"), r);

        Path html = h.root.resolve("out/graph.html");
        r = h.onProject("graph", "--format", "html", "--vulns", "-o", html.toString());
        String page = Files.isRegularFile(html) ? Files.readString(html) : "";
        h.check("graph: html written", r.code == 0 && r.out.contains("Wrote html graph") && page.startsWith("<!doctype html>"), r);
        h.check("graph: html is interactive and self-contained", page.contains("id=\"q\"") && page.contains("const DATA=") && page.contains("CVE-2021-44228")
                && !page.contains("src=\"http") && page.contains("prefers-color-scheme"), page.length() > 3000 ? page.substring(0, 3000) : page);

        r = h.onProject("graph", "--json", "--vulns");
        doc = r.json();
        Object log4j = node(module(doc, "shop-app"), "org.apache.logging.log4j:log4j-core", "2.14.1");
        h.check("graph: --vulns marks nodes", log4j != null && "critical".equals(Json.str(log4j, "severity"))
                && Json.list(log4j, "vulnerabilities").contains("CVE-2021-44228") && Json.get(doc, "vulnerabilities", "org.apache.logging.log4j:log4j-core:2.14.1") != null, log4j);

        r = h.run("graph", "org.springframework:spring-beans:5.3.17", "--ascii");
        h.check("graph: published coordinates", r.code == 0 && r.out.contains("org.springframework:spring-core:5.3.17") && r.out.contains("spring-jcl:5.3.17"), r);

        r = h.onProject("graph", "--format", "svg");
        h.check("graph: unknown format -> 2", r.code == 2, r);
        r = h.onProject("graph", "--depth", "0");
        h.check("graph: --depth 0 -> 2", r.code == 2, r);
        r = h.onProject("graph", "--scope", "bogus");
        h.check("graph: bad scope -> 2", r.code == 2, r);
        r = h.onProject("graph", "--module", "nope");
        h.check("graph: unknown module -> 2", r.code == 2 && r.err.contains("shop-app"), r);
    }

    // ---------------------------------------------------------------- resolve

    static void resolve(Harness h) throws Exception {
        Harness.Result r = h.onProject("resolve", "--ascii");
        h.check("resolve: downgrades -> exit 1", r.code == 1 && r.out.contains("DOWNGRADE"), r);
        h.check("resolve: explains jackson and acme-core", r.out.contains("jackson-databind  2.9.10.1 selected, 2.18.2 requested")
                && r.out.contains("com.acme:acme-core  1.0.0 selected, 1.1.0 requested") && r.out.contains("a direct declaration (depth 1) always wins"), r);
        h.check("resolve: prints dependencyManagement snippet", r.out.contains("<dependencyManagement>") && r.out.contains("<artifactId>jackson-databind</artifactId>")
                && r.out.contains("<version>2.18.2</version>") && r.out.contains("app/pom.xml line"), r);

        r = h.onProject("resolve", "--json");
        Object doc = r.json();
        List<Object> cs = Json.list(module(doc, "shop-app"), "conflicts");
        Object jk = find(cs, "artifact", "com.fasterxml.jackson.core:jackson-databind");
        h.check("resolve: json conflicts", r.code == 1 && cs.size() == 2 && jk != null && Json.bool(jk, false, "downgrade")
                && "direct".equals(Json.str(jk, "rule")) && "2.18.2".equals(Json.str(jk, "highestRequested")), r);
        boolean path = false;
        for (Object q : Json.list(jk, "requests")) if ("com.acme:acme-utils:1.2.0 -> com.fasterxml.jackson.core:jackson-databind:2.18.2".equals(Json.str(q, "path"))) path = true;
        h.check("resolve: competing path", path, jk);
        h.check("resolve: fix points at the declaration", "update-direct".equals(Json.str(jk, "fix", "action")) && "app/pom.xml".equals(Json.str(jk, "fix", "file"))
                && Json.num(jk, 0, "fix", "line") > 0, jk);
        h.check("resolve: summary", Json.num(doc, -1, "summary", "downgrades") == 2 && Json.list(module(doc, "shop-lib"), "conflicts").isEmpty()
                && String.valueOf(Json.str(doc, "fix", "dependencyManagement")).contains("<artifactId>acme-core</artifactId>"), doc);

        r = h.onProject("resolve", "--json", "--pin", "com.fasterxml.jackson.core:jackson-databind:2.18.2");
        doc = r.json();
        Object sim = find(Json.list(doc, "simulation", "modules"), "module", "com.acme.shop:shop-app:3.2.0");
        Object ch = find(Json.list(sim, "changes"), "artifact", "com.fasterxml.jackson.core:jackson-databind");
        Object chCore = find(Json.list(sim, "changes"), "artifact", "com.fasterxml.jackson.core:jackson-core");
        h.check("resolve: --pin simulates the upgrade and its transitive effect", ch != null && "2.18.2".equals(Json.str(ch, "to")) && "upgraded".equals(Json.str(ch, "kind"))
                && chCore != null && "2.18.2".equals(Json.str(chCore, "to")), sim);
        h.check("resolve: --pin leaves acme-core downgraded -> exit 1", r.code == 1 && Json.num(doc, -1, "simulation", "downgradesAfter") == 1, r);

        r = h.onProject("resolve", "--fix", "--ascii");
        h.check("resolve: --fix removes every downgrade -> exit 0", r.code == 0 && r.out.contains("Downgrades: 2 -> 0"), r);

        r = h.onProject("resolve", "--json", "--set", "com.acme:acme-core:1.1.0", "--filter", "acme-core");
        doc = r.json();
        h.check("resolve: --set + --filter", r.code == 0 && Json.list(module(doc, "shop-app"), "conflicts").size() == 1
                && Json.num(doc, -1, "simulation", "downgradesAfter") == 0, r);

        r = h.onProject("resolve", "--pin", "com.fasterxml.jackson.core:jackson-databind:9.9.9");
        h.check("resolve: pin to a missing version -> 2", r.code == 2 && r.err.contains("does not exist"), r);
        r = h.onProject("resolve", "--pin", "com.fasterxml.jackson.core:jackson-databind");
        h.check("resolve: pin without version -> 2", r.code == 2, r);
        r = h.onProject("resolve", "--set", "com.fasterxml.jackson.core:jackson-core:2.18.2");
        h.check("resolve: --set on a transitive artifact -> 2", r.code == 2 && r.err.contains("--pin"), r);
        r = h.onProject("resolve", "--module", "lib");
        h.check("resolve: module without conflicts -> 0", r.code == 0 && r.out.contains("No version conflicts"), r);

        // Transitive conflicts on published artifacts: nearest wins, and first declaration wins.
        publish(h, "org.smres:c:1.0.0");
        publish(h, "org.smres:c:2.0.0");
        publish(h, "org.smres:a:1.0.0", "org.smres:c:1.0.0");
        publish(h, "org.smres:b:1.0.0", "org.smres:c:2.0.0");
        publish(h, "org.smres:mid:1.0.0", "org.smres:b:1.0.0");
        publish(h, "org.smres:near:1.0.0", "org.smres:mid:1.0.0", "org.smres:a:1.0.0");
        publish(h, "org.smres:first:1.0.0", "org.smres:a:1.0.0", "org.smres:b:1.0.0");
        r = h.run("resolve", "org.smres:near:1.0.0", "--json");
        Object c = Json.list(Json.list(r.json(), "modules").get(0), "conflicts").isEmpty() ? null : Json.list(Json.list(r.json(), "modules").get(0), "conflicts").get(0);
        h.check("resolve: nearest wins on a published artifact", r.code == 1 && c != null && "nearest".equals(Json.str(c, "rule")) && "1.0.0".equals(Json.str(c, "selected"))
                && Json.bool(c, false, "majorGap") && "high".equals(Json.str(c, "severity")) && "manage".equals(Json.str(c, "fix", "action")), r);
        r = h.run("resolve", "org.smres:first:1.0.0", "--json");
        c = Json.list(Json.list(r.json(), "modules").get(0), "conflicts").isEmpty() ? null : Json.list(Json.list(r.json(), "modules").get(0), "conflicts").get(0);
        h.check("resolve: first declaration wins", r.code == 1 && c != null && "first-declaration".equals(Json.str(c, "rule")) && "1.0.0".equals(Json.str(c, "selected")), r);
        r = h.run("resolve", "org.smres:near:1.0.0", "--pin", "org.smres:c:2.0.0", "--json");
        h.check("resolve: pinning the transitive artifact fixes it", r.code == 0 && Json.num(r.json(), -1, "simulation", "downgradesAfter") == 0
                && String.valueOf(Json.str(r.json(), "simulation", "dependencyManagement")).contains("<version>2.0.0</version>"), r);
    }

    // ---------------------------------------------------------------- blast

    static void blast(Harness h) throws Exception {
        Harness.Result r = h.onProject("blast", "org.apache.logging.log4j:log4j-core", "--json");
        Object doc = r.json();
        Object v2141 = find(Json.list(doc, "central", "versions"), "version", "2.14.1");
        h.check("blast: central dependents per version", r.code == 0 && v2141 != null && Json.num(v2141, -1, "totalDependents") == 4200
                && Json.num(v2141, -1, "directDependents") == 1900 && Json.num(v2141, -1, "indirectDependents") == 2300, r);
        h.check("blast: vulnerable dependents", Json.list(v2141, "vulnerabilities").contains("CVE-2021-44228") && Json.num(doc, -1, "central", "vulnerableDependents") >= 4200
                && Json.bool(v2141, false, "usedByProject"), v2141);
        Object appMod = find(Json.list(doc, "project", "modules"), "path", "app");
        Object occ = Json.list(appMod, "occurrences").isEmpty() ? null : Json.list(appMod, "occurrences").get(0);
        h.check("blast: project paths", Json.bool(doc, false, "usedByProject") && Json.num(doc, -1, "project", "modulesUsing") == 1
                && occ != null && Json.bool(occ, false, "direct") && "org.apache.logging.log4j:log4j-core:2.14.1".equals(Json.str(occ, "path")), doc);

        r = h.onProject("blast", "org.apache.logging.log4j:log4j-core:2.14.1", "--deep", "--fail", "--json");
        doc = r.json();
        Object emb = Json.list(doc, "project", "embedded").isEmpty() ? null : Json.list(doc, "project", "embedded").get(0);
        h.check("blast: --deep finds the shaded copy in acme-fat", emb != null && "com.acme:acme-fat:1.0.0".equals(Json.str(emb, "host"))
                && "org.apache.logging.log4j:log4j-core:2.14.1".equals(Json.str(emb, "embeds")), doc);
        h.check("blast: --fail when used -> 1", r.code == 1, r);

        r = h.onProject("blast", "com.acme:acme-core:1.1.0", "--json", "--fail");
        doc = r.json();
        Object omitted = null;
        for (Object m : Json.list(doc, "project", "modules")) for (Object o : Json.list(m, "occurrences")) if ("1.1.0".equals(Json.str(o, "version"))) omitted = o;
        h.check("blast: omitted request shows the winner", r.code == 0 && !Json.bool(doc, true, "usedByProject") && omitted != null
                && "conflict".equals(Json.str(omitted, "omitted")) && "1.0.0".equals(Json.str(omitted, "winnerVersion"))
                && "com.acme:acme-utils:1.2.0".equals(Json.str(omitted, "via")), doc);

        r = h.onProject("blast", "org.apache.logging.log4j:*", "--json");
        doc = r.json();
        h.check("blast: glob searches the project only", r.code == 0 && Json.get(doc, "central") == null && Json.num(doc, -1, "project", "modulesUsing") == 2, r);
        r = h.onProject("blast", "org.apache.logging.log4j:*", "--json", "--no-test");
        h.check("blast: --no-test drops the test-scoped use", Json.num(r.json(), -1, "project", "modulesUsing") == 1, r);

        java.nio.file.Path empty = java.nio.file.Files.createDirectories(h.root.resolve("no-project"));
        r = h.run("blast", "com.google.guava:guava:31.1-jre", "-f", empty.toString(), "--json");
        doc = r.json();
        Object g = find(Json.list(doc, "central", "versions"), "version", "31.1-jre");
        h.check("blast: without a project", r.code == 0 && Json.get(doc, "project") == null && g != null && Json.num(g, -1, "totalDependents") == 28000
                && Json.bool(g, false, "requested"), r);

        r = h.onProject("blast", "org.apache.logging.log4j:log4j-core", "--ascii");
        h.check("blast: human output", r.code == 0 && r.out.contains("packages depend on the versions shown") && r.out.contains("used by project")
                && r.out.contains("1 module of 2 uses"), r);

        r = h.run("blast");
        h.check("blast: missing artifact -> 2", r.code == 2, r);
        r = h.run("blast", "org.nothing:nowhere");
        h.check("blast: unknown artifact -> 2", r.code == 2 && r.err.contains("not found"), r);
        r = h.run("blast", "com.google.guava:guava:0.0.1");
        h.check("blast: unknown version -> 2", r.code == 2 && r.err.contains("does not exist"), r);
    }

    // ---------------------------------------------------------------- drift

    static void drift(Harness h) throws Exception {
        publish(h, "org.smdrift:dcore:1.0.0");
        publish(h, "org.smdrift:dlib:1.0.0", "org.smdrift:dcore:[1.0,2.0)");
        Path pom = pom(h, "drift-proj", dep("org.smdrift", "dlib", "1.0.0") + dep("org.example", "widgets", "1.0.0"));
        Path snap = pom.getParent().resolve(".sm-maven/drift.json");
        String f = pom.toString();

        Harness.Result r = h.run("drift", "-f", f, "--ascii");
        h.check("drift: first run records the snapshot", r.code == 0 && r.out.contains("Snapshot recorded") && Files.isRegularFile(snap), r);
        Object snapDoc = Files.isRegularFile(snap) ? Json.parse(Files.readString(snap)) : null;
        h.check("drift: snapshot content", "1.0.0".equals(Json.str(snapDoc, "modules", "org.smtest:drift-proj", "org.smdrift:dcore", "version"))
                && "[1.0,2.0)".equals(Json.str(snapDoc, "modules", "org.smtest:drift-proj", "org.smdrift:dcore", "range"))
                && !Json.bool(snapDoc, true, "modules", "org.smtest:drift-proj", "org.smdrift:dcore", "direct"), snapDoc);

        r = h.run("drift", "-f", f, "--json");
        h.check("drift: unchanged -> 0", r.code == 0 && Json.num(r.json(), -1, "total") == 0, r);

        // A new release inside the range moves the undeclared transitive version.
        publish(h, "org.smdrift:dcore:1.1.0");
        h.clearHooks();
        r = h.runWith(Map.of("SM_MAVEN_WEBHOOK", h.mock.base() + "/hooks/drift"), "drift", "-f", f, "--json");
        Object doc = r.json();
        Object fd = Json.list(doc, "findings").isEmpty() ? null : Json.get(Json.list(doc, "findings").get(0), "finding");
        h.check("drift: range drift detected -> 1", r.code == 1 && Json.num(doc, -1, "total") == 1 && fd != null
                && "org.smdrift:dcore".equals(Json.str(fd, "artifact")) && "1.0.0".equals(Json.str(fd, "from")) && "1.1.0".equals(Json.str(fd, "to"))
                && !Json.bool(fd, true, "direct") && "upgraded".equals(Json.str(fd, "change")), r);
        h.check("drift: reason names the range", fd != null && String.valueOf(Json.str(fd, "reason")).contains("range [1.0,2.0) now resolves to 1.1.0"), fd);
        String hooks = Json.write(h.hookLog());
        h.check("drift: alert sent for new drift", hooks.contains("org.smdrift:dcore") && hooks.contains("\"hook\": \"drift\""), hooks);

        r = h.run("drift", "-f", f, "--ascii");
        h.check("drift: still drifted -> 1 (human)", r.code == 1 && r.out.contains("upgraded") && r.out.contains("now resolves to 1.1.0") && r.out.contains("--baseline"), r);

        // A direct change is reported too, but not with --transitive.
        pom(h, "drift-proj", dep("org.smdrift", "dlib", "1.0.0") + dep("org.example", "widgets", "2.0.0"));
        r = h.run("drift", "-f", f, "--json");
        Object w = null;
        for (Object x : Json.list(r.json(), "findings")) if ("org.example:widgets".equals(Json.str(x, "finding", "artifact"))) w = Json.get(x, "finding");
        h.check("drift: direct major change is high severity", r.code == 1 && w != null && Json.bool(w, false, "direct") && "high".equals(Json.str(w, "severity")), r);
        r = h.run("drift", "-f", f, "--json", "--transitive");
        h.check("drift: --transitive hides declared changes", r.code == 1 && Json.num(r.json(), -1, "total") == 1, r);

        r = h.run("drift", "-f", f, "--baseline");
        h.check("drift: --baseline accepts", r.code == 0 && r.out.contains("Snapshot recorded"), r);
        r = h.run("drift", "-f", f, "--json");
        h.check("drift: no drift after accepting", r.code == 0 && Json.num(r.json(), -1, "total") == 0, r);

        Path custom = h.root.resolve("snapshots/custom.json");
        r = h.run("drift", "-f", f, "--snapshot", custom.toString());
        h.check("drift: --snapshot path", r.code == 0 && Files.isRegularFile(custom), r);
        Files.writeString(custom, "[1,2,3]");
        r = h.run("drift", "-f", f, "--snapshot", custom.toString());
        h.check("drift: corrupt snapshot -> 2", r.code == 2 && r.err.contains("not a drift snapshot"), r);

        r = h.run("drift", "org.smdrift:dlib:1.0.0", "--json");
        h.check("drift: published coordinates record a snapshot", r.code == 0, r);
        r = h.run("drift", "-f", f, "not-coordinates");
        h.check("drift: bad positional -> 2", r.code == 2, r);
    }

    // ---------------------------------------------------------------- classpath

    static void classpath(Harness h) throws Exception {
        Harness.Result r = h.onProject("classpath", "--json");
        Object doc = r.json();
        Object app = module(doc, "shop-app");
        h.check("classpath: conflicts -> exit 1", r.code == 1 && Json.num(doc, -1, "summary", "conflictingDuplicates") >= 2, r);
        Object jcl = null, fat = null;
        for (Object d : Json.list(app, "duplicates")) {
            List<Object> jars = Json.list(d, "jars");
            if (jars.contains("commons-logging:commons-logging:1.2") && jars.contains("org.slf4j:jcl-over-slf4j:1.7.36") && Json.list(d, "examples").contains("org.apache.commons.logging.LogFactory")) jcl = d;
            if (jars.contains("com.acme:acme-fat:1.0.0") && jars.contains("org.apache.logging.log4j:log4j-core:2.14.1")) fat = d;
        }
        h.check("classpath: commons-logging vs jcl-over-slf4j differ", jcl != null && "conflict".equals(Json.str(jcl, "severity")) && Json.num(jcl, 0, "conflicting") >= 1
                && "commons-logging:commons-logging:1.2".equals(Json.str(jcl, "winner")), app);
        h.check("classpath: acme-fat duplicates log4j's JndiLookup", fat != null && Json.list(fat, "examples").contains("org.apache.logging.log4j.core.lookup.JndiLookup"), app);
        h.check("classpath: split package", find(Json.list(app, "splitPackages"), "package", "org.apache.commons.logging") != null, app);
        Object sh = Json.list(app, "shaded").isEmpty() ? null : Json.list(app, "shaded").get(0);
        h.check("classpath: shaded log4j-core inside acme-fat", sh != null && "com.acme:acme-fat:1.0.0".equals(Json.str(sh, "jar"))
                && "org.apache.logging.log4j:log4j-core:2.14.1".equals(Json.str(sh, "embeds")) && Json.bool(sh, false, "sameVersion")
                && Json.num(sh, 0, "relocatedClasses") >= 1 && "both".equals(Json.str(sh, "evidence")), sh);
        Object first = Json.list(app, "classpath").get(0);
        h.check("classpath: own classes first on the classpath", "classes".equals(Json.str(first, "source")), first);

        r = h.onProject("classpath", "--module", "lib", "--ascii");
        h.check("classpath: clean module -> 0", r.code == 0 && r.out.contains("No duplicate classes"), r);

        r = h.onProject("classpath", "--json", "--scope", "compile,runtime,test");
        Object skew = find(Json.list(r.json(), "versionSkew"), "artifact", "org.apache.logging.log4j:log4j-api");
        h.check("classpath: version skew across modules", skew != null && "2.17.1".equals(Json.str(skew, "versions", "com.acme.shop:shop-lib:3.2.0")), r);

        r = h.onProject("classpath", "--ascii");
        h.check("classpath: human output", r.code == 1 && r.out.contains("with different bytes") && r.out.contains("bundles org.apache.logging.log4j:log4j-core:2.14.1")
                && r.out.contains("Split packages"), r);

        // Identical copy: a project that ships the very same class file as one of its dependencies.
        Path p = pom(h, "cp-proj", dep("org.springframework", "spring-jcl", "5.3.17"));
        byte[] jar = Files.readAllBytes(h.fx.repo.resolve("org/springframework/spring-jcl/5.3.17/spring-jcl-5.3.17.jar"));
        byte[] cls = null;
        try (ZipInputStream z = new ZipInputStream(new ByteArrayInputStream(jar))) {
            for (ZipEntry e; (e = z.getNextEntry()) != null; ) if (e.getName().equals("org/apache/commons/logging/Log.class")) cls = z.readAllBytes();
        }
        Path target = p.getParent().resolve("target/classes/org/apache/commons/logging/Log.class");
        Files.createDirectories(target.getParent());
        Files.write(target, cls == null ? new byte[0] : cls);
        r = h.run("classpath", "-f", p.toString(), "--json");
        Object d = Json.list(Json.list(r.json(), "modules").get(0), "duplicates").isEmpty() ? null : Json.list(Json.list(r.json(), "modules").get(0), "duplicates").get(0);
        h.check("classpath: identical duplicate is harmless -> 0", r.code == 0 && d != null && "harmless".equals(Json.str(d, "severity")) && Json.num(d, -1, "identical") == 1, r);
        r = h.run("classpath", "-f", p.toString(), "--strict");
        h.check("classpath: --strict fails on harmless duplicates", r.code == 1, r);

        r = h.run("classpath", "com.acme:acme-fat:1.0.0", "--json");
        sh = Json.list(Json.list(r.json(), "modules").get(0), "shaded").isEmpty() ? null : Json.list(Json.list(r.json(), "modules").get(0), "shaded").get(0);
        h.check("classpath: published artifact's embedded copy", r.code == 1 && sh != null && "pom.properties".equals(Json.str(sh, "evidence")), r);

        r = h.onProject("classpath", "--scope", "everything");
        h.check("classpath: bad scope -> 2", r.code == 2, r);
    }
}
