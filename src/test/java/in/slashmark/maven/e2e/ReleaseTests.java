package in.slashmark.maven.e2e;

import in.slashmark.maven.util.Json;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Release intelligence: radar, pulse, breakcheck, adoption, relocations. */
public final class ReleaseTests {
    private ReleaseTests() {}

    public static void run(Harness h) throws Exception {
        radar(h);
        pulse(h);
        breakcheck(h);
        adoption(h);
        relocations(h);
    }

    // ---------------------------------------------------------------- helpers

    /** Watcher findings ("finding" objects) of a radar/relocations JSON document. */
    static List<Object> findings(Object doc) {
        List<Object> out = new ArrayList<>();
        for (Object f : Json.list(doc, "findings")) out.add(Json.get(f, "finding"));
        return out;
    }

    static Object find(List<Object> list, String field, String value, String field2, String value2) {
        for (Object o : list) {
            if (value.equals(Json.str(o, field)) && (field2 == null || value2.equals(Json.str(o, field2)))) return o;
        }
        return null;
    }

    static Object byGa(List<Object> list, String ga) {
        String[] p = ga.split(":");
        return find(list, "groupId", p[0], "artifactId", p[1]);
    }

    static Object impact(Object comparison, String kind, String type) {
        for (Object i : Json.list(comparison, "impacts")) if (kind.equals(Json.str(i, "kind")) && (type == null || type.equals(Json.str(i, "type")))) return i;
        return null;
    }

    static List<Object> hooksFor(Harness h, String hook) throws Exception {
        List<Object> out = new ArrayList<>();
        for (Object o : Json.list(h.hookLog())) if (hook.equals(Json.str(o, "hook"))) out.add(o);
        return out;
    }

    static void publish(Harness h, String gav, int daysAgo, String... deps) throws Exception {
        h.post("/_admin/publish", Json.obj("gav", gav, "daysAgo", daysAgo, "deps", List.of((Object[]) deps)));
    }

    // ---------------------------------------------------------------- radar

    static void radar(Harness h) throws Exception {
        Harness.Result r = h.onProject("radar", "--reset", "--json");
        Object doc = r.json();
        List<Object> f = findings(doc);
        h.check("radar: first run on the project finds newer releases (exit 1, all new)",
                r.code == 1 && doc != null && "radar".equals(Json.str(doc, "tool")) && Json.num(doc, -1, "new") == f.size() && f.size() > 5, r);
        Object core = find(f, "artifactId", "acme-core", "version", "2.0.0");
        h.check("radar: acme-core 1.0.0 -> 2.0.0 is a major jump with release date and age",
                core != null && "1.0.0".equals(Json.str(core, "current")) && "major".equals(Json.str(core, "jump"))
                        && Json.num(core, -1, "ageDays") == 20 && Json.str(core, "releasedAt") != null && Json.bool(core, false, "direct"), r);
        Object log4j = find(f, "artifactId", "log4j-core", "version", "2.24.3");
        h.check("radar: log4j-core 2.14.1 -> 2.24.3 is a minor jump released 60 days ago",
                log4j != null && "2.14.1".equals(Json.str(log4j, "current")) && "minor".equals(Json.str(log4j, "jump")) && Json.num(log4j, -1, "ageDays") == 60, r);
        Object jackson = find(f, "artifactId", "jackson-databind", "version", "2.18.2");
        h.check("radar: resolved jackson-databind 2.9.10.1 (not the requested 2.18.2) is compared",
                jackson != null && "2.9.10.1".equals(Json.str(jackson, "current")), r);
        h.check("radar: direct only by default (no transitive jackson-core)", byGa(f, "com.fasterxml.jackson.core:jackson-core") == null, r);
        boolean keyed = true;
        for (Object x : Json.list(doc, "findings")) keyed &= Json.str(x, "key") != null && Json.str(x, "key").contains("@");
        h.check("radar: findings carry stable keys and severity", keyed && "medium".equals(Json.str(Json.list(doc, "findings").stream()
                .filter(x -> Json.str(x, "key").startsWith("com.acme:acme-core:2.0.0@")).findFirst().orElse(null), "severity")), r);

        r = h.onProject("radar", "--json");
        h.check("radar: unchanged second run reports nothing new (exit 0)", r.code == 0 && Json.num(r.json(), -1, "new") == 0, r);

        r = h.onProject("radar", "--transitive", "--reset", "--json");
        f = findings(r.json());
        Object jcore = byGa(f, "com.fasterxml.jackson.core:jackson-core");
        h.check("radar --transitive includes transitive dependencies", jcore != null && !Json.bool(jcore, true, "direct"), r);

        r = h.onProject("radar", "--min-jump", "major", "--reset", "--json");
        f = findings(r.json());
        boolean onlyMajor = !f.isEmpty();
        for (Object x : f) onlyMajor &= "major".equals(Json.str(x, "jump"));
        h.check("radar --min-jump major keeps only major jumps", onlyMajor && find(f, "artifactId", "acme-core", "version", "2.0.0") != null, r);

        r = h.onProject("radar", "--since", "30d", "--reset", "--json");
        f = findings(r.json());
        h.check("radar --since 30d keeps recent releases only",
                find(f, "artifactId", "acme-core", "version", "2.0.0") != null && byGa(f, "org.apache.logging.log4j:log4j-core") == null
                        && find(f, "artifactId", "acme-core", "version", "1.1.0") == null, r);

        r = h.onProject("radar", "--reset");
        h.check("radar human output: table with jump and latest version",
                r.code == 1 && r.out.contains("Release Radar") && r.out.contains("com.acme:acme-core") && r.out.contains("major") && r.out.contains("First check"), r);

        r = h.onProject("radar", "--min-jump", "huge");
        h.check("radar: bad --min-jump -> exit 2", r.code == 2 && r.err.contains("--min-jump"), r);
        r = h.onProject("radar", "--since", "soon");
        h.check("radar: bad --since -> exit 2", r.code == 2, r);
        r = h.run("radar", "org.nope:missing:1.0");
        h.check("radar: unknown coordinates -> exit 2", r.code == 2 && r.err.contains("not found"), r);

        // Live feed on an isolated artifact: alerts only on versions published since the last check.
        publish(h, "in.slashmark.radar:radar-dep:1.0.0", 40);
        publish(h, "in.slashmark.radar:radar-app:1.0.0", 30, "in.slashmark.radar:radar-dep:1.0.0");
        Map<String, String> hook = Map.of("SM_MAVEN_WEBHOOK", h.mock.base() + "/hooks/radar-feed");
        h.clearHooks();
        r = h.runWith(hook, "radar", "in.slashmark.radar:radar-app:1.0.0", "--json");
        h.check("radar watch: nothing newer at first -> exit 0, no alert",
                r.code == 0 && Json.num(r.json(), -1, "total") == 0 && hooksFor(h, "radar-feed").isEmpty(), r);
        publish(h, "in.slashmark.radar:radar-dep:1.1.0", 0);
        r = h.runWith(hook, "radar", "in.slashmark.radar:radar-app:1.0.0", "--json");
        f = findings(r.json());
        List<Object> sent = hooksFor(h, "radar-feed");
        h.check("radar watch: newly published 1.1.0 is detected immediately (no stale cache) -> exit 1",
                r.code == 1 && Json.num(r.json(), -1, "new") == 1 && find(f, "artifactId", "radar-dep", "version", "1.1.0") != null
                        && "minor".equals(Json.str(find(f, "artifactId", "radar-dep", "version", "1.1.0"), "jump")), r);
        h.check("radar watch: webhook alert names the new release",
                sent.size() == 1 && "radar".equals(Json.str(sent.get(0), "body", "tool"))
                        && String.valueOf(Json.get(sent.get(0), "body", "lines")).contains("radar-dep 1.0.0 -> 1.1.0"), sent);
        h.check("radar watch: webhook URL is never printed", !r.out.contains("/hooks/") && !r.err.contains("/hooks/"), r);
        h.clearHooks();
        r = h.runWith(hook, "radar", "in.slashmark.radar:radar-app:1.0.0");
        h.check("radar watch: next cycle without new releases does not alert again",
                r.code == 0 && hooksFor(h, "radar-feed").isEmpty() && r.out.contains("No new releases since the last check"), r);
        publish(h, "in.slashmark.radar:radar-dep:2.0.0", 0);
        publish(h, "in.slashmark.radar:radar-dep:3.0.0-RC1", 0);
        r = h.runWith(hook, "radar", "in.slashmark.radar:radar-app:1.0.0");
        sent = hooksFor(h, "radar-feed");
        h.check("radar watch: major release alerts with medium severity; pre-releases hidden by default",
                r.code == 1 && r.out.contains("New since the last check (1)") && r.out.contains("2.0.0") && !r.out.contains("3.0.0-RC1")
                        && sent.size() == 1 && "medium".equals(Json.str(sent.get(0), "body", "severity")), r);
        r = h.run("radar", "in.slashmark.radar:radar-app:1.0.0", "--pre", "--json");
        Object rc = find(findings(r.json()), "artifactId", "radar-dep", "version", "3.0.0-RC1");
        h.check("radar --pre includes pre-releases", rc != null && Json.bool(rc, false, "preRelease"), r);
        r = h.run("radar", "in.slashmark.radar:radar-app:1.0.0", "--watch", "--cycles", "1", "--json");
        h.check("radar --watch --cycles 1 runs one live cycle", r.code == 0 && r.jsonLines().size() == 1 && Json.num(r.jsonLines().get(0), -1, "cycle") == 1, r);
    }

    // ---------------------------------------------------------------- pulse

    static void pulse(Harness h) {
        Harness.Result r = h.onProject("pulse", "--json");
        Object doc = r.json();
        List<Object> deps = Json.list(doc, "dependencies");
        Object utils = byGa(deps, "com.acme:acme-utils");
        h.check("pulse: archived acme-utils makes the run fail (exit 1)", r.code == 1 && utils != null, r);
        h.check("pulse: acme-utils is high risk with the archived reason",
                utils != null && "high".equals(Json.str(utils, "risk", "level")) && Json.num(utils, 0, "risk", "score") >= 50
                        && String.valueOf(Json.get(utils, "risk", "reasons")).contains("archived")
                        && Json.bool(utils, false, "repository", "archived") && Json.num(utils, -1, "repository", "commits90d") == 0, r);
        h.check("pulse: release cadence from Central (median 270 days, last release 380 days ago)",
                utils != null && Json.num(utils, -1, "releases", "medianDaysBetween") == 270 && Json.num(utils, -1, "releases", "lastReleaseDays") == 380
                        && Json.num(utils, -1, "releases", "count") == 2, r);
        h.check("pulse: deps.dev Scorecard is attached", utils != null && Json.dbl(utils, -1, "scorecard", "score") == 2.8
                && Json.num(utils, -1, "scorecard", "maintained") == 0, r);
        Object log4j = byGa(deps, "org.apache.logging.log4j:log4j-core");
        h.check("pulse: active log4j is low risk with GitHub activity",
                log4j != null && "low".equals(Json.str(log4j, "risk", "level")) && Json.num(log4j, -1, "repository", "commits90d") == 140
                        && Json.num(log4j, -1, "repository", "contributors90d") == 40 && "apache/logging-log4j2".equals(Json.str(log4j, "repository", "github")), r);
        h.check("pulse: riskiest first and summary counts", !deps.isEmpty() && "com.acme:acme-utils".equals(Json.str(deps.get(0), "groupId") + ":" + Json.str(deps.get(0), "artifactId"))
                && Json.num(doc, -1, "summary", "high") == 1 && Json.num(doc, -1, "summary", "total") == deps.size(), r);
        Object cl = byGa(deps, "commons-logging:commons-logging");
        h.check("pulse: no source repository and a 10-year-old release is medium risk",
                cl != null && "medium".equals(Json.str(cl, "risk", "level")) && Json.get(cl, "repository", "github") == null, r);

        r = h.onProject("pulse");
        h.check("pulse human output explains why", r.code == 1 && r.out.contains("Project Pulse") && r.out.contains("HIGH")
                && r.out.contains("acme-corp/acme-utils is archived") && r.out.contains("abandoned"), r);
        r = h.onProject("pulse", "--fail-on", "none");
        h.check("pulse --fail-on none -> exit 0", r.code == 0, r);
        r = h.onProject("pulse", "--fail-on", "sometimes");
        h.check("pulse: bad --fail-on -> exit 2", r.code == 2, r);
        r = h.onProject("pulse", "--no-github", "--json");
        Object u2 = byGa(Json.list(r.json(), "dependencies"), "com.acme:acme-utils");
        h.check("pulse --no-github skips GitHub (falls back to the Scorecard 'Maintained' check)",
                r.code == 0 && u2 != null && !Json.bool(u2, true, "repository", "checked") && "medium".equals(Json.str(u2, "risk", "level"))
                        && String.valueOf(Json.get(u2, "risk", "reasons")).contains("Maintained"), r);
        r = h.onProject("pulse", "-n", "2", "--json");
        h.check("pulse --limit shows the riskiest n", Json.list(r.json(), "dependencies").size() == 2 && Json.num(r.json(), -1, "summary", "total") > 2, r);
        r = h.run("pulse", "com.acme:acme-utils:1.2.0", "--json");
        List<Object> d2 = Json.list(r.json(), "dependencies");
        h.check("pulse on coordinates checks that artifact's dependencies",
                r.code == 0 && d2.size() == 2 && byGa(d2, "com.acme:acme-core") != null && "1.1.0".equals(Json.str(byGa(d2, "com.acme:acme-core"), "version")), r);
        r = h.onProject("pulse", "--transitive", "--json");
        h.check("pulse --transitive adds transitive dependencies",
                byGa(Json.list(r.json(), "dependencies"), "com.google.guava:failureaccess") != null, r);
    }

    // ---------------------------------------------------------------- breakcheck

    static void breakcheck(Harness h) {
        Harness.Result r = h.onProject("breakcheck", "com.acme:acme-core:2.0.0", "--json");
        Object doc = r.json();
        Object c = Json.list(doc, "comparisons").isEmpty() ? null : Json.list(doc, "comparisons").get(0);
        h.check("breakcheck: acme-core 1.0.0 -> 2.0.0 breaks the project (exit 1)",
                r.code == 1 && c != null && "1.0.0".equals(Json.str(c, "from")) && "2.0.0".equals(Json.str(doc, "to")) && !Json.bool(doc, true, "safe")
                        && Json.num(doc, -1, "breaks") == 4, r);
        Object rm = impact(c, "method-removed", "com.acme.core.Client");
        h.check("breakcheck: removed Client.connect(String) is called by App",
                rm != null && Json.str(rm, "member").startsWith("connect(String)") && Json.list(rm, "usedBy").contains("com.acme.shop.App"), r);
        Object fin = impact(c, "type-final", "com.acme.core.Config");
        h.check("breakcheck: Config made final hits the ShopConfig subclass", fin != null && Json.list(fin, "usedBy").contains("com.acme.shop.App$ShopConfig"), r);
        Object abs = impact(c, "abstract-method-added", "com.acme.core.Handler");
        h.check("breakcheck: new abstract Handler.onError hits the implementing App",
                abs != null && Json.str(abs, "member").startsWith("onError") && Json.list(abs, "usedBy").contains("com.acme.shop.App"), r);
        Object cv = impact(c, "class-version", null);
        h.check("breakcheck: class file 61 (Java 17) vs project Java 11",
                cv != null && Json.str(cv, "detail").contains("61") && Json.num(c, -1, "projectJava") == 11 && Json.num(doc, -1, "toJava") == 17, r);
        h.check("breakcheck: only the module that uses it is analysed", Json.list(c, "modules").equals(List.of("shop-app"))
                && Json.num(c, -1, "consumerClasses") >= 2, r);

        r = h.onProject("breakcheck", "com.acme:acme-core:2.0.0");
        h.check("breakcheck human output names the calling classes",
                r.code == 1 && r.out.contains("METHOD REMOVED") && r.out.contains("com.acme.core.Client.connect(String)")
                        && r.out.contains("used by com.acme.shop.App") && r.out.contains("JAVA VERSION") && r.out.contains("4 breaking changes hit"), r);
        r = h.onProject("breakcheck", "com.acme:acme-core", "--java", "17", "--json");
        h.check("breakcheck: default target is the newest release; --java 17 removes the class-version break",
                r.code == 1 && !"1.0.0".equals(Json.str(r.json(), "to")) && impact(Json.list(r.json(), "comparisons").get(0), "class-version", null) == null
                        && Json.num(r.json(), -1, "breaks") >= 3, r);
        r = h.onProject("breakcheck", "com.acme:acme-core:2.0.0", "--from", "1.1.0", "--all", "--json");
        Object c2 = Json.list(r.json(), "comparisons").get(0);
        boolean fetchAllUnused = false;
        for (Object u : Json.list(c2, "unusedBreaking")) if (String.valueOf(Json.str(u, "member")).startsWith("fetchAll")) fetchAllUnused = true;
        h.check("breakcheck --from/--all: fetchAll removal is listed as not touching the code", r.code == 1 && fetchAllUnused
                && impact(c2, "method-removed", "com.acme.core.Client") != null, r);
        r = h.onProject("breakcheck", "com.google.guava:guava", "--deps", "--json");
        h.check("breakcheck: guava upgrade does not touch the code (exit 0, safe)", r.code == 0 && Json.bool(r.json(), false, "safe")
                && Json.num(r.json(), -1, "breaks") == 0, r);
        r = h.run("breakcheck", "com.acme:acme-core:2.0.0", "--from", "1.1.0", "--json");
        h.check("breakcheck without a project: every breaking change is potential (exit 1)",
                r.code == 1 && !Json.bool(r.json(), true, "compiled") && Json.num(r.json(), -1, "potential") == 4, r);
        r = h.onProject("breakcheck");
        h.check("breakcheck: missing coordinates -> exit 2", r.code == 2, r);
        r = h.onProject("breakcheck", "org.nope:missing:1.0");
        h.check("breakcheck: unknown artifact -> exit 2", r.code == 2 && r.err.contains("not found"), r);
        r = h.onProject("breakcheck", "com.acrne:acme-core:9.9.9");
        h.check("breakcheck: artifact the project does not use -> exit 2", r.code == 2 && r.err.contains("does not depend"), r);
        r = h.run("breakcheck", "com.acme:acme-core:2.0.0");
        h.check("breakcheck: no project and no --from -> exit 2", r.code == 2 && r.err.contains("--from"), r);
    }

    // ---------------------------------------------------------------- adoption

    static void adoption(Harness h) {
        Harness.Result r = h.onProject("adoption", "com.acme:acme-core", "--json");
        Object a = Json.list(r.json(), "artifacts").isEmpty() ? null : Json.list(r.json(), "artifacts").get(0);
        h.check("adoption: acme-core uses the project's resolved 1.0.0 and only 5.9% are on 2.0.0",
                r.code == 0 && a != null && "1.0.0".equals(Json.str(a, "current")) && "2.0.0".equals(Json.str(a, "newest"))
                        && Math.abs(Json.dbl(a, -1, "newestShare") - 0.0594) < 0.001 && Json.num(a, -1, "totalDependents") == 101, r);
        h.check("adoption: not safe yet, recommends the most adopted 1.1.0",
                a != null && "caution".equals(Json.str(a, "verdict")) && "1.1.0".equals(Json.str(a, "recommended")) && "1.1.0".equals(Json.str(a, "mostAdopted")), r);
        List<Object> vs = a == null ? List.of() : Json.list(a, "versions");
        double sum = 0;
        for (Object v : vs) sum += Json.dbl(v, 0, "share");
        h.check("adoption: per-version dependents distribution", vs.size() == 3 && Json.num(vs.get(0), -1, "dependents") == 40
                && Json.num(vs.get(1), -1, "dependents") == 55 && Math.abs(sum - 1.0) < 0.001, r);

        r = h.onProject("adoption", "--json");
        List<Object> all = Json.list(r.json(), "artifacts");
        Object jackson = byGa(all, "com.fasterxml.jackson.core:jackson-databind");
        Object guava = byGa(all, "com.google.guava:guava");
        h.check("adoption project: jackson-databind 2.18.2 is safe (57.7% moved)",
                jackson != null && "safe".equals(Json.str(jackson, "verdict")) && "2.18.2".equals(Json.str(jackson, "recommended"))
                        && Math.abs(Json.dbl(jackson, -1, "newestShare") - 0.5774) < 0.001, r);
        h.check("adoption project: guava newest has little adoption -> 32.1.3-jre is the proven step",
                guava != null && "caution".equals(Json.str(guava, "verdict")) && "32.1.3-jre".equals(Json.str(guava, "recommended")), r);
        Object utils = byGa(all, "com.acme:acme-utils");
        h.check("adoption project: already newest -> up-to-date", utils != null && "up-to-date".equals(Json.str(utils, "verdict")), r);

        r = h.onProject("adoption", "com.acme:acme-core", "--safe-share", "5%", "--json");
        h.check("adoption --safe-share 5% makes 2.0.0 safe", "safe".equals(Json.str(Json.list(r.json(), "artifacts").get(0), "verdict")), r);
        r = h.onProject("adoption", "com.acme:acme-core", "--safe-share", "50", "--min-age", "30", "--json");
        h.check("adoption --min-age: a 20-day-old release with little adoption means wait",
                "wait".equals(Json.str(Json.list(r.json(), "artifacts").get(0), "verdict")), r);
        r = h.onProject("adoption", "com.acme:acme-core", "--versions", "1", "--json");
        List<Object> v1 = Json.list(Json.list(r.json(), "artifacts").get(0), "versions");
        h.check("adoption --versions 1 keeps the newest plus the current version", v1.size() == 2, r);
        r = h.onProject("adoption", "com.acme:acme-core");
        h.check("adoption human output shows the distribution and the advice",
                r.code == 0 && r.out.contains("most used") && r.out.contains("newest") && r.out.contains("move to com.acme:acme-core:1.1.0"), r);
        r = h.run("adoption", "com.acme:acme-core:1.1.0", "--json");
        Object a2 = Json.list(r.json(), "artifacts").get(0);
        h.check("adoption on explicit coordinates without a project", r.code == 0 && "1.1.0".equals(Json.str(a2, "current"))
                && Math.abs(Json.dbl(a2, -1, "currentShare") - 0.5446) < 0.001, r);
        r = h.run("adoption", "org.nope:missing");
        h.check("adoption: unknown artifact -> exit 2", r.code == 2, r);
        r = h.onProject("adoption", "--versions", "0");
        h.check("adoption: bad --versions -> exit 2", r.code == 2, r);
    }

    // ---------------------------------------------------------------- relocations

    static void relocations(Harness h) throws Exception {
        Map<String, String> hook = Map.of("SM_MAVEN_WEBHOOK", h.mock.base() + "/hooks/relocations");
        h.clearHooks();
        Harness.Result r = h.runWith(hook, "relocations", "-f", h.project.toString(), "--reset", "--json");
        List<Object> f = findings(r.json());
        Object mysql = find(f, "kind", "relocated", "artifact", "mysql:mysql-connector-java:8.0.33");
        h.check("relocations: mysql-connector-java relocation with the exact replacement (exit 1)",
                r.code == 1 && mysql != null && "com.mysql:mysql-connector-j:8.0.33".equals(Json.str(mysql, "replacement"))
                        && "com.mysql:mysql-connector-j:9.1.0".equals(Json.str(mysql, "replacementLatest")), r);
        h.check("relocations: the declaring pom.xml line is given", mysql != null && String.valueOf(Json.str(mysql, "declaredIn")).startsWith("app/pom.xml:"), r);
        Object jaxb = find(f, "kind", "retired", "artifact", "javax.xml.bind:jaxb-api:2.3.1");
        h.check("relocations: retired javax jaxb-api -> jakarta.xml.bind-api", jaxb != null
                && "jakarta.xml.bind:jakarta.xml.bind-api:4.0.2".equals(Json.str(jaxb, "replacement")) && Json.str(jaxb, "note").contains("jakarta"), r);
        Object archived = find(f, "kind", "archived", "artifact", "com.acme:acme-utils:1.2.0");
        h.check("relocations: archived acme-utils repository is high severity",
                archived != null && Json.list(r.json(), "findings").stream().anyMatch(x -> "archived:com.acme:acme-utils:1.2.0".equals(Json.str(x, "key"))
                        && "high".equals(Json.str(x, "severity"))), r);
        h.check("relocations: no false positives (exactly 3 findings)", f.size() == 3, r);
        List<Object> sent = hooksFor(h, "relocations");
        h.check("relocations: webhook alert lists the findings", sent.size() == 1 && "relocations".equals(Json.str(sent.get(0), "body", "tool"))
                && Json.list(sent.get(0), "body", "lines").size() == 3 && "high".equals(Json.str(sent.get(0), "body", "severity")), sent);

        h.clearHooks();
        r = h.runWith(hook, "relocations", "-f", h.project.toString(), "--json");
        h.check("relocations: second run has nothing new (exit 0, no alert)", r.code == 0 && Json.num(r.json(), -1, "new") == 0
                && Json.num(r.json(), -1, "total") == 3 && hooksFor(h, "relocations").isEmpty(), r);
        r = h.onProject("relocations", "--fail-on", "any");
        h.check("relocations --fail-on any -> exit 1 with replacement coordinates", r.code == 1
                && r.out.contains("replace with com.mysql:mysql-connector-j:8.0.33") && r.out.contains("<scope>runtime</scope>")
                && r.out.contains("jakarta.xml.bind:jakarta.xml.bind-api:4.0.2") && r.out.contains("ARCHIVED"), r);
        r = h.onProject("relocations", "--no-github", "--reset", "--json");
        h.check("relocations --no-github skips the archived check", findings(r.json()).size() == 2
                && find(findings(r.json()), "kind", "archived", "artifact", "com.acme:acme-utils:1.2.0") == null, r);
        r = h.run("relocations", "com.acme:acme-utils:1.0.0", "--reset");
        h.check("relocations on a clean artifact -> exit 0", r.code == 0 && r.out.contains("No relocated, retired or archived"), r);
        r = h.run("relocations", "a:b:c", "x:y:z");
        h.check("relocations: too many coordinates -> exit 2", r.code == 2, r);
    }
}
