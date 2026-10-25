package in.slashmark.maven.e2e;

import in.slashmark.maven.util.Json;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** Live threat intelligence: cve-watch, impact, prioritize, release-guard, takeover. */
public final class ThreatTests {
    private ThreatTests() {}

    public static void run(Harness h) throws Exception {
        // Runtime fixtures in a private namespace so other groups' expectations are untouched.
        h.post("/_admin/publish", Json.obj("gav", "org.threatfx:watched:1.0.0", "daysAgo", 200));
        h.post("/_admin/publish", Json.obj("gav", "org.threatfx:watched:1.0.1", "daysAgo", 2));
        h.post("/_admin/publish", Json.obj("gav", "org.threatfx:app:1.0.0", "deps", List.of("org.threatfx:watched:1.0.0"), "daysAgo", 100));
        h.post("/_admin/publish", Json.obj("gav", "org.threatfx:outer:1.0.0", "deps", List.of("org.threatfx:app:1.0.0"), "daysAgo", 90));
        cveWatch(h);
        impact(h);
        prioritize(h);
        releaseGuard(h);
        takeover(h);
    }

    // ---------------------------------------------------------------- helpers

    static List<Object> findings(Object doc) { return Json.list(doc, "findings"); }

    static Object findingByKey(Object doc, String key) {
        for (Object f : findings(doc)) if (key.equals(Json.str(f, "key"))) return f;
        return null;
    }

    static String state(Harness h, String name) { return h.root.resolve("threat-state").resolve(name + ".json").toString(); }

    static Map<String, String> hook(Harness h, String name) { return Map.of("SM_MAVEN_WEBHOOK", h.mock.base() + "/hooks/" + name); }

    static List<Object> hooks(Harness h, String name) throws Exception {
        List<Object> out = new ArrayList<>();
        for (Object o : (List<?>) h.hookLog()) if (name.equals(Json.str(o, "hook"))) out.add(o);
        return out;
    }

    static Object occurrence(Object doc, String module, String kind) {
        for (Object o : Json.list(doc, "occurrences")) {
            if (module.equals(Json.str(o, "module")) && kind.equals(Json.str(o, "kind"))) return o;
        }
        return null;
    }

    static Object byField(List<Object> list, String field, String value) {
        for (Object o : list) if (value.equals(Json.str(o, field))) return o;
        return null;
    }

    // ---------------------------------------------------------------- cve-watch

    static void cveWatch(Harness h) throws Exception {
        String s1 = state(h, "cve1");
        Harness.Result r = h.onProject("cve-watch", "--state", s1, "--json");
        Object doc = r.json();
        Object log4j = findingByKey(doc, "GHSA-jfh8-c2jp-5v3q@org.apache.logging.log4j:log4j-core:2.14.1");
        h.check("cve-watch: first run finds log4shell as new, exit 1", r.code == 1 && log4j != null && Json.bool(log4j, false, "new")
                && "critical".equals(Json.str(log4j, "severity")), r);
        h.check("cve-watch: finding carries KEV, EPSS, fix, path and module", log4j != null && Json.get(log4j, "finding", "kev") != null
                && Json.dbl(log4j, 0, "finding", "epss", "epss") > 0.9 && "2.15.0".equals(Json.str(log4j, "finding", "fixedIn"))
                && "P1".equals(Json.str(log4j, "finding", "priority")) && Json.list(log4j, "finding", "modules").contains("shop-app"), r);
        Object shaded = findingByKey(doc, "GHSA-jfh8-c2jp-5v3q@org.apache.logging.log4j:log4j-core:2.14.1#shaded-in:com.acme:acme-fat:1.0.0");
        h.check("cve-watch: shaded log4j inside acme-fat is reported", shaded != null && "com.acme:acme-fat:1.0.0".equals(Json.str(shaded, "finding", "shadedIn")), r);
        h.check("cve-watch: spring4shell, jackson and guava advisories found, acme-utils 1.2.0 not",
                findingByKey(doc, "GHSA-36p3-wjmg-h94x@org.springframework:spring-beans:5.3.17") != null
                        && findingByKey(doc, "GHSA-57j2-w4cx-62h2@com.fasterxml.jackson.core:jackson-databind:2.9.10.1") != null
                        && findingByKey(doc, "GHSA-7g45-4rm6-3mm3@com.google.guava:guava:31.1-jre") != null
                        && !r.out.contains("GHSA-acm3-ut1l-0001") && Json.num(doc, 0, "total") == 12 && Json.num(doc, 0, "new") == 12, r);

        r = h.onProject("cve-watch", "--state", s1, "--json");
        h.check("cve-watch: second run has nothing new, exit 0", r.code == 0 && Json.num(r.json(), -1, "new") == 0 && Json.num(r.json(), 0, "total") == 12, r);

        r = h.onProject("cve-watch", "--state", state(h, "cve-crit"), "--min-severity", "critical", "--json");
        boolean allCritical = !findings(r.json()).isEmpty();
        for (Object f : findings(r.json())) allCritical &= "critical".equals(Json.str(f, "severity"));
        h.check("cve-watch: --min-severity critical keeps only critical advisories", allCritical && findings(r.json()).size() == 5, r);

        r = h.onProject("cve-watch", "--state", state(h, "cve-noshade"), "--no-shaded", "--json");
        h.check("cve-watch: --no-shaded skips the embedded copies", r.code == 1 && Json.num(r.json(), 0, "total") == 8 && !r.out.contains("shaded-in"), r);

        r = h.onProject("cve-watch", "--min-severity", "severe");
        h.check("cve-watch: bad --min-severity -> exit 2", r.code == 2 && r.err.contains("min-severity"), r);

        r = h.onProject("cve-watch", "--state", state(h, "cve-base"), "--baseline");
        h.check("cve-watch: --baseline records without failing", r.code == 0 && r.out.contains("Baseline recorded") && r.out.contains("CVE-2021-44228"), r);

        r = h.onProject("cve-watch", "--state", state(h, "cve-human"));
        h.check("cve-watch: human output marks new advisories", r.code == 1 && r.out.contains("NEW") && r.out.contains("CVE-2022-22965")
                && r.out.contains("shaded in acme-fat") && r.out.contains("12 new vulnerabilities"), r);

        // A new advisory appears "live" for a dependency of a published artifact.
        String s2 = state(h, "cve-live");
        r = h.run("cve-watch", "org.threatfx:app:1.0.0", "--state", s2, "--json");
        h.check("cve-watch: coordinates target starts clean", r.code == 0 && Json.num(r.json(), -1, "total") == 0, r);
        h.post("/_admin/advisory", Json.obj("id", "GHSA-thfx-wtch-0001", "summary", "Remote code execution in watched", "details", "RCE in watched.",
                "aliases", List.of(), "published", java.time.Instant.now().toString(), "modified", java.time.Instant.now().toString(),
                "severity", List.of(Json.obj("type", "CVSS_V3", "score", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")),
                "affected", List.of(Json.obj("package", Json.obj("ecosystem", "Maven", "name", "org.threatfx:watched"),
                        "ranges", List.of(Json.obj("type", "ECOSYSTEM", "events", List.of(Json.obj("introduced", "0"), Json.obj("fixed", "1.0.1")))))),
                "database_specific", Json.obj("severity", "CRITICAL")));
        h.clearHooks();
        r = h.runWith(hook(h, "threat-cve"), "cve-watch", "org.threatfx:app:1.0.0", "--state", s2, "--watch", "--cycles", "1", "--json");
        List<Object> hk = hooks(h, "threat-cve");
        h.check("cve-watch: new live advisory -> exit 1 with one new finding", r.code == 1 && Json.num(r.json(), 0, "new") == 1
                && findingByKey(r.json(), "GHSA-thfx-wtch-0001@org.threatfx:watched:1.0.0") != null, r);
        h.check("cve-watch: alert delivered to the webhook", hk.size() == 1 && "cve-watch".equals(Json.str(hk.get(0), "body", "tool"))
                && Json.str(hk.get(0), "body", "title").contains("1 new") && "critical".equals(Json.str(hk.get(0), "body", "severity"))
                && String.valueOf(Json.get(hk.get(0), "body", "lines")).contains("GHSA-thfx-wtch-0001"), hk + "\n" + r);
        h.check("cve-watch: webhook URL is never printed", !r.out.contains("/hooks/") && !r.err.contains("/hooks/"), r);
        h.clearHooks();
        r = h.runWith(hook(h, "threat-cve"), "cve-watch", "org.threatfx:app:1.0.0", "--state", s2, "--watch", "--cycles", "1", "--json");
        h.check("cve-watch: already-alerted advisory is not sent again", r.code == 0 && Json.num(r.json(), -1, "new") == 0 && hooks(h, "threat-cve").isEmpty(), r);
    }

    // ---------------------------------------------------------------- impact

    static void impact(Harness h) throws Exception {
        Harness.Result r = h.onProject("impact", "CVE-2021-44228", "--json");
        Object doc = r.json();
        Object dep = occurrence(doc, "shop-app", "dependency");
        h.check("impact: log4shell affects the project -> exit 1", r.code == 1 && Json.bool(doc, false, "affected")
                && Json.num(doc, 0, "summary", "modulesAffected") == 1 && Json.num(doc, 0, "summary", "occurrences") == 2, r);
        h.check("impact: direct log4j-core occurrence with path and scope", dep != null && Json.bool(dep, false, "direct")
                && "compile".equals(Json.str(dep, "scope")) && "org.apache.logging.log4j:log4j-core:2.14.1".equals(Json.str(dep, "artifact"))
                && "2.15.0".equals(Json.str(dep, "fixedIn")), r);
        h.check("impact: minimal change bumps the log4j.version property to the first published fix, verified",
                dep != null && "property".equals(Json.str(dep, "change", "kind")) && "log4j.version".equals(Json.str(dep, "change", "property"))
                        && "pom.xml".equals(Json.str(dep, "change", "file")) && "2.17.1".equals(Json.str(dep, "change", "to"))
                        && Json.bool(dep, false, "change", "verified") && "2.17.1".equals(Json.str(dep, "change", "resolvedAfter")), r);
        Object sh = occurrence(doc, "shop-app", "shaded");
        h.check("impact: shaded copy inside acme-fat found, no fixed host release", sh != null && "com.acme:acme-fat:1.0.0".equals(Json.str(sh, "shadedIn"))
                && "replace-host".equals(Json.str(sh, "change", "kind")), r);
        h.check("impact: KEV and EPSS fetched for the advisory", Json.bool(doc, false, "kev", "ransomware") && Json.dbl(doc, 0, "epss", "epss") > 0.9
                && "GHSA-jfh8-c2jp-5v3q".equals(Json.str(doc, "advisory", "id")), r);

        r = h.onProject("impact", "GHSA-36p3-wjmg-h94x", "--json");
        doc = r.json();
        Object lib = occurrence(doc, "shop-lib", "dependency");
        Object app = occurrence(doc, "shop-app", "dependency");
        h.check("impact: spring4shell in both modules (direct in lib, transitive in app)", r.code == 1 && lib != null && app != null
                && Json.bool(lib, false, "direct") && !Json.bool(app, true, "direct")
                && Json.list(app, "paths").toString().contains("com.acme.shop:shop-lib:3.2.0 -> org.springframework:spring-beans:5.3.17"), r);
        h.check("impact: fix goes to lib/pom.xml (also for shop-app, via the module)", lib != null && app != null
                && "literal".equals(Json.str(lib, "change", "kind")) && "lib/pom.xml".equals(Json.str(lib, "change", "file"))
                && "5.3.18".equals(Json.str(lib, "change", "to")) && Json.num(lib, 0, "change", "line") > 0
                && "shop-lib".equals(Json.str(app, "change", "viaModule")) && Json.bool(app, false, "change", "verified"), r);

        r = h.onProject("impact", "CVE-2020-36518", "--json");
        dep = occurrence(r.json(), "shop-app", "dependency");
        h.check("impact: jackson fix uses the first published unaffected release and shows the losing path",
                dep != null && "2.12.6.1".equals(Json.str(dep, "fixedIn")) && "2.15.4".equals(Json.str(dep, "recommended"))
                        && Json.list(dep, "paths").toString().contains("2.18.2") && Json.list(dep, "paths").toString().contains("conflict"), r);

        r = h.onProject("impact", "GHSA-acm3-ut1l-0001");
        h.check("impact: advisory for a version not in use -> exit 0, not affected", r.code == 0 && r.out.contains("Not affected")
                && r.out.contains("com.acme:acme-utils:1.2.0"), r);

        r = h.onProject("impact", "cve-2021-44228", "--no-shaded", "--json");
        h.check("impact: lowercase id accepted, --no-shaded skips embedded copies", r.code == 1 && Json.num(r.json(), -1, "summary", "shaded") == 0
                && Json.num(r.json(), 0, "summary", "direct") == 1, r);

        r = h.onProject("impact", "CVE-2021-44228");
        h.check("impact: human output shows paths and the fix", r.code == 1 && r.out.contains("Set <log4j.version> to 2.17.1")
                && r.out.contains("acme-fat") && r.out.contains("KNOWN EXPLOITED"), r);

        r = h.run("impact", "GHSA-thfx-wtch-0001", "org.threatfx:outer:1.0.0", "--json");
        dep = Json.list(r.json(), "occurrences").isEmpty() ? null : Json.list(r.json(), "occurrences").get(0);
        h.check("impact: transitive occurrence -> dependencyManagement pin, verified", r.code == 1 && dep != null && !Json.bool(dep, true, "direct")
                && "manage".equals(Json.str(dep, "change", "kind")) && "1.0.1".equals(Json.str(dep, "change", "to"))
                && Json.bool(dep, false, "change", "verified") && "org.threatfx:app:1.0.0".equals(Json.str(dep, "change", "introducedBy")), r);

        r = h.onProject("impact", "CVE-2099-0001");
        h.check("impact: unknown advisory -> exit 2", r.code == 2 && r.err.contains("not found"), r);
        r = h.onProject("impact");
        h.check("impact: missing id -> exit 2", r.code == 2, r);
        r = h.onProject("impact", "log4j");
        h.check("impact: not an advisory id -> exit 2", r.code == 2, r);
    }

    // ---------------------------------------------------------------- prioritize

    static void prioritize(Harness h) throws Exception {
        Harness.Result r = h.onProject("prioritize", "--json");
        Object doc = r.json();
        List<Object> fs = findings(doc);
        h.check("prioritize: findings found -> exit 1, P1 first", r.code == 1 && !fs.isEmpty() && "P1".equals(Json.str(fs.get(0), "priority"))
                && Json.num(fs.get(0), 0, "rank") == 1 && Json.get(fs.get(0), "kev") != null, r);
        h.check("prioritize: counts per band (KEV + high EPSS in P1)", Json.num(doc, 0, "counts", "P1") == 7 && Json.num(doc, 0, "counts", "P3") == 4
                && Json.num(doc, 0, "counts", "P4") == 1 && Json.num(doc, 0, "total") == 12, r);
        Object recursion = null, info = null;
        for (Object f : fs) {
            if ("GHSA-p6xc-xr62-6r2g".equals(Json.str(f, "advisory", "id")) && Json.get(f, "shadedIn") == null) recursion = f;
            if ("GHSA-5mg8-w23w-74h3".equals(Json.str(f, "advisory", "id"))) info = f;
        }
        h.check("prioritize: CVE-2021-45105 is P1 because of EPSS 64% (not in KEV)", recursion != null && "P1".equals(Json.str(recursion, "priority"))
                && Json.get(recursion, "kev") == null && Json.list(recursion, "reasons").toString().contains("EPSS 64%"), r);
        h.check("prioritize: low-severity guava disclosure is P4 with its fix", info != null && "P4".equals(Json.str(info, "priority"))
                && "32.0.0-android".equals(Json.str(info, "fixedIn")), r);
        Object log4jPlan = null, guavaPlan = null, springPlan = null;
        for (Object p : Json.list(doc, "fixPlan")) {
            if (Json.get(p, "shadedIn") != null) continue;
            if ("org.apache.logging.log4j:log4j-core".equals(Json.str(p, "artifact"))) log4jPlan = p;
            if ("com.google.guava:guava".equals(Json.str(p, "artifact"))) guavaPlan = p;
            if ("org.springframework:spring-beans".equals(Json.str(p, "artifact"))) springPlan = p;
        }
        h.check("prioritize: fix plan clears all advisories per artifact", log4jPlan != null && "2.17.1".equals(Json.str(log4jPlan, "upgradeTo"))
                && Json.list(log4jPlan, "fixes").size() == 4 && guavaPlan != null && "32.1.3-jre".equals(Json.str(guavaPlan, "upgradeTo"))
                && springPlan != null && Json.bool(springPlan, false, "direct"), r);

        r = h.onProject("prioritize", "--min-priority", "P1", "--json");
        boolean allP1 = true;
        for (Object f : findings(r.json())) allP1 &= "P1".equals(Json.str(f, "priority"));
        h.check("prioritize: --min-priority P1", r.code == 1 && allP1 && Json.num(r.json(), 0, "shown") == 7, r);

        r = h.onProject("prioritize", "--top", "3", "--json");
        h.check("prioritize: --top 3", findings(r.json()).size() == 3 && Json.num(r.json(), 0, "total") == 12, r);

        r = h.onProject("prioritize", "--min-epss", "50%", "--no-shaded", "--json");
        boolean exploited = !findings(r.json()).isEmpty();
        for (Object f : findings(r.json())) exploited &= Json.get(f, "kev") != null || Json.dbl(f, 0, "epss", "epss") >= 0.5;
        h.check("prioritize: --min-epss filters to likely-exploited, --no-shaded drops copies", exploited && findings(r.json()).size() == 4, r);

        r = h.onProject("prioritize", "--min-priority", "P3", "--fail-on", "none");
        h.check("prioritize: --fail-on none -> exit 0, human bands shown", r.code == 0 && r.out.contains("P1") && r.out.contains("act now")
                && r.out.contains("Fix plan") && r.out.contains("2.17.1") && !r.out.contains("CVE-2020-8908"), r);

        r = h.onProject("prioritize", "--min-priority", "P3", "--fail-on", "P2", "--scope", "test");
        h.check("prioritize: --scope test has nothing at P2+ -> exit 0", r.code == 0, r);

        r = h.run("prioritize", "org.example:widgets:1.0.0");
        h.check("prioritize: clean artifact -> exit 0", r.code == 0 && r.out.contains("No known vulnerabilities"), r);

        r = h.onProject("prioritize", "--min-priority", "P9");
        h.check("prioritize: bad --min-priority -> exit 2", r.code == 2, r);
        r = h.onProject("prioritize", "--top", "many");
        h.check("prioritize: bad --top -> exit 2", r.code == 2, r);
    }

    // ---------------------------------------------------------------- release-guard

    static void releaseGuard(Harness h) throws Exception {
        Harness.Result r = h.onProject("release-guard", "--json");
        Object doc = r.json();
        Object agent = byField(Json.list(doc, "releases"), "artifact", "com.acme:acme-agent");
        h.check("release-guard: acme-agent 1.0.1 flagged -> exit 1", r.code == 1 && agent != null && "1.0.1".equals(Json.str(agent, "release"))
                && "1.0.0".equals(Json.str(agent, "inUse")) && Json.bool(agent, false, "suspicious") && Json.num(agent, 0, "score") >= 90, r);
        List<String> ids = new ArrayList<>();
        if (agent != null) for (Object s : Json.list(agent, "signals")) ids.add(Json.str(s, "id"));
        h.check("release-guard: all planted signals detected", ids.containsAll(List.of("signing-key-changed", "agent-entrypoint", "native-library",
                "process-exec", "dynamic-classloading", "hardcoded-ip", "young-release", "shell-command")), ids + "\n" + r);
        String sig = agent == null ? "" : Json.list(agent, "signals").toString();
        h.check("release-guard: signal details name the key, IP and native library", sig.contains("DEADBEEFCAFEF00D") && sig.contains("1111222233334444")
                && sig.contains("203.0.113.7") && sig.contains("libacme.so") && sig.contains("Premain-Class"), sig);
        h.check("release-guard: only the agent is suspicious", Json.num(doc, 0, "summary", "suspicious") == 1
                && Json.num(doc, 0, "summary", "releasesReviewed") > 5, r);

        r = h.onProject("release-guard", "--all", "--direct", "--json");
        boolean allListed = Json.list(r.json(), "releases").size() == Json.num(r.json(), -1, "summary", "releasesReviewed");
        h.check("release-guard: --all lists clean releases too, --direct still covers acme-agent", r.code == 1 && allListed
                && byField(Json.list(r.json(), "releases"), "artifact", "com.acme:acme-core") != null, r);

        r = h.run("release-guard", "com.acme:acme-agent");
        h.check("release-guard: g:a compares the newest release with the previous one", r.code == 1 && r.out.contains("SUSPICIOUS")
                && r.out.contains("Do not upgrade to 1.0.1") && r.out.contains("signing-key-changed"), r);

        r = h.run("release-guard", "com.acme:acme-core:1.0.0", "--json");
        Object core = byField(Json.list(r.json(), "releases"), "artifact", "com.acme:acme-core");
        h.check("release-guard: same key, no new capabilities -> clean, exit 0", r.code == 0 && core == null
                && Json.num(r.json(), -1, "summary", "suspicious") == 0, r);

        // A fresh release signed by a different key.
        h.post("/_admin/publish", Json.obj("gav", "org.threatfx:signed:1.0.0", "key", "1111222233334444", "daysAgo", 100));
        h.post("/_admin/publish", Json.obj("gav", "org.threatfx:signed:1.1.0", "key", "ABCDEF0123456789", "daysAgo", 0));
        r = h.run("release-guard", "org.threatfx:signed:1.0.0", "--json");
        Object signed = byField(Json.list(r.json(), "releases"), "artifact", "org.threatfx:signed");
        h.check("release-guard: runtime key change + brand-new release -> suspicious", r.code == 1 && signed != null
                && Json.num(signed, 0, "score") == 50 && Json.list(signed, "signals").toString().contains("ABCDEF0123456789"), r);
        r = h.run("release-guard", "org.threatfx:signed:1.0.0", "--threshold", "60");
        h.check("release-guard: --threshold above the score -> exit 0", r.code == 0 && r.out.contains("REVIEW"), r);

        r = h.run("release-guard", "com.nope:nothing:1.0");
        h.check("release-guard: unknown artifact -> exit 2", r.code == 2, r);
        r = h.onProject("release-guard", "--threshold", "500");
        h.check("release-guard: bad --threshold -> exit 2", r.code == 2, r);
        r = h.onProject("release-guard", "--releases", "0");
        h.check("release-guard: bad --releases -> exit 2", r.code == 2, r);
    }

    // ---------------------------------------------------------------- takeover

    static void takeover(Harness h) throws Exception {
        String s1 = state(h, "take1");
        Harness.Result r = h.onProject("takeover", "--state", s1, "--json");
        Object doc = r.json();
        Object acrne = null, internal = null;
        for (Object f : findings(doc)) {
            if ("com.acrne".equals(Json.str(f, "finding", "groupId"))) acrne = f;
            if ("com.acme.internal".equals(Json.str(f, "finding", "groupId"))) internal = f;
        }
        h.check("takeover: homoglyph look-alike com.acrne found -> exit 1", r.code == 1 && acrne != null
                && "lookalike".equals(Json.str(acrne, "finding", "type")) && "homoglyph".equals(Json.str(acrne, "finding", "technique"))
                && "com.acme".equals(Json.str(acrne, "finding", "imitates")), r);
        h.check("takeover: look-alike reuses acme-core and is signed by a foreign key", acrne != null
                && Json.list(acrne, "finding", "collidesWith").contains("acme-core") && "high".equals(Json.str(acrne, "severity"))
                && Json.list(acrne, "finding", "signingKeys").contains("0BADC0DE0BADC0DE")
                && Json.list(acrne, "finding", "reasons").toString().contains("not a key that signs your artifacts"), r);
        h.check("takeover: publicly claimed internal namespace com.acme.internal", internal != null
                && "internal-claimed".equals(Json.str(internal, "finding", "type"))
                && Json.list(internal, "finding", "reasons").toString().contains("99.0.0"), r);
        h.check("takeover: no false positives on the fixture", Json.num(doc, 0, "total") == 2, r);

        r = h.onProject("takeover", "--state", s1, "--json");
        h.check("takeover: second run has nothing new -> exit 0", r.code == 0 && Json.num(r.json(), -1, "new") == 0 && Json.num(r.json(), 0, "total") == 2, r);

        r = h.onProject("takeover", "--state", state(h, "take-np"), "--no-probe", "--json");
        boolean found = false;
        for (Object f : findings(r.json())) found |= "com.acrne".equals(Json.str(f, "finding", "groupId"));
        h.check("takeover: --no-probe still finds com.acrne through the artifact-name search", r.code == 1 && found, r);

        // A new typo-squat appears.
        h.post("/_admin/publish", Json.obj("gav", "com.acmee:billing:1.0.0", "daysAgo", 0));
        h.clearHooks();
        r = h.runWith(hook(h, "threat-ns"), "takeover", "-f", h.project.toString(), "--state", s1, "--watch", "--cycles", "1", "--json");
        Object acmee = null;
        for (Object f : findings(r.json())) if ("com.acmee".equals(Json.str(f, "finding", "groupId"))) acmee = f;
        List<Object> hk = hooks(h, "threat-ns");
        h.check("takeover: newly published typo-squat is the only new finding", r.code == 1 && Json.num(r.json(), 0, "new") == 1 && acmee != null
                && Json.bool(acmee, false, "new") && "repetition".equals(Json.str(acmee, "finding", "technique")), r);
        h.check("takeover: alert sent for the new namespace", hk.size() == 1 && "takeover".equals(Json.str(hk.get(0), "body", "tool"))
                && String.valueOf(Json.get(hk.get(0), "body", "lines")).contains("com.acmee"), hk + "\n" + r);

        r = h.onProject("takeover", "--state", state(h, "take-human"));
        h.check("takeover: human output explains the threats", r.code == 1 && r.out.contains("Look-alike") && r.out.contains("com.acrne")
                && r.out.contains("Internal namespace") && r.out.contains("dependency-confusion"), r);

        r = h.run("takeover", "com.acme:acme-core:1.0.0", "--state", state(h, "take-gav"), "--json");
        found = false;
        for (Object f : findings(r.json())) found |= "com.acrne".equals(Json.str(f, "finding", "groupId"));
        h.check("takeover: coordinates target protects their groupId", r.code == 1 && found, r);

        r = h.onProject("takeover", "--group", "bad..group");
        h.check("takeover: bad --group -> exit 2", r.code == 2, r);
        r = h.onProject("takeover", "--max-probes", "0");
        h.check("takeover: bad --max-probes -> exit 2", r.code == 2, r);
    }
}
