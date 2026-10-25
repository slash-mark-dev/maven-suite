package in.slashmark.maven.e2e;

import in.slashmark.maven.util.Json;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/** Upgrade intelligence and live compliance: simulate, safe, jdk, license-watch, sbom. */
public final class UpgradeTests {
    private UpgradeTests() {}

    public static void run(Harness h) throws Exception {
        simulate(h);
        safe(h);
        jdk(h);
        licenseWatch(h);
        sbom(h);
    }

    // ---------------------------------------------------------------- helpers

    static Object byField(List<Object> list, String field, String value) {
        for (Object o : list) if (value.equals(Json.str(o, field))) return o;
        return null;
    }

    static boolean anyField(List<Object> list, String field, String value) { return byField(list, field, value) != null; }

    static boolean anyContains(List<Object> list, String field, String needle) {
        for (Object o : list) { String s = Json.str(o, field); if (s != null && s.contains(needle)) return true; }
        return false;
    }

    // ---------------------------------------------------------------- simulate

    static void simulate(Harness h) throws Exception {
        Harness.Result r = h.onProject("simulate", "org.apache.logging.log4j:log4j-core:2.24.3", "--json");
        Object j = r.json();
        h.check("simulate: log4j-core upgrade is SAFE (exit 0)", r.code == 0 && "SAFE".equals(Json.str(j, "verdict")), r);
        Object up = Json.get(j, "upgrades", 0);
        h.check("simulate: upgrade 2.14.1 -> 2.24.3 (minor jump)", "2.14.1".equals(Json.str(up, "from")) && "2.24.3".equals(Json.str(up, "to"))
                && "minor".equals(Json.str(up, "jump")), r);
        h.check("simulate: tree diff shows log4j-core upgraded in shop-app", anyField(Json.list(j, "treeChanges"), "change", "upgraded")
                && "shop-app".equals(Json.str(byField(Json.list(j, "treeChanges"), "artifact", "org.apache.logging.log4j:log4j-core"), "module")), r);
        List<Object> fixed = Json.list(j, "vulnerabilities", "fixed");
        h.check("simulate: fixes all four log4j CVEs incl. Log4Shell", fixed.size() == 4 && anyField(fixed, "displayId", "CVE-2021-44228")
                && Json.num(j, -1, "vulnerabilities", "before") == 8 && Json.num(j, -1, "vulnerabilities", "after") == 4
                && Json.list(j, "vulnerabilities", "introduced").isEmpty(), r);

        r = h.onProject("simulate", "com.acme:acme-core:2.0.0", "--json");
        j = r.json();
        List<Object> breaks = Json.list(j, "apiBreaks");
        h.check("simulate: acme-core 2.0.0 is BREAKING (exit 1)", r.code == 1 && "BREAKING".equals(Json.str(j, "verdict")), r);
        h.check("simulate: finds the 3 API breaks the app code hits (removed method, final class, new abstract method)", breaks.size() == 3
                && anyField(breaks, "kind", "abstract-method-added") && "com.acme.core.Handler".equals(Json.str(byField(breaks, "kind", "abstract-method-added"), "type")), r);
        Object jdk = Json.get(j, "jdk", 0);
        h.check("simulate: 2.0.0 needs Java 17 (class file 61) but the project runs on 11", Json.num(jdk, 0, "toMajor") == 61
                && Json.num(jdk, 0, "requiresJava") == 17 && Boolean.FALSE.equals(Json.get(jdk, "compatible")), r);

        r = h.onProject("simulate", "com.acme:acme-core:2.0.0", "--release", "17", "--json");
        j = r.json();
        h.check("simulate: --release 17 makes the class-file level compatible (API breaks remain)", Boolean.TRUE.equals(Json.get(j, "jdk", 0, "compatible"))
                && "BREAKING".equals(Json.str(j, "verdict")), r);

        r = h.onProject("simulate", "com.acme:acme-core:2.0.0", "--no-api", "--release", "17", "--json");
        h.check("simulate: --no-api skips the bytecode check", Json.list(r.json(), "apiBreaks").isEmpty(), r);

        r = h.onProject("simulate", "org.example:widgets:2.0.0", "--json");
        j = r.json();
        h.check("simulate: widgets 2.0.0 reports the Apache-2.0 -> BUSL-1.1 relicense and is not SAFE",
                !Json.list(j, "licenses").isEmpty() && Json.write(Json.get(j, "licenses"), false).contains("BUSL-1.1") && !"SAFE".equals(Json.str(j, "verdict")), r);

        r = h.onProject("simulate", "com.google.guava:guava", "--json");
        h.check("simulate: g:a without version upgrades to the newest release", "33.4.8-jre".equals(Json.str(r.json(), "upgrades", 0, "to")), r);

        r = h.onProject("simulate", "--all-latest", "--json");
        h.check("simulate: --all-latest plans an upgrade for several direct dependencies", Json.list(r.json(), "upgrades").size() >= 4, r);

        r = h.onProject("simulate", "com.acme:acme-core:2.0.0");
        h.check("simulate: human output names the verdict and the breaking member", r.code == 1 && r.out.contains("BREAKING") && r.out.contains("onError"), r);

        r = h.onProject("simulate");
        h.check("simulate: nothing to simulate -> exit 2", r.code == 2, r);
        r = h.onProject("simulate", "org.nowhere:missing:1.0");
        h.check("simulate: unknown artifact -> exit 2 with a message", r.code == 2 && r.err.contains("org.nowhere:missing"), r);
    }

    // ---------------------------------------------------------------- safe

    static void safe(Harness h) throws Exception {
        Harness.Result r = h.onProject("safe", "--json");
        Object j = r.json();
        List<Object> deps = Json.list(j, "dependencies");
        Object log4j = byField(deps, "artifact", "org.apache.logging.log4j:log4j-core");
        h.check("safe: action needed (exit 1), log4j-core -> 2.24.3", r.code == 1 && Boolean.TRUE.equals(Json.get(j, "actionNeeded"))
                && "2.24.3".equals(Json.str(log4j, "safeVersion")) && Json.list(log4j, "currentVulnerabilities").size() == 4, r);
        Object core = byField(deps, "artifact", "com.acme:acme-core");
        h.check("safe: acme-core stops at 1.1.0 because 2.0.0 needs Java 17 and breaks the app's code", "1.1.0".equals(Json.str(core, "safeVersion"))
                && Json.write(Json.get(core, "rejected"), false).contains("2.0.0"), r);
        Object widgets = byField(deps, "artifact", "org.example:widgets");
        h.check("safe: widgets is kept at 1.0.0 (2.0.0 changes licence to BUSL-1.1)", "keep".equals(Json.str(widgets, "status"))
                && Json.write(Json.get(widgets, "rejected"), false).contains("BUSL-1.1"), r);
        h.check("safe: re-resolving with the pins removes every known vulnerability", Json.num(j, -1, "verification", "vulnerabilitiesBefore") == 8
                && Json.num(j, -1, "verification", "vulnerabilitiesAfter") == 0, r);
        h.check("safe: pin snippets point at the right pom.xml", Json.str(log4j, "pin") != null && Json.str(log4j, "pin").contains("app/pom.xml")
                && Json.str(log4j, "pin").contains("<version>2.24.3</version>"), r);
        Object mysql = byField(deps, "artifact", "com.mysql:mysql-connector-j");
        h.check("safe: relocated mysql-connector-java is reported under its new coordinates", mysql != null && Json.str(mysql, "pin").contains("relocated"), r);

        r = h.onProject("safe", "--allow", "BUSL-1.1", "--json");
        h.check("safe: --allow BUSL-1.1 accepts widgets 2.0.0", "2.0.0".equals(Json.str(byField(Json.list(r.json(), "dependencies"), "artifact", "org.example:widgets"), "safeVersion")), r);

        r = h.onProject("safe", "--only-vulnerable", "--json");
        deps = Json.list(r.json(), "dependencies");
        boolean allVuln = !deps.isEmpty();
        for (Object d : deps) allVuln &= Boolean.TRUE.equals(Json.get(d, "vulnerable"));
        h.check("safe: --only-vulnerable lists only the 4 vulnerable dependencies", allVuln && deps.size() == 4, r);

        r = h.onProject("safe", "--same-major", "--json");
        boolean sameMajor = true;
        for (Object d : Json.list(r.json(), "dependencies")) {
            String cur = Json.str(d, "current"), sv = Json.str(d, "safeVersion");
            if (cur != null && sv != null && !cur.split("\\.")[0].equals(sv.split("\\.")[0])) sameMajor = false;
        }
        h.check("safe: --same-major never proposes a new major version", sameMajor, r);

        r = h.onProject("safe", "com.google.guava:guava:31.1-jre", "--json");
        h.check("safe: one coordinate analyses just that dependency", Json.list(r.json(), "dependencies").size() == 1
                && "33.4.8-jre".equals(Json.str(r.json(), "dependencies", 0, "safeVersion")), r);

        r = h.onProject("safe", "--min-age", "soon");
        h.check("safe: bad --min-age -> exit 2", r.code == 2, r);
    }

    // ---------------------------------------------------------------- jdk

    static void jdk(Harness h) throws Exception {
        Harness.Result r = h.onProject("jdk", "--target", "21", "--json");
        Object j = r.json();
        List<Object> f = Json.list(j, "findings");
        h.check("jdk: scans project classes and dependencies for Java 21", Json.num(j, 0, "target") == 21 && Json.num(j, 0, "release") == 11
                && Json.num(j, 0, "scanned", "classes") > 0 && r.code == 1, r);
        h.check("jdk: finds JAXB (removed in Java 11) used by App", anyContains(f, "api", "javax.xml.bind") || anyContains(f, "api", "JAXB"), r);
        h.check("jdk: finds sun.misc.Unsafe and System.getSecurityManager", anyContains(f, "api", "sun.misc.Unsafe") && anyContains(f, "api", "getSecurityManager"), r);
        h.check("jdk: proposes jakarta.xml.bind-api for the javax -> jakarta move", anyField(Json.list(j, "jakarta"), "artifact", "jakarta.xml.bind:jakarta.xml.bind-api"), r);
        h.check("jdk: summary counts match the findings", Json.num(j, -1, "summary", "warnings") + Json.num(j, -1, "summary", "errors") + Json.num(j, -1, "summary", "info") == f.size(), r);

        r = h.onProject("jdk", "--target", "21", "--fail-on", "none", "--json");
        h.check("jdk: --fail-on none -> exit 0", r.code == 0, r);
        r = h.onProject("jdk", "--target", "21", "--fail-on", "sometimes");
        h.check("jdk: bad --fail-on -> exit 2", r.code == 2, r);

        r = h.onProject("jdk", "--target", "21", "--no-deps", "--json");
        Object nd = r.json();
        h.check("jdk: --no-deps scans fewer units and drops dependency findings", Json.num(nd, 99, "scanned", "units") < Json.num(j, 0, "scanned", "units"), r);

        r = h.run("jdk", "com.acme:acme-core:2.0.0", "--target", "11", "--json");
        h.check("jdk: a published artifact built for Java 17 is not ready for Java 11", Boolean.FALSE.equals(Json.get(r.json(), "ready")) && r.code == 1, r);

        r = h.onProject("jdk", "--target", "21");
        h.check("jdk: human report has sections and the fix hints", r.out.contains("javax -> jakarta") && r.out.contains("fix:"), r);
    }

    // ---------------------------------------------------------------- license-watch

    static void licenseWatch(Harness h) throws Exception {
        Harness.Result r = h.onProject("license-watch", "--reset", "--json");
        Object j = r.json();
        List<Object> f = Json.list(j, "findings");
        h.check("license-watch: first run reports 2 new issues (exit 1)", r.code == 1 && f.size() == 2 && Json.num(j, -1, "new") == 2, r);
        String all = Json.write(f, false);
        h.check("license-watch: widgets 2.0.0 relicensed Apache-2.0 -> BUSL-1.1", all.contains("relicense:org.example:widgets:2.0.0:BUSL-1.1"), r);
        h.check("license-watch: gpl-lib (GPL-3.0-only) violates the default policy, with its path", all.contains("org.example:gpl-lib") && all.contains("GPL-3.0-only")
                && all.contains("shop-lib"), r);

        r = h.onProject("license-watch", "--json");
        h.check("license-watch: second run has nothing new (exit 0)", r.code == 0 && Json.num(r.json(), -1, "new") == 0, r);

        r = h.onProject("license-watch", "--deny", "GPL-3.0-only,BUSL-1.1", "--reset", "--json");
        h.check("license-watch: --deny with SPDX ids flags both issues", r.code == 1 && Json.list(r.json(), "findings").size() == 2, r);

        r = h.onProject("license-watch", "--allow", "Apache-2.0,MIT,BSD-*,EPL-2.0,LGPL-*,GPL-3.0-only,BUSL-1.1,EPL-1.0,CDDL-1.1,GPL-2.0-with-classpath-exception", "--reset", "--json");
        String allowed = Json.write(Json.get(r.json(), "findings"), false);
        h.check("license-watch: --allow allowlist mode accepts listed licences", !allowed.contains("gpl-lib"), r);

        h.clearHooks();
        r = h.runWith(java.util.Map.of("SM_MAVEN_WEBHOOK", h.mock.base() + "/hooks/licenses"), "license-watch", "-f", h.project.toString(), "--reset");
        boolean hooked = false;
        for (Object o : Json.list(h.hookLog())) if ("licenses".equals(Json.str(o, "hook"))) hooked = true;
        h.check("license-watch: new issues are delivered to a webhook (URL never printed)", hooked && r.code == 1 && !r.out.contains("/hooks/") && !r.err.contains("/hooks/"), r);

        r = h.run("license-watch", "org.example:widgets:1.0.0", "--reset", "--json");
        h.check("license-watch: works on published coordinates", Json.write(Json.get(r.json(), "findings"), false).contains("BUSL-1.1"), r);

        r = h.onProject("license-watch", "--allow", "MIT", "--deny", "GPL-3.0-only", "--reset", "--json");
        h.check("license-watch: --allow and --deny combine (allowlist plus explicit denies)", r.code == 1
                && Json.write(Json.get(r.json(), "findings"), false).contains("gpl-lib"), r);
    }

    // ---------------------------------------------------------------- sbom

    static void sbom(Harness h) throws Exception {
        Harness.Result r = h.onProject("sbom");
        Object j = r.json();
        List<Object> comps = Json.list(j, "components");
        h.check("sbom: CycloneDX 1.5 document on stdout", r.code == 0 && "CycloneDX".equals(Json.str(j, "bomFormat")) && "1.5".equals(Json.str(j, "specVersion"))
                && Json.str(j, "serialNumber").startsWith("urn:uuid:"), r);
        Object log4j = byField(comps, "purl", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1");
        h.check("sbom: components carry purl, SHA-256 hash and SPDX licence", log4j != null && Json.write(Json.get(log4j, "hashes"), false).contains("SHA-256")
                && Json.write(Json.get(log4j, "licenses"), false).contains("Apache-2.0"), r);
        h.check("sbom: includes reactor modules and transitive dependencies", byField(comps, "name", "shop-lib") != null && byField(comps, "name", "log4j-api") != null, r);
        h.check("sbom: dependency graph section", !Json.list(j, "dependencies").isEmpty(), r);
        String vulns = Json.write(Json.get(j, "vulnerabilities"), false);
        h.check("sbom: live vulnerabilities with VEX analysis (Log4Shell)", vulns.contains("CVE-2021-44228") && vulns.contains("\"analysis\""), r);

        r = h.onProject("sbom", "--format", "spdx");
        j = r.json();
        h.check("sbom: SPDX 2.3 JSON with packages and DEPENDS_ON relationships", "SPDX-2.3".equals(Json.str(j, "spdxVersion")) && Json.list(j, "packages").size() > 10
                && Json.write(Json.get(j, "relationships"), false).contains("DEPENDS_ON"), r);

        Path out = h.root.resolve("bom.cdx.json");
        r = h.onProject("sbom", "-o", out.toString());
        h.check("sbom: -o writes the file and prints a summary", r.code == 0 && Files.exists(out) && Json.str(Json.parse(Files.readString(out)), "bomFormat") != null
                && r.out.contains("CycloneDX"), r);

        r = h.onProject("sbom", "--no-vulns");
        h.check("sbom: --no-vulns leaves vulnerabilities out", Json.list(r.json(), "vulnerabilities").isEmpty(), r);

        r = h.onProject("sbom", "--fail-exploitable", "-o", h.root.resolve("bom2.json").toString());
        h.check("sbom: --fail-exploitable -> exit 1 (Log4Shell ships in compile scope)", r.code == 1, r);

        r = h.run("sbom", "org.apache.logging.log4j:log4j-core:2.14.1");
        h.check("sbom: published coordinates become the root component", "log4j-core".equals(Json.str(r.json(), "metadata", "component", "name")), r);

        r = h.onProject("sbom", "--format", "xml");
        h.check("sbom: unknown --format -> exit 2", r.code == 2, r);
    }
}
