package in.slashmark.maven.tools;

import in.slashmark.maven.analysis.Licenses;
import in.slashmark.maven.analysis.Risk;
import in.slashmark.maven.cli.Args;
import in.slashmark.maven.cli.Command;
import in.slashmark.maven.cli.Ctx;
import in.slashmark.maven.cli.Exit;
import in.slashmark.maven.cli.Ui;
import in.slashmark.maven.cli.UsageException;
import in.slashmark.maven.data.GitHub;
import in.slashmark.maven.model.Gav;
import in.slashmark.maven.model.ModelBuilder;
import in.slashmark.maven.resolve.DepNode;
import in.slashmark.maven.util.Http;
import in.slashmark.maven.util.Json;
import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** CI Policy Gate: Fail builds on live risk data: severity, KEV, EPSS, licenses, age, health. */
public final class Gate extends Command {
    @Override public String name() { return "gate"; }
    @Override public String title() { return "CI Policy Gate"; }
    @Override public String group() { return "Live compliance"; }
    @Override public String summary() { return "Fail builds on live risk data: severity, KEV, EPSS, licenses, age, health"; }

    @Override
    public Set<String> flags() { return Set.of("kev", "deny-archived", "include-test", "warn-only"); }

    @Override
    public String help() {
        return String.join("\n",
                "Usage: sm-maven gate [group:artifact:version] [options]",
                "",
                summary() + ".",
                "Evaluates the resolved dependencies (compile/runtime/system scope) of the project, or of published",
                "coordinates, against a policy using live OSV, CISA KEV, FIRST EPSS, licence and release data, prints",
                "pass/fail per rule with the violating coordinates, and exits 1 when any rule fails.",
                "",
                "Policy rules (flags override the policy file):",
                "  --fail-on <severity>     Fail on vulnerabilities at or above critical|high|medium|low (none = off)",
                "  --kev                    Fail on any vulnerability in the CISA Known Exploited Vulnerabilities catalog",
                "  --epss <score>           Fail on vulnerabilities with an EPSS exploit probability >= score (0.5 or 50%)",
                "  --deny-license <list>    Fail on licences: SPDX ids, prefixes (GPL-*), categories (strong-copyleft,",
                "                           network-copyleft, source-available, unknown). Dual-licensed artifacts only fail",
                "                           when every offered licence is denied",
                "  --max-age-days <n>       Fail on unmaintained artifacts: newest release older than n days",
                "  --deny <patterns>        Fail on banned coordinates: group, group:artifact or g:a:version (globs, ranges)",
                "  --deny-archived          Fail on dependencies whose source repository is archived on GitHub",
                "  --allow-vuln <ids>       Accepted risks: CVE/GHSA ids with optional expiry, e.g. CVE-2021-44228@2026-12-31",
                "                           (expired entries stop applying and are reported)",
                "  --include-test           Also gate test- and provided-scoped dependencies",
                "",
                "Policy file (default: .sm-maven/policy.properties or .sm-maven/policy.json next to the pom.xml):",
                "  --policy <file>          Use this policy file (.properties or .json, same keys as the flags)",
                "",
                "    # .sm-maven/policy.properties",
                "    fail-on=high",
                "    kev=true",
                "    epss=0.5",
                "    deny-license=AGPL-*,source-available",
                "    max-age-days=1095",
                "    deny=commons-collections:commons-collections:[,3.2.2)",
                "    allow-vuln=CVE-2023-2976@2026-12-31",
                "",
                "  With no policy file and no rule flags the default policy is: --fail-on critical --kev.",
                "",
                "Output:",
                "  --format <fmt>           text (default), github (workflow ::error annotations), junit (JUnit XML),",
                "                           sarif (SARIF 2.1.0 for code scanning) or json",
                "  --sarif, --junit         Shortcuts for --format sarif / --format junit",
                "  -o, --output <file>      Write the report there and print the text summary",
                "  --warn-only              Report violations but exit 0",
                "",
                "Exit codes: 0 policy passed, 1 policy failed, 2 usage error, 3 network error.",
                "",
                "Examples:",
                "  sm-maven gate --fail-on high --kev --epss 0.5",
                "  sm-maven gate --deny-license 'GPL-*,AGPL-*' --max-age-days 1095 --format github",
                "  sm-maven gate --policy ci/policy.json --sarif -o gate.sarif",
                "  sm-maven gate org.apache.logging.log4j:log4j-core:2.14.1 --kev");
    }

    // ---------------------------------------------------------------- policy

    static final class Allow {
        String id, reason;
        LocalDate until;
        boolean expired;

        Object toJson() { return OpsCommon.m("id", id, "until", until == null ? null : until.toString(), "reason", reason, "expired", expired); }
    }

    static final class Policy {
        String source = "default";
        String failOn;
        boolean kev;
        Double epss;
        List<String> denyLicense = new ArrayList<>();
        Integer maxAgeDays;
        List<String> deny = new ArrayList<>();
        boolean denyArchived;
        boolean includeTest;
        List<Allow> allow = new ArrayList<>();

        boolean anyRule() {
            return failOn != null || kev || epss != null || !denyLicense.isEmpty() || maxAgeDays != null || !deny.isEmpty() || denyArchived;
        }

        Object toJson() {
            List<Object> a = new ArrayList<>();
            for (Allow x : allow) a.add(x.toJson());
            return OpsCommon.m("source", source, "failOn", failOn, "kev", kev, "epss", epss, "denyLicense", denyLicense,
                    "maxAgeDays", maxAgeDays, "deny", deny, "denyArchived", denyArchived, "includeTest", includeTest, "allowVuln", a);
        }
    }

    private static final Pattern ALLOW = Pattern.compile("^\\s*([^@\\s]+?)(?:[@:](\\d{4}-\\d{2}-\\d{2}))?(?:\\s+(.*))?$");

    static Allow parseAllow(String s, String reason) {
        Matcher m = ALLOW.matcher(s);
        if (!m.matches()) throw new UsageException("allow-vuln entry '" + s + "' should look like CVE-2021-44228 or CVE-2021-44228@2026-12-31");
        Allow a = new Allow();
        a.id = m.group(1);
        a.reason = reason != null ? reason : m.group(3);
        if (m.group(2) != null) {
            try {
                a.until = LocalDate.parse(m.group(2));
            } catch (DateTimeParseException e) {
                throw new UsageException("allow-vuln entry '" + s + "' has an invalid date");
            }
            a.expired = a.until.isBefore(LocalDate.now(ZoneOffset.UTC));
        }
        return a;
    }

    private static String key(String k) { return k.toLowerCase(Locale.ROOT).replace("-", "").replace("_", "").replace(".", ""); }

    static boolean bool(Object v, String k) {
        if (v instanceof Boolean) return (Boolean) v;
        String s = String.valueOf(v).trim().toLowerCase(Locale.ROOT);
        if (s.equals("true") || s.equals("yes") || s.equals("on") || s.equals("1")) return true;
        if (s.equals("false") || s.equals("no") || s.equals("off") || s.equals("0")) return false;
        throw new UsageException("policy key '" + k + "' expects true or false, got '" + v + "'");
    }

    static double number(Object v, String k) {
        if (v instanceof Number) return ((Number) v).doubleValue();
        String s = String.valueOf(v).trim();
        try {
            if (s.endsWith("%")) return Double.parseDouble(s.substring(0, s.length() - 1)) / 100.0;
            return Double.parseDouble(s);
        } catch (NumberFormatException e) {
            throw new UsageException("policy key '" + k + "' expects a number, got '" + v + "'");
        }
    }

    static String failOn(String v, String where) {
        String s = v.trim().toLowerCase(Locale.ROOT);
        if (s.equals("none") || s.equals("off") || s.equals("false")) return null;
        if (s.equals("moderate")) s = "medium";
        if (!List.of("critical", "high", "medium", "low").contains(s)) throw new UsageException(where + " expects critical, high, medium, low or none, got '" + v + "'");
        return s;
    }

    /** Applies one policy-file entry. */
    static void apply(Policy p, String rawKey, Object v) {
        switch (key(rawKey)) {
            case "failon": case "severity": p.failOn = failOn(String.valueOf(v), "policy key '" + rawKey + "'"); break;
            case "kev": p.kev = bool(v, rawKey); break;
            case "epss": {
                double d = number(v, rawKey);
                p.epss = d <= 0 ? null : d;
                break;
            }
            case "denylicense": case "denylicenses": p.denyLicense = OpsCommon.list(v); break;
            case "maxagedays": {
                double d = number(v, rawKey);
                p.maxAgeDays = d <= 0 ? null : (int) d;
                break;
            }
            case "deny": p.deny = OpsCommon.list(v); break;
            case "denyarchived": p.denyArchived = bool(v, rawKey); break;
            case "includetest": p.includeTest = bool(v, rawKey); break;
            case "allowvuln": case "allowvulns": case "allow": {
                p.allow.clear();
                List<Object> items = v instanceof List ? Json.list(Map.of("x", v), "x") : new ArrayList<>(OpsCommon.list(v));
                for (Object o : items) {
                    if (o instanceof Map) {
                        String id = Json.str(o, "id");
                        if (id == null) throw new UsageException("allow-vuln entries need an \"id\"");
                        String until = Json.str(o, "until");
                        p.allow.add(parseAllow(id + (until == null ? "" : "@" + until), Json.str(o, "reason")));
                    } else {
                        for (String s : OpsCommon.list(o)) p.allow.add(parseAllow(s, null));
                    }
                }
                break;
            }
            default:
                throw new UsageException("unknown policy key '" + rawKey + "' (known: fail-on, kev, epss, deny-license, max-age-days, deny, deny-archived, allow-vuln, include-test)");
        }
    }

    static Policy load(Path file) throws IOException {
        Policy p = new Policy();
        p.source = file.toString();
        String name = file.getFileName().toString().toLowerCase(Locale.ROOT);
        if (name.endsWith(".json")) {
            Object j;
            try {
                j = Json.parse(Files.readString(file, StandardCharsets.UTF_8));
            } catch (IllegalArgumentException e) {
                throw new UsageException(file + " is not valid JSON: " + e.getMessage());
            }
            if (!(j instanceof Map)) throw new UsageException(file + ": the policy must be a JSON object");
            Map<String, Object> root = Json.map(j);
            if (root.get("policy") instanceof Map) root = Json.map(root, "policy");
            for (Map.Entry<String, Object> e : root.entrySet()) {
                if (e.getKey().startsWith("$") || e.getKey().equals("comment")) continue;
                if (e.getValue() != null) apply(p, e.getKey(), e.getValue());
            }
        } else {
            Properties props = new Properties();
            try (Reader r = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                props.load(r);
            }
            for (String k : props.stringPropertyNames()) apply(p, k, props.getProperty(k));
        }
        return p;
    }

    Policy policy(Ctx ctx, Args args) throws IOException {
        Policy p = null;
        String explicit = args.get("policy");
        if (explicit != null) {
            Path f = Paths.get(explicit);
            if (!Files.isRegularFile(f)) throw new UsageException("policy file " + explicit + " does not exist");
            p = load(f);
        } else {
            String fopt = ctx.globals().get("file");
            Path base = Paths.get(fopt == null ? "." : fopt);
            if (!Files.isDirectory(base)) base = base.toAbsolutePath().getParent();
            if (base != null) {
                for (String n : new String[] {"policy.properties", "policy.json"}) {
                    Path f = base.resolve(".sm-maven").resolve(n);
                    if (Files.isRegularFile(f)) {
                        p = load(f);
                        break;
                    }
                }
            }
        }
        boolean fromFile = p != null;
        if (p == null) p = new Policy();
        boolean flags = false;
        if (args.get("fail-on") != null) { p.failOn = failOn(args.get("fail-on"), "--fail-on"); flags = true; }
        if (args.has("kev")) { p.kev = args.flag("kev"); flags = true; }
        if (args.get("epss") != null) {
            double d = args.getDouble("epss", 0);
            if (d < 0 || d > 1) throw new UsageException("--epss expects a probability between 0 and 1 (or a percentage), got '" + args.get("epss") + "'");
            p.epss = d == 0 ? null : d;
            flags = true;
        }
        if (args.has("deny-license")) { p.denyLicense = args.getAll("deny-license"); flags = true; }
        if (args.get("max-age-days") != null) {
            int d = args.getInt("max-age-days", 0);
            if (d < 0) throw new UsageException("--max-age-days must be positive");
            p.maxAgeDays = d == 0 ? null : d;
            flags = true;
        }
        if (args.has("deny")) { p.deny = args.getAll("deny"); flags = true; }
        if (args.has("deny-archived")) { p.denyArchived = args.flag("deny-archived"); flags = true; }
        if (args.has("allow-vuln")) {
            p.allow.clear();
            for (String s : args.getAll("allow-vuln")) p.allow.add(parseAllow(s, null));
        }
        if (args.has("include-test")) p.includeTest = args.flag("include-test");
        if (!fromFile && !flags && !p.anyRule()) {
            p.failOn = "critical";
            p.kev = true;
            p.source = "default";
        } else if (flags) {
            p.source = fromFile ? p.source + " + command line" : "command line";
        }
        return p;
    }

    // ---------------------------------------------------------------- evaluation

    static final class Rule {
        final String id, title, config;
        boolean enabled;
        String error;
        final List<Map<String, Object>> violations = new ArrayList<>();

        Rule(String id, String title, String config, boolean enabled) {
            this.id = id;
            this.title = title;
            this.config = config;
            this.enabled = enabled;
        }

        String status() { return !enabled ? "off" : error != null && violations.isEmpty() ? "error" : violations.isEmpty() ? "pass" : "fail"; }

        Object toJson() {
            return OpsCommon.m("id", id, "title", title, "config", config, "status", status(), "error", error,
                    "count", violations.size(), "violations", violations);
        }
    }

    private static final Map<String, String> SARIF_NAMES = Map.of("severity", "VulnerableDependency", "kev", "KnownExploitedVulnerability",
            "epss", "LikelyExploitedVulnerability", "license", "DeniedLicense", "maintenance", "UnmaintainedDependency",
            "deny", "BannedDependency", "archived", "ArchivedSourceRepository");

    private static final String RULE_URI = "https://slashmark.in/sm-maven/gate#";

    @Override
    public int run(Ctx ctx, Args args) throws Exception {
        String format = args.get("format", null);
        if (args.flag("sarif")) format = "sarif";
        if (args.flag("junit")) format = "junit";
        if (format == null) format = "text";
        format = format.toLowerCase(Locale.ROOT);
        if (!List.of("text", "github", "junit", "sarif", "json").contains(format)) {
            throw new UsageException("--format expects text, github, junit, sarif or json, got '" + format + "'");
        }
        String output = args.get("output");
        boolean warnOnly = args.flag("warn-only") || args.flag("no-fail");
        Policy p = policy(ctx, args);
        long t0 = System.currentTimeMillis();

        Ctx.Target target = ctx.target(args, 0);
        Set<String> scopes = p.includeTest ? null : Set.of("compile", "runtime", "system");
        List<DepNode> nodes = new ArrayList<>(target.dependencies(scopes));
        if (target.artifact != null) {
            // Gating published coordinates covers the artifact itself, not only what it pulls in.
            nodes.add(0, DepNode.artifactRoot(target.artifact.groupId, target.artifact.artifactId, target.artifact.version, "jar"));
        }
        Map<String, DepNode> byGav = new LinkedHashMap<>();
        for (DepNode n : nodes) byGav.putIfAbsent(n.gav().toString(), n);

        Rule severity = new Rule("severity", "Vulnerability severity", p.failOn == null ? null : "fail on " + p.failOn + " and above", p.failOn != null);
        Rule kev = new Rule("kev", "Known exploited vulnerabilities (CISA KEV)", p.kev ? "any KEV entry" : null, p.kev);
        Rule epss = new Rule("epss", "Exploit probability (FIRST EPSS)", p.epss == null ? null : "EPSS >= " + p.epss, p.epss != null);
        Rule license = new Rule("license", "Licence policy", p.denyLicense.isEmpty() ? null : "deny " + String.join(", ", p.denyLicense), !p.denyLicense.isEmpty());
        Rule age = new Rule("maintenance", "Maintained dependencies", p.maxAgeDays == null ? null : "newest release within " + p.maxAgeDays + " days", p.maxAgeDays != null);
        Rule deny = new Rule("deny", "Banned coordinates", p.deny.isEmpty() ? null : "deny " + String.join(", ", p.deny), !p.deny.isEmpty());
        Rule archived = new Rule("archived", "Archived source repositories", p.denyArchived ? "source repository must not be archived" : null, p.denyArchived);
        List<Rule> rules = List.of(severity, kev, epss, license, age, deny, archived);
        List<Map<String, Object>> suppressed = new ArrayList<>();

        // Vulnerabilities (severity, KEV, EPSS) with accepted risks applied.
        if (severity.enabled || kev.enabled || epss.enabled) {
            List<Risk.Finding> findings = Risk.assess(ctx, nodes, true);
            for (Risk.Finding f : findings) {
                Allow allow = allowed(p, f);
                boolean sevHit = severity.enabled && OpsCommon.sevRank(f.vuln.severity) >= OpsCommon.sevRank(p.failOn);
                boolean kevHit = kev.enabled && f.kev != null;
                boolean epssHit = epss.enabled && f.epss != null && f.epss.epss >= p.epss;
                if (!sevHit && !kevHit && !epssHit) continue;
                if (allow != null) {
                    suppressed.add(OpsCommon.m("advisory", f.vuln.id, "cve", f.vuln.cves().isEmpty() ? null : f.vuln.cves().get(0), "artifact", f.gav.toString(),
                            "severity", f.vuln.severity, "allowedBy", allow.id, "until", allow.until == null ? null : allow.until.toString(), "reason", allow.reason));
                    continue;
                }
                String label = vulnLabel(f);
                if (sevHit) severity.violations.add(violation(target, f.node, f.gav, f.vuln.severity, label, vulnData(f)));
                if (kevHit) kev.violations.add(violation(target, f.node, f.gav, "critical", label + " is exploited in the wild (KEV since " + f.kev.dateAdded + ")", vulnData(f)));
                if (epssHit) epss.violations.add(violation(target, f.node, f.gav, sevOr(f.vuln.severity, "high"),
                        label + " has EPSS " + String.format(Locale.ROOT, "%.2f", f.epss.epss) + " (top " + top(f.epss.percentile) + ")", vulnData(f)));
            }
        }

        if (license.enabled && !nodes.isEmpty()) {
            List<Gav> gavs = new ArrayList<>();
            for (DepNode n : nodes) gavs.add(n.gav());
            ctx.ui.progress("Reading licences of " + gavs.size() + " artifacts...");
            Map<String, List<String>> lic = OpsCommon.licenses(ctx, gavs);
            ctx.ui.progressDone();
            boolean denyUnknown = false;
            for (String s : p.denyLicense) if (s.equalsIgnoreCase("unknown") || s.equalsIgnoreCase("none")) denyUnknown = true;
            for (DepNode n : nodes) {
                List<String> ids = lic.getOrDefault(n.gav().toString(), List.of());
                boolean hit;
                if (ids.isEmpty()) hit = denyUnknown;
                else {
                    hit = true;
                    for (String id : ids) if (!Licenses.matches(id, p.denyLicense)) { hit = false; break; }
                }
                if (!hit) continue;
                String what = ids.isEmpty() ? "declares no licence" : "is licensed " + String.join(" OR ", ids) + " (" + Licenses.bestOf(ids).label + ")";
                license.violations.add(violation(target, n, n.gav(), "high", n.gav() + " " + what, OpsCommon.m("licenses", ids, "category", Licenses.bestOf(ids).label)));
            }
        }

        if (age.enabled && !nodes.isEmpty()) {
            List<String> gas = new ArrayList<>(new LinkedHashSet<>(nodes.stream().map(DepNode::ga).toList()));
            ctx.ui.progress("Checking release activity of " + gas.size() + " artifacts...");
            Map<String, OpsCommon.ReleaseInfo> rel = OpsCommon.releases(ctx, gas);
            ctx.ui.progressDone();
            long now = System.currentTimeMillis();
            for (DepNode n : nodes) {
                OpsCommon.ReleaseInfo ri = rel.get(n.ga());
                if (ri == null || ri.lastRelease <= 0) continue;
                long days = (now - ri.lastRelease) / 86_400_000L;
                if (days <= p.maxAgeDays) continue;
                age.violations.add(violation(target, n, n.gav(), "medium",
                        n.ga() + " looks unmaintained: newest release " + ri.newest + " was " + days + " days ago (limit " + p.maxAgeDays + ")",
                        OpsCommon.m("newest", ri.newest, "lastRelease", Instant.ofEpochMilli(ri.lastRelease).toString(), "daysSinceRelease", days)));
            }
        }

        if (deny.enabled) {
            for (DepNode n : nodes) {
                for (String pat : p.deny) {
                    if (!OpsCommon.coordinateMatches(pat, n.gav())) continue;
                    deny.violations.add(violation(target, n, n.gav(), "high", n.gav() + " is banned by '" + pat + "'" + (n.isDirect() ? "" : " (via " + n.pathString() + ")"),
                            OpsCommon.m("pattern", pat)));
                    break;
                }
            }
        }

        if (archived.enabled && !nodes.isEmpty()) {
            ctx.ui.progress("Checking source repositories on GitHub...");
            List<Http.Result<GitHub.Repo>> res = ctx.http.parallel(nodes, n -> {
                ModelBuilder.Model m = ctx.models.buildRemote(n.gav());
                if (m == null) return null;
                String r = GitHub.repoFromUrl(m.pom.scmUrl);
                if (r == null) r = GitHub.repoFromUrl(m.pom.scmConnection);
                if (r == null) r = GitHub.repoFromUrl(m.pom.url);
                return r == null ? null : ctx.github.repo(r);
            });
            ctx.ui.progressDone();
            for (int i = 0; i < nodes.size(); i++) {
                Http.Result<GitHub.Repo> r = res.get(i);
                if (!r.ok()) {
                    if (archived.error == null) archived.error = r.error.getMessage();
                    continue;
                }
                if (r.value == null || !r.value.archived) continue;
                DepNode n = nodes.get(i);
                archived.violations.add(violation(target, n, n.gav(), "high", n.gav() + ": source repository " + r.value.fullName + " is archived (no further fixes)",
                        OpsCommon.m("repository", r.value.fullName)));
            }
            if (archived.error != null) ctx.ui.warnErr("GitHub lookups failed for some dependencies: " + archived.error);
        }

        List<Map<String, Object>> expired = new ArrayList<>();
        for (Allow a : p.allow) if (a.expired) expired.add(Json.map(Map.of("x", a.toJson()), "x"));

        int failed = 0, total = 0, enabledCount = 0;
        for (Rule r : rules) {
            if (!r.enabled) continue;
            enabledCount++;
            if (!r.violations.isEmpty()) failed++;
            total += r.violations.size();
        }
        boolean passed = failed == 0;
        long ms = System.currentTimeMillis() - t0;

        Map<String, Object> doc = OpsCommon.m("tool", "gate", "target", target.label, "passed", passed, "rulesFailed", failed, "rulesChecked", enabledCount,
                "violations", total, "dependencies", nodes.size(), "policy", p.toJson(), "rules", rulesJson(rules),
                "suppressed", suppressed, "expiredAllowances", expired, "checkedAt", Instant.now().toString());

        String report = null;
        switch (format) {
            case "github": report = github(target, rules, passed, failed, total, expired); break;
            case "junit": report = junit(target, rules, ms); break;
            case "sarif": report = sarif(ctx, target, rules, suppressed); break;
            case "json": report = Json.write(doc) + "\n"; break;
            default: break;
        }
        if (output != null) {
            Path out = Paths.get(output);
            if (out.toAbsolutePath().getParent() != null) Files.createDirectories(out.toAbsolutePath().getParent());
            Files.writeString(out, report != null ? report : Json.write(doc) + "\n", StandardCharsets.UTF_8);
        }
        if (ctx.ui.json) {
            ctx.ui.emitJson(doc);
        } else if (report != null && output == null) {
            byte[] b = report.getBytes(StandardCharsets.UTF_8);
            ctx.ui.out().write(b, 0, b.length);
            ctx.ui.out().flush();
        } else {
            printText(ctx.ui, target, p, rules, suppressed, expired, nodes.size(), passed, failed, total);
            if (output != null) ctx.ui.note("Report written to " + output + " (" + format + ")");
        }
        return passed || warnOnly ? Exit.OK : Exit.ISSUES;
    }

    private static String top(double percentile) {
        double t = Math.max(0, 100 - percentile * 100);
        return (t < 1 ? String.format(Locale.ROOT, "%.2f", t) : String.format(Locale.ROOT, "%.1f", t)) + "%";
    }

    private static String sevOr(String s, String def) { return s == null || s.equals("unknown") ? def : s; }

    private static Allow allowed(Policy p, Risk.Finding f) {
        for (Allow a : p.allow) {
            if (a.expired) continue;
            if (a.id.equalsIgnoreCase(f.vuln.id)) return a;
            for (String al : f.vuln.aliases) if (a.id.equalsIgnoreCase(al)) return a;
        }
        return null;
    }

    private static String vulnLabel(Risk.Finding f) {
        String id = f.vuln.cves().isEmpty() ? f.vuln.id : f.vuln.cves().get(0);
        return id + " in " + f.gav + (f.fix != null ? " (fixed in " + f.fix + ")" : "");
    }

    private static Map<String, Object> vulnData(Risk.Finding f) {
        return OpsCommon.m("advisory", f.vuln.id, "cve", f.vuln.cves().isEmpty() ? null : f.vuln.cves().get(0), "summary", f.vuln.summary,
                "cvss", f.vuln.score >= 0 ? f.vuln.score : null, "kev", f.kev != null, "epss", f.epss == null ? null : f.epss.epss,
                "priority", f.priority, "fixedIn", f.fix, "url", f.vuln.url());
    }

    private static Map<String, Object> violation(Ctx.Target target, DepNode n, Gav gav, String severity, String message, Map<String, Object> extra) {
        OpsCommon.Location loc = OpsCommon.locate(target.project, n);
        Map<String, Object> v = OpsCommon.m("artifact", gav.toString(), "severity", severity, "message", message,
                "scope", n == null ? null : n.scope, "direct", n == null ? null : n.isDirect(), "path", n == null ? null : n.pathString(),
                "file", loc == null ? null : loc.file, "line", loc == null || loc.line <= 0 ? null : loc.line);
        if (extra != null) v.putAll(extra);
        return v;
    }

    private static List<Object> rulesJson(List<Rule> rules) {
        List<Object> l = new ArrayList<>();
        for (Rule r : rules) l.add(r.toJson());
        return l;
    }

    // ---------------------------------------------------------------- text

    private static void printText(Ui ui, Ctx.Target target, Policy p, List<Rule> rules, List<Map<String, Object>> suppressed,
                                  List<Map<String, Object>> expired, int deps, boolean passed, int failed, int total) {
        ui.title("CI Policy Gate " + ui.dot() + " " + target.label);
        ui.note("Policy: " + p.source + " " + ui.dot() + " " + Ui.plural(deps, "dependency", "dependencies") + " checked"
                + (p.includeTest ? " (all scopes)" : " (compile/runtime scope)"));
        ui.println();
        for (Rule r : rules) {
            if (!r.enabled) continue;
            String head = ui.bold(r.title) + ui.dim(" [" + r.id + "] " + r.config);
            if (r.violations.isEmpty() && r.error != null) {
                ui.warn(head + " " + ui.arrow() + " could not be checked: " + r.error);
                continue;
            }
            if (r.violations.isEmpty()) {
                ui.good(head + " " + ui.arrow() + " pass");
                continue;
            }
            ui.fail(head + " " + ui.arrow() + " " + ui.red(Ui.plural(r.violations.size(), "violation")));
            int shown = 0;
            for (Map<String, Object> v : r.violations) {
                if (++shown > 25 && !ui.verbose) {
                    ui.line(ui.dim("... and " + (r.violations.size() - 25) + " more (--verbose or --json for all)"));
                    break;
                }
                String where = v.get("file") == null ? "" : ui.dim("  " + v.get("file") + (v.get("line") == null ? "" : ":" + v.get("line")));
                ui.line(ui.severity(String.valueOf(v.get("severity"))) + " " + v.get("message") + where);
            }
        }
        if (!suppressed.isEmpty()) {
            ui.section("Accepted risks (allow-vuln)");
            for (Map<String, Object> s : suppressed) {
                ui.line(ui.dim(s.get("advisory") + " in " + s.get("artifact") + " allowed by " + s.get("allowedBy")
                        + (s.get("until") == null ? " (no expiry)" : " until " + s.get("until"))));
            }
        }
        for (Map<String, Object> e : expired) {
            ui.warn("Allowance for " + e.get("id") + " expired on " + e.get("until") + ": it no longer suppresses findings");
        }
        ui.println();
        if (passed) ui.good(ui.green(ui.bold("Policy passed")) + " " + ui.dot() + " " + Ui.plural(rules.stream().filter(r -> r.enabled).count(), "rule") + " checked");
        else ui.fail(ui.red(ui.bold("Policy FAILED")) + " " + ui.dot() + " " + failed + " of " + rules.stream().filter(r -> r.enabled).count()
                + " rules violated, " + Ui.plural(total, "violation"));
    }

    // ---------------------------------------------------------------- GitHub annotations

    static String ghData(String s) { return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A"); }

    static String ghProp(String s) { return ghData(s).replace(":", "%3A").replace(",", "%2C"); }

    private static String github(Ctx.Target target, List<Rule> rules, boolean passed, int failed, int total, List<Map<String, Object>> expired) {
        StringBuilder b = new StringBuilder();
        for (Rule r : rules) {
            if (!r.enabled) continue;
            for (Map<String, Object> v : r.violations) {
                b.append("::error ");
                if (v.get("file") != null) {
                    b.append("file=").append(ghProp(String.valueOf(v.get("file"))));
                    if (v.get("line") != null) b.append(",line=").append(v.get("line"));
                    b.append(',');
                }
                b.append("title=").append(ghProp("sm-maven gate: " + r.title)).append("::").append(ghData("[" + String.valueOf(v.get("severity")).toUpperCase(Locale.ROOT) + "] " + v.get("message"))).append('\n');
            }
            if (r.violations.isEmpty() && r.error != null) b.append("::warning title=").append(ghProp("sm-maven gate: " + r.title)).append("::")
                    .append(ghData("could not be checked: " + r.error)).append('\n');
        }
        for (Map<String, Object> e : expired) {
            b.append("::warning title=").append(ghProp("sm-maven gate: expired allowance")).append("::")
                    .append(ghData("allow-vuln " + e.get("id") + " expired on " + e.get("until"))).append('\n');
        }
        String summary = passed ? "Policy passed for " + target.label : "Policy failed for " + target.label + ": " + failed + " rule(s), " + total + " violation(s)";
        b.append(passed ? "::notice title=" : "::error title=").append(ghProp("sm-maven gate")).append("::").append(ghData(summary)).append('\n');
        return b.toString();
    }

    // ---------------------------------------------------------------- JUnit XML

    private static String junit(Ctx.Target target, List<Rule> rules, long ms) {
        int tests = 0, failures = 0, errors = 0;
        for (Rule r : rules) {
            if (!r.enabled) continue;
            tests++;
            if (!r.violations.isEmpty()) failures++;
            else if (r.error != null) errors++;
        }
        String time = String.format(Locale.ROOT, "%.3f", ms / 1000.0);
        StringBuilder b = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        b.append("<testsuites name=\"sm-maven gate\" tests=\"").append(tests).append("\" failures=\"").append(failures)
                .append("\" errors=\"").append(errors).append("\" time=\"").append(time).append("\">\n");
        b.append("  <testsuite name=\"").append(OpsCommon.xml("sm-maven gate: " + target.label)).append("\" tests=\"").append(tests)
                .append("\" failures=\"").append(failures).append("\" errors=\"").append(errors).append("\" skipped=\"0\" time=\"").append(time)
                .append("\" timestamp=\"").append(Instant.now().toString().substring(0, 19)).append("\">\n");
        for (Rule r : rules) {
            if (!r.enabled) continue;
            b.append("    <testcase classname=\"sm-maven.gate.").append(r.id).append("\" name=\"").append(OpsCommon.xml(r.title + ": " + r.config)).append("\" time=\"0\"");
            if (r.violations.isEmpty() && r.error == null) {
                b.append("/>\n");
                continue;
            }
            b.append(">\n");
            if (r.violations.isEmpty()) {
                b.append("      <error type=\"lookup\" message=\"").append(OpsCommon.xml(r.error)).append("\"/>\n");
            } else {
                StringBuilder body = new StringBuilder();
                for (Map<String, Object> v : r.violations) {
                    body.append('[').append(String.valueOf(v.get("severity")).toUpperCase(Locale.ROOT)).append("] ").append(v.get("message"));
                    if (v.get("file") != null) body.append(" [").append(v.get("file")).append(v.get("line") == null ? "" : ":" + v.get("line")).append(']');
                    body.append('\n');
                }
                b.append("      <failure type=\"").append(r.id).append("\" message=\"").append(OpsCommon.xml(Ui.plural(r.violations.size(), "violation")))
                        .append("\">").append(OpsCommon.xml(body.toString())).append("</failure>\n");
            }
            b.append("    </testcase>\n");
        }
        b.append("  </testsuite>\n</testsuites>\n");
        return b.toString();
    }

    // ---------------------------------------------------------------- SARIF 2.1.0

    private static String sarifLevel(String sev) {
        int r = OpsCommon.sevRank(sev);
        return r >= 3 ? "error" : r == 2 ? "warning" : "note";
    }

    private static String uri(Ctx.Target target, String file) {
        if (file == null || target.project == null) return file;
        Path abs = target.project.root.resolve(file).toAbsolutePath().normalize();
        Path cwd = Paths.get("").toAbsolutePath().normalize();
        if (abs.startsWith(cwd)) return cwd.relativize(abs).toString().replace('\\', '/');
        return file;
    }

    private static String sarif(Ctx ctx, Ctx.Target target, List<Rule> rules, List<Map<String, Object>> suppressed) {
        List<Object> ruleDefs = new ArrayList<>();
        Map<String, Integer> index = new LinkedHashMap<>();
        for (Rule r : rules) {
            if (!r.enabled) continue;
            index.put(r.id, ruleDefs.size());
            ruleDefs.add(OpsCommon.m("id", "gate/" + r.id, "name", SARIF_NAMES.getOrDefault(r.id, r.id),
                    "shortDescription", Json.obj("text", r.title),
                    "fullDescription", Json.obj("text", r.title + ": " + r.config),
                    "helpUri", RULE_URI + r.id,
                    "help", Json.obj("text", "Policy rule '" + r.id + "' of sm-maven gate (" + r.config + "). Upgrade, replace or explicitly accept the dependency."),
                    "defaultConfiguration", Json.obj("level", "error"),
                    "properties", Json.obj("tags", List.of("security", "supply-chain", "maven"), "precision", "high")));
        }
        List<Object> results = new ArrayList<>();
        for (Rule r : rules) {
            if (!r.enabled) continue;
            for (Map<String, Object> v : r.violations) results.add(sarifResult(target, r.id, index.get(r.id), v, null));
        }
        for (Map<String, Object> s : suppressed) {
            Integer ix = index.containsKey("severity") ? index.get("severity") : index.containsKey("kev") ? index.get("kev") : index.get("epss");
            String rid = index.containsKey("severity") ? "severity" : index.containsKey("kev") ? "kev" : "epss";
            if (ix == null) continue;
            Map<String, Object> v = OpsCommon.m("artifact", s.get("artifact"), "severity", s.get("severity"),
                    "message", s.get("advisory") + " in " + s.get("artifact") + " (accepted risk)", "advisory", s.get("advisory"));
            results.add(sarifResult(target, rid, ix, v, "allow-vuln " + s.get("allowedBy") + (s.get("until") == null ? "" : " until " + s.get("until"))));
        }
        Map<String, Object> driver = OpsCommon.m("name", "sm-maven", "fullName", "Slash Mark Maven Suite: CI Policy Gate", "version", Http.VERSION,
                "semanticVersion", Http.VERSION, "informationUri", "https://slashmark.in", "organization", "Slash Mark IT Solutions", "rules", ruleDefs);
        Map<String, Object> run = OpsCommon.m("tool", Json.obj("driver", driver),
                "automationDetails", Json.obj("id", "sm-maven/gate/" + target.label),
                "invocations", List.of(Json.obj("executionSuccessful", true, "endTimeUtc", Instant.now().toString())),
                "results", results);
        Map<String, Object> doc = OpsCommon.m("$schema", "https://json.schemastore.org/sarif-2.1.0.json", "version", "2.1.0", "runs", List.of(run));
        return Json.write(doc) + "\n";
    }

    private static Object sarifResult(Ctx.Target target, String ruleId, int ruleIndex, Map<String, Object> v, String suppression) {
        Map<String, Object> res = new LinkedHashMap<>();
        res.put("ruleId", "gate/" + ruleId);
        res.put("ruleIndex", ruleIndex);
        res.put("level", sarifLevel(String.valueOf(v.get("severity"))));
        res.put("message", Json.obj("text", String.valueOf(v.get("message"))));
        Map<String, Object> loc = new LinkedHashMap<>();
        String file = (String) v.get("file");
        if (file == null && target.project != null) file = "pom.xml";
        if (file != null) {
            Map<String, Object> phys = new LinkedHashMap<>();
            phys.put("artifactLocation", Json.obj("uri", uri(target, file)));
            Object line = v.get("line");
            if (line instanceof Number && ((Number) line).intValue() > 0) phys.put("region", Json.obj("startLine", ((Number) line).intValue()));
            loc.put("physicalLocation", phys);
        }
        loc.put("logicalLocations", List.of(Json.obj("fullyQualifiedName", String.valueOf(v.get("artifact")), "kind", "package")));
        res.put("locations", List.of(loc));
        String fp = ruleId + "|" + v.get("artifact") + "|" + (v.get("advisory") == null ? "" : v.get("advisory"));
        res.put("partialFingerprints", Json.obj("smMavenGate/v1", in.slashmark.maven.util.Hash.sha256Hex(fp.getBytes(StandardCharsets.UTF_8)).substring(0, 32)));
        Map<String, Object> props = new LinkedHashMap<>();
        for (String k : new String[] {"artifact", "severity", "advisory", "cve", "kev", "epss", "fixedIn", "scope", "path", "licenses", "pattern"}) {
            if (v.get(k) != null) props.put(k, v.get(k));
        }
        res.put("properties", props);
        if (suppression != null) res.put("suppressions", List.of(Json.obj("kind", "external", "status", "accepted", "justification", suppression)));
        return res;
    }
}
