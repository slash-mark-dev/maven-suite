package in.slashmark.maven.tools;

import in.slashmark.maven.analysis.Licenses;
import in.slashmark.maven.analysis.Risk;
import in.slashmark.maven.cli.Args;
import in.slashmark.maven.cli.Command;
import in.slashmark.maven.cli.Ctx;
import in.slashmark.maven.cli.Exit;
import in.slashmark.maven.cli.Project;
import in.slashmark.maven.cli.Ui;
import in.slashmark.maven.cli.UsageException;
import in.slashmark.maven.data.GitHub;
import in.slashmark.maven.model.Gav;
import in.slashmark.maven.model.MavenVersion;
import in.slashmark.maven.resolve.DepNode;
import in.slashmark.maven.resolve.Resolver;
import in.slashmark.maven.util.Http;
import in.slashmark.maven.util.HttpException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Multi-Repo Live Dashboard: One live risk view across every Maven repository of an organisation. */
public final class Dashboard extends Command {
    @Override public String name() { return "dashboard"; }
    @Override public String title() { return "Multi-Repo Live Dashboard"; }
    @Override public String group() { return "Operations"; }
    @Override public String summary() { return "One live risk view across every Maven repository of an organisation"; }

    @Override
    public Set<String> flags() { return Set.of("include-archived", "include-forks", "include-test"); }

    static final List<String> DEFAULT_LICENSE_ISSUES = List.of("strong-copyleft", "network-copyleft", "source-available");

    @Override
    public String help() {
        return String.join("\n",
                "Usage: sm-maven dashboard [path ...] [--org <github-org>] [options]",
                "",
                summary() + ".",
                "Finds the pom.xml files of every repository of a GitHub organisation (or takes local project folders),",
                "resolves them and summarises each one: vulnerabilities by priority (P1 act now .. P4 defer, with CISA KEV",
                "and EPSS), known-exploited count, outdated dependencies, licence issues and a health grade A-F.",
                "GITHUB_TOKEN (or GH_TOKEN) is used for the GitHub API when set; it is never printed.",
                "",
                "Options:",
                "  --org <name>             GitHub organisation or user to scan",
                "  --repos <names>          Only these repositories of the organisation (globs allowed)",
                "  -n, --limit <n>          At most n repositories (default 50)",
                "  --max-poms <n>           At most n pom.xml files per repository (default 50)",
                "  --include-archived       Also scan archived repositories",
                "  --include-forks          Also scan forks",
                "  --include-test           Count test-scoped dependencies too (default: compile/runtime)",
                "  --license-issues <list>  Licences that count as issues (default strong-copyleft,network-copyleft,",
                "                           source-available; SPDX ids, GPL-* prefixes or categories)",
                "  --format <fmt>           text (default), html (self-contained dashboard page) or json",
                "  --html                   Shortcut for --format html",
                "  -o, --output <file>      Where to write the HTML page (default sm-maven-dashboard.html)",
                "",
                "Grade: 100 minus 25 per P1, 10 per P2, 4 per P3, 1 per P4 finding, 2 per outdated dependency (max 20) and",
                "8 per licence issue (max 24); A >= 90, B >= 75, C >= 60, D >= 40, F below.",
                "Exit codes: 0 no P1 (act now) findings anywhere, 1 at least one repository has P1 findings.",
                "",
                "Examples:",
                "  sm-maven dashboard --org slash-mark-dev",
                "  sm-maven dashboard --org slash-mark-dev --html -o public/risk.html",
                "  sm-maven dashboard services/billing services/orders --json");
    }

    // ---------------------------------------------------------------- model

    static final class Entry {
        String name, source, url, branch, error, location;
        boolean archived;
        long pushedAt;
        final List<String> poms = new ArrayList<>();
        final List<String> modules = new ArrayList<>();
        int deps;
        final Map<String, Integer> priority = new LinkedHashMap<>();
        final Map<String, Integer> severity = new LinkedHashMap<>();
        int kev, outdated, vulns;
        final List<Map<String, Object>> top = new ArrayList<>();
        final List<Map<String, Object>> outdatedList = new ArrayList<>();
        final List<Map<String, Object>> licenseIssues = new ArrayList<>();
        int score = 100;
        String grade = "A";

        Entry() {
            for (String p : List.of("P1", "P2", "P3", "P4")) priority.put(p, 0);
            for (String s : List.of("critical", "high", "medium", "low")) severity.put(s, 0);
        }

        Map<String, Object> toJson() {
            return OpsCommon.m("name", name, "source", source, "url", url, "branch", branch, "archived", archived,
                    "pushedAt", pushedAt > 0 ? Instant.ofEpochMilli(pushedAt).toString() : null, "poms", poms, "modules", modules,
                    "error", error, "dependencies", deps, "grade", error != null ? null : grade, "score", error != null ? null : score,
                    "vulnerabilities", OpsCommon.m("total", vulns, "byPriority", priority, "bySeverity", severity),
                    "kev", kev, "outdated", outdated, "licenseIssues", licenseIssues.size(),
                    "topFindings", top, "outdatedDependencies", outdatedList, "licenseFindings", licenseIssues);
        }
    }

    // ---------------------------------------------------------------- run

    @Override
    public int run(Ctx ctx, Args args) throws Exception {
        String format = args.get("format", null);
        if (args.flag("html")) format = "html";
        format = format == null ? "text" : format.toLowerCase(Locale.ROOT);
        if (!List.of("text", "html", "json").contains(format)) throw new UsageException("--format expects text, html or json, got '" + format + "'");
        String org = args.get("org");
        if (org != null && (org.equals("true") || !org.matches("[A-Za-z0-9_.\\-]+"))) throw new UsageException("--org expects a GitHub organisation or user name");
        int limit = args.getInt("limit", 50);
        int maxPoms = args.getInt("max-poms", 50);
        List<String> only = args.getAll("repos");
        boolean includeArchived = args.flag("include-archived");
        boolean includeForks = args.flag("include-forks");
        boolean includeTest = args.flag("include-test");
        List<String> licIssues = args.has("license-issues") ? args.getAll("license-issues") : DEFAULT_LICENSE_ISSUES;
        String output = args.get("output");
        Set<String> scopes = includeTest ? null : Set.of("compile", "runtime", "system");

        List<Entry> entries = new ArrayList<>();
        List<Map<String, Object>> skipped = new ArrayList<>();
        Path tmp = Files.createTempDirectory("sm-maven-dashboard");
        try {
            if (org != null) {
                ctx.ui.progress("Listing repositories of " + org + "...");
                List<GitHub.Repo> repos;
                try {
                    repos = ctx.github.orgRepos(org, Math.max(limit, 1) * 4);
                } catch (HttpException e) {
                    if (e.status == 404) throw new UsageException("GitHub organisation or user '" + org + "' was not found");
                    throw e;
                }
                ctx.ui.progressDone();
                if (repos.isEmpty()) throw new UsageException("GitHub organisation or user '" + org + "' has no repositories (or was not found)");
                repos.sort(Comparator.comparing(r -> r.fullName.toLowerCase(Locale.ROOT)));
                int n = 0;
                for (GitHub.Repo r : repos) {
                    String shortName = r.fullName.substring(r.fullName.indexOf('/') + 1);
                    if (!only.isEmpty() && only.stream().noneMatch(p -> OpsCommon.globMatch(p, shortName) || OpsCommon.globMatch(p, r.fullName))) continue;
                    if (r.archived && !includeArchived) { skipped.add(OpsCommon.m("name", r.fullName, "reason", "archived")); continue; }
                    if (r.fork && !includeForks) { skipped.add(OpsCommon.m("name", r.fullName, "reason", "fork")); continue; }
                    if (n >= limit) { skipped.add(OpsCommon.m("name", r.fullName, "reason", "over --limit")); continue; }
                    Entry e = new Entry();
                    e.name = r.fullName;
                    e.source = "github";
                    e.url = r.htmlUrl != null ? r.htmlUrl : "https://github.com/" + r.fullName;
                    e.branch = r.defaultBranch == null ? "main" : r.defaultBranch;
                    e.archived = r.archived;
                    e.pushedAt = r.pushedAt;
                    ctx.ui.progress("Scanning " + r.fullName + "...");
                    List<Path> roots;
                    try {
                        roots = download(ctx, r.fullName, e.branch, tmp.resolve("r" + n), maxPoms, e);
                    } catch (HttpException ex) {
                        e.error = "GitHub: " + ex.getMessage();
                        entries.add(e);
                        n++;
                        continue;
                    }
                    ctx.ui.progressDone();
                    if (e.poms.isEmpty()) {
                        skipped.add(OpsCommon.m("name", r.fullName, "reason", "no pom.xml"));
                        continue;
                    }
                    n++;
                    analyse(ctx, e, roots, scopes, licIssues);
                    entries.add(e);
                }
            }
            List<String> paths = new ArrayList<>(args.positionals());
            if (org == null && paths.isEmpty()) paths.add(ctx.globals().get("file") == null ? "." : ctx.globals().get("file"));
            for (String p : paths) {
                Path path = Paths.get(p);
                Path pom = Files.isDirectory(path) ? path.resolve("pom.xml") : path;
                if (!Files.isRegularFile(pom)) throw new UsageException("no pom.xml found at " + path.toAbsolutePath().normalize());
                Entry e = new Entry();
                e.source = "local";
                e.location = pom.toAbsolutePath().normalize().toString();
                e.url = e.location;
                e.poms.add(path.toString());
                analyse(ctx, e, List.of(pom), scopes, licIssues);
                entries.add(e);
            }
        } finally {
            deleteTree(tmp);
        }

        // Totals
        Map<String, Object> totals = totals(entries);
        Map<String, Object> doc = OpsCommon.m("tool", "dashboard", "org", org, "generatedAt", Instant.now().toString(),
                "repositories", entriesJson(entries), "totals", totals, "skipped", skipped);
        if (format.equals("html")) {
            Path out = Paths.get(output != null ? output : "sm-maven-dashboard.html");
            if (out.toAbsolutePath().getParent() != null) Files.createDirectories(out.toAbsolutePath().getParent());
            Files.writeString(out, html(org, entries, totals, skipped), StandardCharsets.UTF_8);
            doc.put("htmlFile", out.toAbsolutePath().normalize().toString());
        } else if (output != null) {
            Path out = Paths.get(output);
            if (out.toAbsolutePath().getParent() != null) Files.createDirectories(out.toAbsolutePath().getParent());
            Files.writeString(out, in.slashmark.maven.util.Json.write(doc) + "\n", StandardCharsets.UTF_8);
        }
        if (ctx.ui.json || format.equals("json")) {
            ctx.ui.emitJson(doc);
        } else {
            print(ctx.ui, org, entries, totals, skipped);
            if (doc.get("htmlFile") != null) ctx.ui.good("Dashboard written to " + doc.get("htmlFile"));
        }
        int p1 = ((Number) totals.get("p1")).intValue();
        return p1 > 0 ? Exit.ISSUES : Exit.OK;
    }

    /** Downloads every pom.xml of a repository into dir (same layout) and returns the build roots. */
    private static List<Path> download(Ctx ctx, String repo, String branch, Path dir, int maxPoms, Entry e) throws HttpException, IOException {
        List<String> files = ctx.github.findFiles(repo, branch, "pom.xml");
        List<String> keep = new ArrayList<>();
        for (String f : files) {
            // POMs under src/ are test fixtures or archetype templates, not part of the build.
            if (f.startsWith("src/") || f.contains("/src/") || f.contains("/target/")) continue;
            keep.add(f);
        }
        keep.sort(Comparator.comparingInt((String f) -> f.split("/").length).thenComparing(f -> f));
        if (keep.size() > maxPoms) keep = keep.subList(0, maxPoms);
        List<byte[]> contents = ctx.http.parallelOrNull(keep, f -> ctx.github.file(repo, f, branch));
        List<Path> written = new ArrayList<>();
        for (int i = 0; i < keep.size(); i++) {
            if (contents.get(i) == null) continue;
            Path p = dir.resolve(keep.get(i)).normalize();
            if (!p.startsWith(dir)) continue;
            Files.createDirectories(p.getParent());
            Files.write(p, contents.get(i));
            written.add(p);
            e.poms.add(keep.get(i));
        }
        return written;
    }

    private void analyse(Ctx ctx, Entry e, List<Path> pomFiles, Set<String> scopes, List<String> licIssues) {
        try {
            // Load the shallowest POM first; POMs that are not modules of an earlier build are separate builds.
            Set<Path> covered = new LinkedHashSet<>();
            List<Project> projects = new ArrayList<>();
            for (Path pom : pomFiles) {
                Path abs = pom.toAbsolutePath().normalize();
                if (covered.contains(abs)) continue;
                Project p = Project.load(abs, ctx.models);
                for (Project.Module m : p.modules) {
                    covered.add(m.pom.toAbsolutePath().normalize());
                    e.modules.add(m.gav().toString());
                }
                projects.add(p);
            }
            if (e.name == null) e.name = projects.get(0).rootModule().model.pom.artifactId;
            Resolver.Options opt = new Resolver.Options();
            opt.includeTest = scopes == null;
            Map<String, DepNode> nodes = new LinkedHashMap<>();
            for (Project p : projects) {
                p.resolveAll(ctx.resolver, opt, ctx.ui);
                for (DepNode n : p.allResolved(scopes)) nodes.putIfAbsent(n.gav().toString(), n);
            }
            List<DepNode> list = new ArrayList<>(nodes.values());
            e.deps = list.size();
            if (list.isEmpty()) return;

            List<Risk.Finding> findings = Risk.assess(ctx, list, true);
            e.vulns = findings.size();
            for (Risk.Finding f : findings) {
                e.priority.merge(f.priority, 1, Integer::sum);
                String sev = f.vuln.severity == null ? "unknown" : f.vuln.severity.equals("moderate") ? "medium" : f.vuln.severity;
                if (e.severity.containsKey(sev)) e.severity.merge(sev, 1, Integer::sum);
                if (f.kev != null) e.kev++;
                if (e.top.size() < 5) {
                    e.top.add(OpsCommon.m("advisory", f.vuln.id, "cve", f.vuln.cves().isEmpty() ? null : f.vuln.cves().get(0), "artifact", f.gav.toString(),
                            "severity", sev, "priority", f.priority, "kev", f.kev != null, "epss", f.epss == null ? null : f.epss.epss,
                            "fixedIn", f.fix, "summary", f.vuln.summary, "url", f.vuln.url()));
                }
            }

            List<String> gas = new ArrayList<>();
            for (DepNode n : list) if (!gas.contains(n.ga())) gas.add(n.ga());
            Map<String, OpsCommon.ReleaseInfo> rel = OpsCommon.releases(ctx, gas);
            for (DepNode n : list) {
                OpsCommon.ReleaseInfo ri = rel.get(n.ga());
                if (ri == null || ri.newest == null) continue;
                MavenVersion cur = MavenVersion.of(n.version), nw = MavenVersion.of(ri.newest);
                if (nw.compareTo(cur) <= 0) continue;
                e.outdated++;
                e.outdatedList.add(OpsCommon.m("artifact", n.gav().toString(), "newest", ri.newest, "major", nw.major() != cur.major(), "direct", n.isDirect()));
            }

            List<Gav> gavs = new ArrayList<>();
            for (DepNode n : list) gavs.add(n.gav());
            Map<String, List<String>> lic = OpsCommon.licenses(ctx, gavs);
            for (DepNode n : list) {
                List<String> ids = lic.getOrDefault(n.gav().toString(), List.of());
                if (ids.isEmpty()) {
                    if (licIssues.stream().anyMatch(x -> x.equalsIgnoreCase("unknown"))) {
                        e.licenseIssues.add(OpsCommon.m("artifact", n.gav().toString(), "licenses", ids, "category", "unknown"));
                    }
                    continue;
                }
                boolean all = true;
                for (String id : ids) if (!Licenses.matches(id, licIssues)) all = false;
                if (all) e.licenseIssues.add(OpsCommon.m("artifact", n.gav().toString(), "licenses", ids, "category", Licenses.bestOf(ids).label));
            }
            grade(e);
        } catch (Exception ex) {
            ctx.ui.progressDone();
            e.error = ex.getMessage() == null ? ex.toString() : ex.getMessage();
        }
    }

    static void grade(Entry e) {
        int penalty = 25 * e.priority.get("P1") + 10 * e.priority.get("P2") + 4 * e.priority.get("P3") + e.priority.get("P4")
                + Math.min(20, 2 * e.outdated) + Math.min(24, 8 * e.licenseIssues.size());
        e.score = Math.max(0, 100 - penalty);
        e.grade = e.score >= 90 ? "A" : e.score >= 75 ? "B" : e.score >= 60 ? "C" : e.score >= 40 ? "D" : "F";
    }

    private static Map<String, Object> totals(List<Entry> entries) {
        int deps = 0, vulns = 0, kev = 0, outdated = 0, lic = 0, p1 = 0, p2 = 0, p3 = 0, p4 = 0, errors = 0;
        Map<String, Integer> grades = new LinkedHashMap<>();
        for (String g : List.of("A", "B", "C", "D", "F")) grades.put(g, 0);
        for (Entry e : entries) {
            if (e.error != null) { errors++; continue; }
            deps += e.deps;
            vulns += e.vulns;
            kev += e.kev;
            outdated += e.outdated;
            lic += e.licenseIssues.size();
            p1 += e.priority.get("P1");
            p2 += e.priority.get("P2");
            p3 += e.priority.get("P3");
            p4 += e.priority.get("P4");
            grades.merge(e.grade, 1, Integer::sum);
        }
        return OpsCommon.m("repositories", entries.size(), "errors", errors, "dependencies", deps, "vulnerabilities", vulns, "p1", p1, "p2", p2, "p3", p3, "p4", p4,
                "kev", kev, "outdated", outdated, "licenseIssues", lic, "grades", grades);
    }

    private static List<Object> entriesJson(List<Entry> entries) {
        List<Object> l = new ArrayList<>();
        for (Entry e : entries) l.add(e.toJson());
        return l;
    }

    private static String shortName(Entry e) {
        return e.source.equals("github") && e.name.contains("/") ? e.name.substring(e.name.indexOf('/') + 1) : e.name;
    }

    // ---------------------------------------------------------------- text

    private static String gradeColor(Ui ui, String g) {
        switch (g) {
            case "A": return ui.green(ui.bold(g));
            case "B": return ui.green(g);
            case "C": return ui.yellow(g);
            case "D": return ui.red(g);
            default: return ui.red(ui.bold(g));
        }
    }

    private static void print(Ui ui, String org, List<Entry> entries, Map<String, Object> totals, List<Map<String, Object>> skipped) {
        ui.title("Multi-Repo Live Dashboard" + (org != null ? " " + ui.dot() + " " + org : "") + " " + ui.dot() + " " + Ui.plural(entries.size(), "repository", "repositories"));
        ui.note("live data: OSV, CISA KEV, FIRST EPSS, Maven Central " + ui.dot() + " " + Instant.now().toString().substring(0, 16).replace('T', ' ') + " UTC");
        Ui.Table t = new Ui.Table("Repository", "Grade", "Deps", "P1", "P2", "P3", "P4", "KEV", "Outdated", "Licences", "Top risk").rightAlign(2, 3, 4, 5, 6, 7, 8, 9);
        for (Entry e : entries) {
            if (e.error != null) {
                t.row(shortName(e), ui.red("error"), "", "", "", "", "", "", "", "", ui.red(e.error));
                continue;
            }
            String topRisk = e.top.isEmpty() ? ui.dim("none") : top(e.top.get(0));
            t.row(shortName(e), gradeColor(ui, e.grade) + ui.dim(" " + e.score), e.deps, red(ui, e.priority.get("P1")), e.priority.get("P2"), e.priority.get("P3"),
                    e.priority.get("P4"), red(ui, e.kev), e.outdated, e.licenseIssues.size(), topRisk);
        }
        ui.table(t);
        for (Entry e : entries) {
            if (e.error != null || (e.top.isEmpty() && e.licenseIssues.isEmpty())) continue;
            ui.section(shortName(e) + " " + ui.dot() + " grade " + gradeColor(ui, e.grade));
            for (Map<String, Object> f : e.top) {
                ui.line(String.valueOf(f.get("priority")) + " " + ui.severity(String.valueOf(f.get("severity"))) + " " + top(f)
                        + (Boolean.TRUE.equals(f.get("kev")) ? ui.red(" KEV") : "") + (f.get("fixedIn") == null ? "" : ui.dim(" " + ui.arrow() + " fixed in " + f.get("fixedIn"))));
            }
            if (e.vulns > e.top.size()) ui.line(ui.dim("... and " + (e.vulns - e.top.size()) + " more"));
            for (Map<String, Object> l : e.licenseIssues) ui.line(ui.yellow("licence") + " " + l.get("artifact") + " " + l.get("licenses") + ui.dim(" (" + l.get("category") + ")"));
        }
        ui.println();
        ui.println(ui.bold("Total") + ": " + Ui.plural(n(totals, "dependencies"), "dependency", "dependencies") + ", "
                + Ui.plural(n(totals, "vulnerabilities"), "vulnerability", "vulnerabilities") + " (" + n(totals, "p1") + " act now, "
                + n(totals, "kev") + " known exploited), " + n(totals, "outdated") + " outdated, " + Ui.plural(n(totals, "licenseIssues"), "licence issue"));
        if (!skipped.isEmpty()) {
            List<String> s = new ArrayList<>();
            for (Map<String, Object> m : skipped) s.add(m.get("name") + " (" + m.get("reason") + ")");
            ui.note("skipped: " + String.join(", ", s));
        }
    }

    private static long n(Map<String, Object> m, String k) { return ((Number) m.get(k)).longValue(); }

    private static String red(Ui ui, int n) { return n > 0 ? ui.red(String.valueOf(n)) : String.valueOf(n); }

    private static String top(Map<String, Object> f) {
        String id = f.get("cve") != null ? String.valueOf(f.get("cve")) : String.valueOf(f.get("advisory"));
        return id + " " + f.get("artifact");
    }

    // ---------------------------------------------------------------- HTML

    private static String html(String org, List<Entry> entries, Map<String, Object> totals, List<Map<String, Object>> skipped) {
        String title = "Maven risk dashboard" + (org != null ? " · " + org : "");
        StringBuilder b = new StringBuilder();
        b.append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
                .append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
                .append("<meta name=\"generator\" content=\"sm-maven ").append(Http.VERSION).append("\">\n")
                .append("<title>").append(OpsCommon.html(title)).append("</title>\n<style>\n")
                .append(":root{--bg:#f6f7f9;--card:#fff;--fg:#1d2330;--muted:#6b7385;--line:#e3e6ec;--a:#1f9d55;--b:#5cb85c;--c:#d9a400;--d:#e0702b;--f:#c62828;--kev:#8b0000}\n")
                .append("@media (prefers-color-scheme:dark){:root{--bg:#12151b;--card:#1b2029;--fg:#e6e9ef;--muted:#98a1b3;--line:#2b3240}}\n")
                .append("*{box-sizing:border-box}body{margin:0;font:14px/1.45 system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--fg)}\n")
                .append("header{padding:24px 32px 8px}h1{margin:0;font-size:22px}header p{margin:4px 0 0;color:var(--muted)}\n")
                .append("main{padding:16px 32px 40px;max-width:1300px}\n")
                .append(".kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:20px}\n")
                .append(".kpi{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}.kpi b{display:block;font-size:26px}.kpi span{color:var(--muted)}\n")
                .append("table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}\n")
                .append("th,td{padding:9px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}\n")
                .append("td.n{text-align:right;font-variant-numeric:tabular-nums}.hot{color:var(--f);font-weight:600}\n")
                .append(".grade{display:inline-block;width:30px;height:30px;line-height:30px;border-radius:50%;text-align:center;color:#fff;font-weight:700}\n")
                .append(".g-A{background:var(--a)}.g-B{background:var(--b)}.g-C{background:var(--c)}.g-D{background:var(--d)}.g-F{background:var(--f)}\n")
                .append(".cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(380px,1fr));gap:14px;margin-top:22px}\n")
                .append(".card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}.card h2{margin:0 0 8px;font-size:16px;display:flex;gap:10px;align-items:center}\n")
                .append(".card ul{margin:6px 0 0;padding-left:18px}.card li{margin:3px 0}.muted{color:var(--muted)}.tag{display:inline-block;padding:1px 6px;border-radius:4px;font-size:11px;font-weight:600;color:#fff}\n")
                .append(".sev-critical{background:var(--kev)}.sev-high{background:var(--f)}.sev-medium{background:var(--c)}.sev-low{background:#1e88e5}.sev-unknown{background:#607d8b}.kevtag{background:#000}\n")
                .append("a{color:inherit}footer{padding:0 32px 30px;color:var(--muted);font-size:12px}\n")
                .append("</style>\n</head>\n<body>\n<header><h1>").append(OpsCommon.html(title)).append("</h1><p>Generated ")
                .append(OpsCommon.html(Instant.now().toString().substring(0, 16).replace('T', ' '))).append(" UTC from live OSV, CISA KEV, FIRST EPSS and Maven Central data</p></header>\n<main>\n");
        b.append("<section class=\"kpis\">\n");
        kpi(b, String.valueOf(totals.get("repositories")), "repositories");
        kpi(b, String.valueOf(totals.get("dependencies")), "dependencies");
        kpi(b, String.valueOf(totals.get("p1")), "act now (P1)");
        kpi(b, String.valueOf(totals.get("kev")), "known exploited");
        kpi(b, String.valueOf(totals.get("vulnerabilities")), "vulnerabilities");
        kpi(b, String.valueOf(totals.get("outdated")), "outdated");
        kpi(b, String.valueOf(totals.get("licenseIssues")), "licence issues");
        b.append("</section>\n<table>\n<thead><tr><th>Repository</th><th>Grade</th><th>Deps</th><th>P1</th><th>P2</th><th>P3</th><th>P4</th><th>KEV</th><th>Outdated</th><th>Licences</th><th>Top risk</th></tr></thead>\n<tbody>\n");
        for (Entry e : entries) {
            String link = e.source.equals("github") ? "<a href=\"" + OpsCommon.html(e.url) + "\">" + OpsCommon.html(shortName(e)) + "</a>" : OpsCommon.html(shortName(e));
            if (e.error != null) {
                b.append("<tr><td>").append(link).append("</td><td colspan=\"10\" class=\"hot\">").append(OpsCommon.html(e.error)).append("</td></tr>\n");
                continue;
            }
            b.append("<tr><td>").append(link).append("</td><td><span class=\"grade g-").append(e.grade).append("\" title=\"score ").append(e.score).append("\">")
                    .append(e.grade).append("</span></td>")
                    .append(num(e.deps, false)).append(num(e.priority.get("P1"), true)).append(num(e.priority.get("P2"), false))
                    .append(num(e.priority.get("P3"), false)).append(num(e.priority.get("P4"), false)).append(num(e.kev, true))
                    .append(num(e.outdated, false)).append(num(e.licenseIssues.size(), false)).append("<td>")
                    .append(e.top.isEmpty() ? "<span class=\"muted\">none</span>" : OpsCommon.html(top(e.top.get(0)))).append("</td></tr>\n");
        }
        b.append("</tbody>\n</table>\n<section class=\"cards\">\n");
        for (Entry e : entries) {
            if (e.error != null) continue;
            b.append("<article class=\"card\"><h2><span class=\"grade g-").append(e.grade).append("\">").append(e.grade).append("</span>")
                    .append(OpsCommon.html(e.name)).append(" <span class=\"muted\">score ").append(e.score).append("</span></h2>\n");
            b.append("<div class=\"muted\">").append(e.deps).append(" dependencies · ").append(e.modules.size()).append(" module(s) · ")
                    .append(e.poms.size()).append(" pom.xml").append(e.pushedAt > 0 ? " · last push " + OpsCommon.html(Ui.ago(e.pushedAt)) : "").append("</div>\n");
            if (!e.top.isEmpty()) {
                b.append("<ul>\n");
                for (Map<String, Object> f : e.top) {
                    String sev = String.valueOf(f.get("severity"));
                    b.append("<li><span class=\"tag sev-").append(OpsCommon.html(sev)).append("\">").append(OpsCommon.html(sev.toUpperCase(Locale.ROOT))).append("</span> ")
                            .append(Boolean.TRUE.equals(f.get("kev")) ? "<span class=\"tag kevtag\">KEV</span> " : "")
                            .append("<a href=\"").append(OpsCommon.html(String.valueOf(f.get("url")))).append("\">")
                            .append(OpsCommon.html(String.valueOf(f.get("cve") != null ? f.get("cve") : f.get("advisory")))).append("</a> in <code>")
                            .append(OpsCommon.html(String.valueOf(f.get("artifact")))).append("</code> <span class=\"muted\">")
                            .append(f.get("priority")).append(f.get("fixedIn") == null ? "" : " · fixed in " + OpsCommon.html(String.valueOf(f.get("fixedIn"))))
                            .append("</span></li>\n");
                }
                if (e.vulns > e.top.size()) b.append("<li class=\"muted\">and ").append(e.vulns - e.top.size()).append(" more</li>\n");
                b.append("</ul>\n");
            } else {
                b.append("<p class=\"muted\">No known vulnerabilities.</p>\n");
            }
            if (!e.licenseIssues.isEmpty()) {
                b.append("<p><b>Licence issues</b></p><ul>\n");
                for (Map<String, Object> l : e.licenseIssues) {
                    b.append("<li><code>").append(OpsCommon.html(String.valueOf(l.get("artifact")))).append("</code> ")
                            .append(OpsCommon.html(String.valueOf(l.get("licenses")))).append(" <span class=\"muted\">(").append(OpsCommon.html(String.valueOf(l.get("category")))).append(")</span></li>\n");
                }
                b.append("</ul>\n");
            }
            if (!e.outdatedList.isEmpty()) {
                b.append("<details><summary>").append(e.outdated).append(" outdated</summary><ul>\n");
                for (Map<String, Object> o : e.outdatedList) {
                    b.append("<li><code>").append(OpsCommon.html(String.valueOf(o.get("artifact")))).append("</code> → ").append(OpsCommon.html(String.valueOf(o.get("newest"))))
                            .append(Boolean.TRUE.equals(o.get("major")) ? " <span class=\"muted\">(major)</span>" : "").append("</li>\n");
                }
                b.append("</ul></details>\n");
            }
            b.append("</article>\n");
        }
        b.append("</section>\n</main>\n<footer>");
        if (!skipped.isEmpty()) {
            List<String> s = new ArrayList<>();
            for (Map<String, Object> m : skipped) s.add(m.get("name") + " (" + m.get("reason") + ")");
            b.append("Skipped: ").append(OpsCommon.html(String.join(", ", s))).append("<br>");
        }
        b.append("Grade = 100 − 25·P1 − 10·P2 − 4·P3 − 1·P4 − 2·outdated (max 20) − 8·licence issues (max 24). ")
                .append("Generated by sm-maven dashboard · Slash Mark IT Solutions · informational, not legal advice.</footer>\n</body>\n</html>\n");
        return b.toString();
    }

    private static void kpi(StringBuilder b, String value, String label) {
        b.append("<div class=\"kpi\"><b>").append(OpsCommon.html(value)).append("</b><span>").append(OpsCommon.html(label)).append("</span></div>\n");
    }

    private static String num(int n, boolean hot) {
        return "<td class=\"n" + (hot && n > 0 ? " hot" : "") + "\">" + n + "</td>";
    }

    private static void deleteTree(Path root) {
        if (root == null || !Files.exists(root)) return;
        try (var s = Files.walk(root)) {
            s.sorted(Comparator.reverseOrder()).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (IOException ignored) {
                    // best effort
                }
            });
        } catch (IOException ignored) {
            // best effort
        }
    }
}
