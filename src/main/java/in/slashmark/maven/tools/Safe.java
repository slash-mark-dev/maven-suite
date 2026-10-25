package in.slashmark.maven.tools;

import in.slashmark.maven.analysis.Licenses;
import in.slashmark.maven.bytecode.ApiDiff;
import in.slashmark.maven.bytecode.Jar;
import in.slashmark.maven.cli.Args;
import in.slashmark.maven.cli.Command;
import in.slashmark.maven.cli.Ctx;
import in.slashmark.maven.cli.Exit;
import in.slashmark.maven.cli.Project;
import in.slashmark.maven.cli.Ui;
import in.slashmark.maven.cli.UsageException;
import in.slashmark.maven.data.CentralSearch;
import in.slashmark.maven.data.Osv;
import in.slashmark.maven.model.Dependency;
import in.slashmark.maven.model.Gav;
import in.slashmark.maven.model.MavenVersion;
import in.slashmark.maven.resolve.DepNode;
import in.slashmark.maven.resolve.Graph;
import in.slashmark.maven.resolve.Resolver;
import in.slashmark.maven.util.HttpException;
import in.slashmark.maven.util.Json;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Safe Version Finder: Newest version with no known vulnerabilities, no API breaks for you, same license and your JDK. */
public final class Safe extends Command {
    @Override public String name() { return "safe"; }
    @Override public String title() { return "Safe Version Finder"; }
    @Override public String group() { return "Upgrade intelligence"; }
    @Override public String summary() { return "Newest version with no known vulnerabilities, no API breaks for you, same license and your JDK"; }

    @Override
    public Set<String> flags() { return Set.of("pre", "only-vulnerable", "same-major"); }

    @Override
    public String help() {
        return String.join("\n",
                "Usage: sm-maven safe [group:artifact[:version]...] [options]",
                "",
                summary() + ".",
                "",
                "For every vulnerable dependency (any depth) and every outdated direct dependency, or for the",
                "artifacts you name, walks the newer releases from the newest down and picks the first one that:",
                "  - has no known vulnerability (OSV)",
                "  - has no binary/source API break that hits the project's compiled classes",
                "  - runs on your Java release (class-file version)",
                "  - keeps the same license, or a license your --allow policy accepts",
                "Rejected versions are listed with the reason, and the exact pom.xml snippet to pin the safe",
                "version is printed (the version element for direct dependencies, dependencyManagement for",
                "transitive ones). The pins are then re-resolved to confirm the result.",
                "Without a project, g:a:v is checked on its own (no API check). Exit 1 when a dependency is",
                "vulnerable now (a pin is needed) or no safe version exists.",
                "",
                "Options:",
                "  <g:a[:v]>              Only these artifacts (version = the one to start from)",
                "  --release <N>          Java release you run on (default: the project's maven.compiler.release,",
                "                         else the running JDK)",
                "  --allow <spdx,...>     Licenses a new version may switch to (ids, prefixes like LGPL-*, or",
                "                         categories: permissive, weak-copyleft...)",
                "  --deny <spdx,...>      Licenses a new version must not switch to",
                "  --min-age <days>       Skip releases younger than this (supply-chain cool-down, default 0)",
                "  --same-major           Stay on the current major version",
                "  --only-vulnerable      Only look at vulnerable dependencies (not merely outdated ones)",
                "  --pre                  Consider pre-releases",
                "  --no-test              Leave test-scoped dependencies out",
                "",
                "Examples:",
                "  sm-maven safe",
                "  sm-maven safe org.apache.logging.log4j:log4j-core --release 8",
                "  sm-maven safe org.example:widgets --allow BUSL-1.1",
                "  sm-maven safe com.google.guava:guava:31.1-jre --json");
    }

    /** One dependency being evaluated. */
    static final class Item {
        final String groupId, artifactId, current;
        DepNode node;
        final Set<String> directIn = new LinkedHashSet<>();
        final Set<String> transitiveIn = new LinkedHashSet<>();
        /** Modules that get it through a sibling module that declares it (the sibling's version change covers them). */
        final Set<String> viaReactor = new LinkedHashSet<>();
        String relocatedFrom;
        List<Osv.Vuln> currentVulns = new ArrayList<>();
        List<String> currentLicenses = List.of();
        String recommended;
        String status;      // upgrade, keep, none
        final List<Object[]> rejected = new ArrayList<>();   // {version, reasons}
        long recommendedAt;

        Item(String g, String a, String v) {
            groupId = g;
            artifactId = a;
            current = v;
        }

        String ga() { return groupId + ":" + artifactId; }
    }

    @Override
    public int run(Ctx ctx, Args args) throws Exception {
        Ui ui = ctx.ui;
        boolean pre = args.flag("pre"), onlyVuln = args.flag("only-vulnerable"), sameMajor = args.flag("same-major");
        boolean includeTest = !args.flag("no-test");
        List<String> allow = args.getAll("allow"), deny = args.getAll("deny");
        int minAge = args.getInt("min-age", 0);
        if (minAge < 0) throw new UsageException("--min-age must be 0 or more days");
        List<String> specs = args.positionals();
        for (String s : specs) if (!Gav.looksLikeGav(s)) throw new UsageException("expected group:artifact[:version], got '" + s + "'");

        Project project = null;
        if (ctx.hasProject() || specs.isEmpty()) {
            project = ctx.project();
            Resolver.Options opt = new Resolver.Options();
            opt.includeTest = includeTest;
            project.resolveAll(ctx.resolver, opt, ui);
        }
        int running = UpgradeKit.parseRelease(System.getProperty("java.specification.version", "17"));
        int release = UpgradeKit.release(ctx, args, project, running);
        int maxMajor = UpgradeKit.majorFor(release);
        Set<String> reactor = ctx.models.reactorGavs();

        // ---------------------------------------------------------------- what to look at
        Map<String, Item> items = new LinkedHashMap<>();
        List<DepNode> nodes = new ArrayList<>();
        if (project != null) {
            for (DepNode n : project.allResolved(null)) if (includeTest || !"test".equals(n.scope)) nodes.add(n);
        }
        if (!specs.isEmpty()) {
            for (String s : specs) {
                Gav g;
                try {
                    g = Gav.parse(s);
                } catch (IllegalArgumentException e) {
                    throw new UsageException(e.getMessage());
                }
                DepNode n = null;
                for (DepNode x : nodes) if (x.ga().equals(g.ga())) { n = x; break; }
                String v = g.version != null && !g.version.equalsIgnoreCase("latest") ? g.version : n != null ? n.version : null;
                if (v == null) {
                    if (project != null) throw new UsageException(g.ga() + " is not a dependency of " + project.rootModule().gav().ga() + "; give a version (" + g.ga() + ":<version>)");
                    throw new UsageException("give the version you use now: " + g.ga() + ":<version>");
                }
                if (ctx.versions(g.groupId, g.artifactId, false).isEmpty()) throw new UsageException(g.ga() + " was not found on " + ctx.repos.remotes().get(0).url);
                Item it = new Item(g.groupId, g.artifactId, v);
                it.node = n != null && n.version.equals(v) ? n : null;
                items.put(it.ga(), it);
            }
        } else {
            List<Gav> gavs = new ArrayList<>();
            for (DepNode n : nodes) gavs.add(n.gav());
            Map<String, List<Osv.Vuln>> vulns = ctx.vulnerabilities(gavs);
            for (DepNode n : nodes) {
                boolean vulnerable = !vulns.getOrDefault(n.gav().toString(), List.of()).isEmpty();
                boolean candidate = vulnerable;
                if (!vulnerable && !onlyVuln && n.isDirect() && n.range == null && !reactor.contains(n.gav().toString())) {
                    List<String> vs = ctx.versions(n.groupId, n.artifactId, !pre);
                    candidate = !vs.isEmpty() && MavenVersion.compare(vs.get(vs.size() - 1), n.version) > 0;
                }
                if (!candidate || items.containsKey(n.ga())) continue;
                Item it = new Item(n.groupId, n.artifactId, n.version);
                it.node = n;
                items.put(it.ga(), it);
            }
        }
        if (project != null) {
            for (Item it : items.values()) {
                for (Project.Module m : project.codeModules()) {
                    if (m.graph() == null) continue;
                    DepNode n = m.graph().selected(it.groupId, it.artifactId);
                    if (n == null) continue;
                    boolean declared = false;
                    for (Dependency d : m.model.pom.dependencies) if (d.ga().equals(it.ga())) declared = true;
                    if (n.relocatedFrom != null && n.isDirect()) {
                        it.relocatedFrom = n.relocatedFrom;
                        declared = true;
                    }
                    (declared ? it.directIn : it.transitiveIn).add(m.relPath);
                    if (!declared) {
                        // Arrives through a sibling module: editing that module's version is enough.
                        Project.Module via = project.module(n.path().get(0).ga());
                        if (via != null && reactor.contains(n.path().get(0).gav().toString())) {
                            for (Dependency d : via.model.pom.dependencies) if (d.ga().equals(it.ga())) it.viaReactor.add(m.relPath);
                        }
                    }
                }
            }
        }

        // ---------------------------------------------------------------- evaluate candidate versions
        Map<String, List<String>> newer = new LinkedHashMap<>();
        List<Gav> toCheck = new ArrayList<>();
        for (Item it : items.values()) {
            List<String> vs = new ArrayList<>();
            MavenVersion cur = MavenVersion.of(it.current);
            for (String v : ctx.versions(it.groupId, it.artifactId, !pre)) {
                MavenVersion mv = MavenVersion.of(v);
                if (mv.compareTo(cur) <= 0) continue;
                if (sameMajor && mv.major() != cur.major()) continue;
                vs.add(0, v);    // newest first
            }
            newer.put(it.ga(), vs);
            toCheck.add(new Gav(it.groupId, it.artifactId, it.current));
            for (String v : vs) toCheck.add(new Gav(it.groupId, it.artifactId, v));
        }
        Map<String, List<Osv.Vuln>> vulns = toCheck.isEmpty() ? Map.of() : ctx.vulnerabilities(toCheck);
        List<Jar> classes = project == null ? List.of() : UpgradeKit.projectClasses(project);
        ApiDiff.Usage usage = ApiDiff.Usage.of(classes);
        long now = System.currentTimeMillis();
        for (Item it : items.values()) {
            Gav cur = new Gav(it.groupId, it.artifactId, it.current);
            it.currentVulns = vulns.getOrDefault(cur.toString(), List.of());
            it.currentLicenses = UpgradeKit.licenses(ctx, cur);
            ui.progress("Evaluating " + it.ga() + "...");
            for (String v : newer.get(it.ga())) {
                Gav g = new Gav(it.groupId, it.artifactId, v);
                List<String> reasons = new ArrayList<>();
                List<Osv.Vuln> vv = vulns.getOrDefault(g.toString(), List.of());
                if (!vv.isEmpty()) {
                    List<String> ids = new ArrayList<>();
                    for (Osv.Vuln x : vv) ids.add(x.displayId() + " " + (x.severity == null ? "unknown" : x.severity));
                    reasons.add(Ui.plural(vv.size(), "known vulnerability", "known vulnerabilities") + ": " + String.join(", ", ids));
                }
                int major = UpgradeKit.jarMajor(ctx, g);
                if (major > maxMajor) reasons.add("needs Java " + UpgradeKit.javaOf(major) + " (class file " + major + "), you run Java " + release);
                List<String> lic = UpgradeKit.licenses(ctx, g);
                if (!lic.equals(it.currentLicenses) && !licenseAccepted(lic, allow, deny)) {
                    reasons.add("license changes " + UpgradeKit.licenseText(it.currentLicenses) + " -> " + UpgradeKit.licenseText(lic)
                            + " (" + Licenses.bestOf(lic).label + ")" + (allow.isEmpty() ? "; accept it with --allow" : ""));
                }
                if (!usage.members.isEmpty() || !usage.types.isEmpty()) {
                    List<ApiDiff.Impact> imp = UpgradeKit.impacts(ctx, cur, g, usage);
                    if (imp != null && !imp.isEmpty()) {
                        List<String> what = new ArrayList<>();
                        for (ApiDiff.Impact i : imp) what.add(i.change.kind + " " + i.change.where());
                        reasons.add(Ui.plural(imp.size(), "API break") + " in your code: " + String.join("; ", what));
                    }
                }
                long released = 0;
                if (minAge > 0) {
                    released = releasedAt(ctx, g);
                    if (released > 0 && now - released < minAge * 86_400_000L) {
                        reasons.add("released " + Ui.ago(released) + " (younger than --min-age " + minAge + " days)");
                    }
                }
                if (reasons.isEmpty()) {
                    it.recommended = v;
                    it.recommendedAt = released;
                    break;
                }
                it.rejected.add(new Object[] {v, reasons});
            }
            ui.progressDone();
            if (it.recommended != null) it.status = "upgrade";
            else if (it.currentVulns.isEmpty()) it.status = "keep";
            else it.status = "none";
        }

        // ---------------------------------------------------------------- verify the pins together
        Map<String, Object> verify = null;
        if (project != null) verify = verify(ctx, project, items, includeTest);

        boolean needsAction = false;
        for (Item it : items.values()) if (!it.currentVulns.isEmpty()) needsAction = true;
        int exit = needsAction ? Exit.ISSUES : Exit.OK;

        if (ui.json) {
            List<Object> list = new ArrayList<>();
            for (Item it : items.values()) {
                List<Object> rej = new ArrayList<>();
                for (Object[] r : it.rejected) rej.add(Json.obj("version", r[0], "reasons", r[1]));
                List<Object> cv = new ArrayList<>();
                for (Osv.Vuln v : it.currentVulns) cv.add(Json.obj("id", v.id, "displayId", v.displayId(), "severity", v.severity));
                list.add(Json.obj("artifact", it.ga(), "current", it.current, "scope", it.node == null ? null : it.node.scope,
                        "direct", it.node == null ? null : it.node.isDirect(), "relocatedFrom", it.relocatedFrom,
                        "vulnerable", !it.currentVulns.isEmpty(), "currentVulnerabilities", cv, "licenses", it.currentLicenses,
                        "status", it.status, "safeVersion", it.recommended != null ? it.recommended : "keep".equals(it.status) ? it.current : null,
                        "newest", newer.get(it.ga()).isEmpty() ? it.current : newer.get(it.ga()).get(0),
                        "rejected", rej, "pin", snippet(it, project)));
            }
            ui.emitJson(Json.obj("project", project == null ? null : project.rootModule().gav().toString(), "release", release,
                    "policy", Json.obj("allow", allow, "deny", deny, "minAgeDays", minAge, "sameMajor", sameMajor),
                    "dependencies", list, "verification", verify, "actionNeeded", needsAction));
            return exit;
        }

        ui.title(title() + " " + ui.dot() + " " + (project == null ? String.join(", ", specs) : project.rootModule().gav().toString())
                + ui.dim("  (Java " + release + (allow.isEmpty() ? "" : ", allow " + String.join(",", allow)) + (deny.isEmpty() ? "" : ", deny " + String.join(",", deny)) + ")"));
        if (items.isEmpty()) {
            ui.good("Every dependency is free of known vulnerabilities and up to date.");
            return Exit.OK;
        }
        Ui.Table t = new Ui.Table("Dependency", "Current", "Status", "Safe version", "Newest", "Notes");
        for (Item it : items.values()) {
            String st = !it.currentVulns.isEmpty() ? ui.red(Ui.plural(it.currentVulns.size(), "vuln")) : ui.dim("outdated");
            String safe = it.recommended != null ? ui.green(it.recommended) : "keep".equals(it.status) ? it.current + ui.dim(" (keep)") : ui.red("none");
            String newest = newer.get(it.ga()).isEmpty() ? it.current : newer.get(it.ga()).get(0);
            String note = it.rejected.isEmpty() ? "" : Ui.plural(it.rejected.size(), "newer version") + " rejected";
            t.row(it.ga(), it.current, st, safe, newest, note);
        }
        ui.table(t);

        for (Item it : items.values()) {
            ui.section(it.ga() + " " + it.current + (it.node != null ? ui.dim("  " + it.node.scope + (it.node.isDirect() ? ", direct" : ", via " + it.node.path().get(0).ga())) : ""));
            if (!it.currentVulns.isEmpty()) {
                List<String> ids = new ArrayList<>();
                for (Osv.Vuln v : it.currentVulns) ids.add(v.displayId() + " " + ui.severity(v.severity));
                ui.fail("vulnerable now: " + String.join(", ", ids));
            }
            for (Object[] r : it.rejected) {
                @SuppressWarnings("unchecked")
                List<String> reasons = (List<String>) r[1];
                ui.line(ui.red(ui.unicode() ? "✖" : "X") + " " + r[0] + ui.dim(" rejected: ") + String.join("; ", reasons));
            }
            if (it.recommended != null) {
                ui.good(ui.bold(it.recommended) + " is the newest safe version" + (it.recommendedAt > 0 ? ui.dim(" (released " + Ui.ago(it.recommendedAt) + ")") : ""));
                String sn = snippet(it, project);
                if (sn != null) {
                    ui.println();
                    for (String l : sn.split("\n")) ui.line(ui.cyan(l));
                }
            } else if ("keep".equals(it.status)) {
                ui.good("keep " + it.current + ": no newer version passes every check, and " + it.current + " has no known vulnerability");
            } else {
                ui.fail("no safe version: every newer release is rejected" + (newer.get(it.ga()).isEmpty() ? " (there is none)" : "") + "; consider replacing " + it.ga());
            }
        }
        if (verify != null && Json.num(verify, 0, "pins") > 0) {
            ui.section("With these pins");
            long b = Json.num(verify, 0, "vulnerabilitiesBefore"), a = Json.num(verify, 0, "vulnerabilitiesAfter");
            if (a < b) ui.good("known vulnerabilities " + b + " " + ui.arrow() + " " + a + " after re-resolving every module");
            else ui.line("known vulnerabilities " + b + " " + ui.arrow() + " " + a);
            for (Object o : Json.list(verify, "remaining")) ui.warn("still vulnerable: " + Json.str(o, "artifact") + " " + Json.str(o, "id") + ui.dim("  " + Json.str(o, "reason")));
            long others = Json.num(verify, 0, "notAnalysed");
            if (others > 0) ui.note("  " + Ui.plural(others, "vulnerability", "vulnerabilities") + " in dependencies not analysed here (run 'sm-maven safe' without arguments)");
            ui.note("  Run 'sm-maven simulate' with the same versions for the full tree diff.");
        }
        return exit;
    }

    static boolean licenseAccepted(List<String> lic, List<String> allow, List<String> deny) {
        if (allow.isEmpty() && deny.isEmpty()) return false;
        if (lic.isEmpty()) return false;
        for (String id : lic) {
            boolean ok = (allow.isEmpty() || Licenses.matches(id, allow)) && !Licenses.matches(id, deny);
            if (ok) return true;   // dual licensing: one acceptable option is enough
        }
        return false;
    }

    private static long releasedAt(Ctx ctx, Gav g) {
        try {
            CentralSearch.Result r = ctx.search.version(g.groupId, g.artifactId, g.version);
            return r.docs.isEmpty() ? 0 : r.docs.get(0).timestamp;
        } catch (HttpException e) {
            ctx.ui.warnErr("release date of " + g + " unavailable: " + e.getMessage());
            return 0;
        }
    }

    /** The pom.xml change that pins the safe version. */
    static String snippet(Item it, Project project) {
        if (it.recommended == null) return null;
        String dep = UpgradeKit.dependencyXml(it.groupId, it.artifactId, it.recommended, "    ");
        if (project == null) return UpgradeKit.dependencyXml(it.groupId, it.artifactId, it.recommended, "");
        StringBuilder b = new StringBuilder();
        if (it.relocatedFrom != null) {
            b.append("<!-- ").append(it.relocatedFrom).append(" is relocated: replace it in ").append(files(it.directIn)).append(" with -->\n");
            b.append(UpgradeKit.dependencyXml(it.groupId, it.artifactId, it.recommended, ""));
            return b.toString();
        }
        if (!it.directIn.isEmpty()) {
            b.append("<!-- ").append(files(it.directIn)).append(" -->\n");
            b.append(UpgradeKit.dependencyXml(it.groupId, it.artifactId, it.recommended, ""));
        }
        Set<String> managed = new LinkedHashSet<>(it.transitiveIn);
        managed.removeAll(it.viaReactor);
        if (!managed.isEmpty()) {
            if (b.length() > 0) b.append('\n');
            b.append("<!-- pom.xml (root) dependencyManagement: pins the transitive version for ").append(files(managed)).append(" -->\n");
            b.append("<dependencyManagement>\n  <dependencies>\n").append(dep).append("\n  </dependencies>\n</dependencyManagement>");
        }
        if (b.length() == 0) b.append(UpgradeKit.dependencyXml(it.groupId, it.artifactId, it.recommended, ""));
        return b.toString();
    }

    private static String files(Set<String> rels) {
        List<String> out = new ArrayList<>();
        for (String r : rels) out.add(r.equals(".") ? "pom.xml" : r + "/pom.xml");
        return String.join(", ", out);
    }

    /** Re-resolves every module with all recommended versions and compares known vulnerabilities. */
    private static Map<String, Object> verify(Ctx ctx, Project project, Map<String, Item> items, boolean includeTest) throws Exception {
        int pins = 0;
        Set<String> reactor = ctx.models.reactorGavs();
        Map<String, DepNode> before = new LinkedHashMap<>(), after = new LinkedHashMap<>();
        for (Project.Module m : project.codeModules()) {
            if (m.graph() == null) continue;
            Resolver.Options o = new Resolver.Options();
            o.includeTest = includeTest;
            for (Item it : items.values()) {
                if (it.recommended == null || it.relocatedFrom != null) continue;
                if (it.directIn.contains(m.relPath)) o.directOverrides.put(it.ga(), it.recommended);
                else if (it.transitiveIn.contains(m.relPath)) o.pins.put(it.ga(), it.recommended);
            }
            for (DepNode n : m.graph().resolved()) if (!reactor.contains(n.gav().toString())) before.putIfAbsent(n.gav().toString(), n);
            if (o.directOverrides.isEmpty() && o.pins.isEmpty()) {
                for (DepNode n : m.graph().resolved()) if (!reactor.contains(n.gav().toString())) after.putIfAbsent(n.gav().toString(), n);
                continue;
            }
            pins += o.directOverrides.size() + o.pins.size();
            ctx.ui.progress("Re-resolving " + m.model.pom.artifactId + " with the safe versions...");
            Graph g = ctx.resolver.resolve(m.model, o);
            ctx.ui.progressDone();
            for (DepNode n : g.resolved()) if (!reactor.contains(n.gav().toString())) after.putIfAbsent(n.gav().toString(), n);
        }
        if (!includeTest) {
            before.values().removeIf(n -> "test".equals(n.scope));
            after.values().removeIf(n -> "test".equals(n.scope));
        }
        Set<Gav> all = new LinkedHashSet<>();
        for (DepNode n : before.values()) all.add(n.gav());
        for (DepNode n : after.values()) all.add(n.gav());
        Map<String, List<Osv.Vuln>> vulns = all.isEmpty() ? Map.of() : ctx.vulnerabilities(all);
        int b = 0, a = 0;
        for (DepNode n : before.values()) b += vulns.getOrDefault(n.gav().toString(), List.of()).size();
        List<Object> remaining = new ArrayList<>();
        int others = 0;
        for (DepNode n : after.values()) {
            List<Osv.Vuln> vs = vulns.getOrDefault(n.gav().toString(), List.of());
            a += vs.size();
            Item it = items.get(n.ga());
            if (it == null) {
                others += vs.size();
                continue;
            }
            for (Osv.Vuln v : vs) {
                String reason = it.recommended == null ? "no safe version" : it.relocatedFrom != null ? "relocated: replace the dependency" : "pin not applied";
                remaining.add(Json.obj("artifact", n.gav().toString(), "id", v.displayId(), "severity", v.severity, "reason", reason));
            }
        }
        return Json.obj("pins", pins, "vulnerabilitiesBefore", b, "vulnerabilitiesAfter", a, "remaining", remaining, "notAnalysed", others);
    }
}
