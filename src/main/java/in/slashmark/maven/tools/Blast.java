package in.slashmark.maven.tools;

import in.slashmark.maven.bytecode.Jar;
import in.slashmark.maven.cli.Args;
import in.slashmark.maven.cli.Command;
import in.slashmark.maven.cli.Ctx;
import in.slashmark.maven.cli.Exit;
import in.slashmark.maven.cli.Project;
import in.slashmark.maven.cli.Ui;
import in.slashmark.maven.cli.UsageException;
import in.slashmark.maven.data.DepsDev;
import in.slashmark.maven.data.Osv;
import in.slashmark.maven.model.Gav;
import in.slashmark.maven.model.MavenVersion;
import in.slashmark.maven.repo.Metadata;
import in.slashmark.maven.resolve.DepNode;
import in.slashmark.maven.resolve.Resolver;
import in.slashmark.maven.util.Json;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Blast Radius Analyzer: Who depends on an artifact: Central-wide dependents plus every path in your project. */
public final class Blast extends Command {
    @Override public String name() { return "blast"; }
    @Override public String title() { return "Blast Radius Analyzer"; }
    @Override public String group() { return "Live dependency analysis"; }
    @Override public String summary() { return "Who depends on an artifact: Central-wide dependents plus every path in your project"; }

    @Override
    public Set<String> flags() { return Set.of("deep", "fail", "no-vulns", "all-versions"); }

    @Override
    public String help() {
        return String.join("\n",
                "Usage: sm-maven blast <group:artifact[:version]> [options]",
                "",
                summary() + ".",
                "For maintainers: how many packages on Maven Central depend on each version (deps.dev, direct and",
                "indirect), and how many of those sit on vulnerable versions. For incident triage: every module and",
                "every dependency path in your project that pulls the artifact in, whether that version is selected",
                "or omitted, and which direct dependencies you would have to change. Globs (org.apache.logging.log4j:*)",
                "search the project only.",
                "",
                "Options:",
                "  --deep                 Also scan the resolved JARs for shaded/embedded copies of the artifact",
                "  --all-versions         Query dependents for every published version (default: newest 12 + yours)",
                "  --no-vulns             Skip the OSV vulnerability lookup",
                "  --fail                 Exit 1 when the project uses the artifact (CI incident checks)",
                "  --no-test              Ignore test-scoped dependencies",
                "",
                "Examples:",
                "  sm-maven blast org.apache.logging.log4j:log4j-core",
                "  sm-maven blast org.apache.logging.log4j:log4j-core:2.14.1 --deep --fail",
                "  sm-maven blast 'org.apache.logging.log4j:*'",
                "  sm-maven blast com.acme:acme-core --json");
    }

    /** One occurrence of the artifact in a module's graph. */
    private static final class Hit {
        final DepSupport.Unit unit;
        final DepNode n;

        Hit(DepSupport.Unit unit, DepNode n) {
            this.unit = unit;
            this.n = n;
        }
    }

    @Override
    public int run(Ctx ctx, Args args) throws Exception {
        String spec = args.pos(0);
        if (spec == null) throw new UsageException("give the artifact to analyse, e.g. sm-maven blast org.apache.logging.log4j:log4j-core");
        boolean deep = args.flag("deep");
        boolean failIfUsed = args.flag("fail");
        boolean noVulns = args.flag("no-vulns");
        boolean allVersions = args.flag("all-versions");
        boolean noTest = args.flag("no-test");
        boolean glob = spec.contains("*");
        String[] parts = spec.split(":");
        if (parts.length < 2 || parts[0].isEmpty() || parts[1].isEmpty()) throw new UsageException("expected groupId:artifactId[:version], got '" + spec + "'");
        Gav gav = null;
        if (!glob) {
            try {
                gav = Gav.parse(spec);
            } catch (IllegalArgumentException e) {
                throw new UsageException(e.getMessage());
            }
        }
        String requestedVersion = gav == null ? (parts.length > 2 ? parts[parts.length - 1] : null) : gav.version;
        DepSupport.Matcher matcher = new DepSupport.Matcher(List.of(parts[0] + ":" + parts[1]));

        // ---- inside the project
        List<DepSupport.Unit> units = new ArrayList<>();
        List<Hit> hits = new ArrayList<>();
        String projectLabel = null;
        if (ctx.hasProject()) {
            Project p = ctx.project();
            Resolver.Options opt = new Resolver.Options();
            opt.includeTest = !noTest;
            p.resolveAll(ctx.resolver, opt, ctx.ui);
            projectLabel = p.rootModule().gav().toString();
            for (Project.Module m : p.codeModules()) if (m.graph() != null) units.add(new DepSupport.Unit(m.gav().toString(), m.relPath, m.graph(), m));
            for (DepSupport.Unit u : units) {
                for (DepNode n : u.graph.find(x -> matcher.matches(x))) {
                    if (!n.selected && ("unreachable".equals(n.omitted) || DepSupport.rangeSibling(n))) continue;
                    if (requestedVersion != null && !requestedVersion.equals(n.version)) {
                        // keep other versions of the artifact visible: they tell whether the project is affected at all
                        if (!n.selected) continue;
                    }
                    hits.add(new Hit(u, n));
                }
            }
        }

        // ---- on Central
        Metadata md = null;
        List<String> versions = new ArrayList<>();
        if (!glob) {
            md = ctx.repos.metadata(gav.groupId, gav.artifactId);
            if (md == null && hits.isEmpty()) throw new UsageException(gav.ga() + " was not found on " + ctx.repos.remotes().get(0).url);
            if (md != null) {
                for (String v : md.sortedVersions()) if (!MavenVersion.of(v).isSnapshot()) versions.add(v);
                if (requestedVersion != null && !versions.contains(requestedVersion) && hits.isEmpty()) {
                    throw new UsageException(gav + " does not exist (latest: " + (versions.isEmpty() ? "none" : versions.get(versions.size() - 1)) + ")");
                }
            }
        }
        Set<String> projectVersions = new LinkedHashSet<>();
        for (Hit h : hits) if (h.n.selected && h.n.ga().equals(gav == null ? "" : gav.ga())) projectVersions.add(h.n.version);
        List<String> query = new ArrayList<>();
        if (!glob) {
            if (allVersions) query.addAll(versions);
            else {
                query.addAll(versions.subList(Math.max(0, versions.size() - 12), versions.size()));
                for (String v : projectVersions) if (!query.contains(v) && versions.contains(v)) query.add(v);
                if (requestedVersion != null && versions.contains(requestedVersion) && !query.contains(requestedVersion)) query.add(requestedVersion);
                query.sort(MavenVersion::compare);
            }
        }
        final String ga = gav == null ? null : gav.ga();
        List<DepsDev.Dependents> deps = query.isEmpty() ? List.of()
                : ctx.http.parallelOrNull(query, v -> ctx.depsDev.dependents(ga, v));
        Map<String, List<Osv.Vuln>> vmap = new LinkedHashMap<>();
        if (!noVulns && !query.isEmpty()) {
            List<Gav> gl = new ArrayList<>();
            for (String v : query) gl.add(new Gav(gav.groupId, gav.artifactId, v));
            vmap = ctx.vulnerabilities(gl);
        }
        Map<String, Long> published = new LinkedHashMap<>();
        if (!query.isEmpty()) {
            List<DepsDev.VersionInfo> vis = ctx.depsDev.versions(ga);
            if (vis != null) for (DepsDev.VersionInfo vi : vis) published.put(vi.version, vi.publishedAt);
        }
        long total = 0, direct = 0, vulnerableDependents = 0;
        boolean known = false;
        List<Object> versionRows = new ArrayList<>();
        for (int i = 0; i < query.size(); i++) {
            String v = query.get(i);
            DepsDev.Dependents d = deps.get(i);
            List<Osv.Vuln> vs = vmap.getOrDefault(new Gav(gav.groupId, gav.artifactId, v).toString(), List.of());
            if (d != null) {
                known = true;
                total += d.total;
                direct += d.direct;
                if (!vs.isEmpty()) vulnerableDependents += d.total;
            }
            List<String> ids = new ArrayList<>();
            for (Osv.Vuln x : vs) ids.add(DepSupport.vulnId(x));
            versionRows.add(Json.obj("version", v, "publishedAt", published.containsKey(v) && published.get(v) > 0 ? java.time.Instant.ofEpochMilli(published.get(v)).toString() : null,
                    "directDependents", d == null ? null : d.direct, "indirectDependents", d == null ? null : d.indirect,
                    "totalDependents", d == null ? null : d.total, "vulnerabilities", noVulns ? null : ids,
                    "severity", vs.isEmpty() ? null : vs.get(0).severity, "usedByProject", projectVersions.contains(v) ? Boolean.TRUE : null,
                    "requested", v.equals(requestedVersion) ? Boolean.TRUE : null));
        }

        // ---- shaded / embedded copies
        List<Object> embedded = new ArrayList<>();
        List<String[]> embeddedRows = new ArrayList<>();
        if (deep && !units.isEmpty()) {
            Map<String, DepNode> nodes = new LinkedHashMap<>();
            for (DepSupport.Unit u : units) for (DepNode n : u.graph.resolved()) if (!ctx.models.inReactor(n.gav())) nodes.putIfAbsent(n.gav().toString(), n);
            List<DepNode> list = new ArrayList<>(nodes.values());
            ctx.ui.progress("Scanning " + list.size() + " JARs for embedded copies...");
            List<Jar> jars = ctx.http.parallelOrNull(list, n -> ctx.jar(n.gav()));
            ctx.ui.progressDone();
            for (int i = 0; i < list.size(); i++) {
                Jar j = jars.get(i);
                if (j == null) continue;
                DepNode host = list.get(i);
                for (String e : j.embeddedMavenArtifacts()) {
                    String ega = DepSupport.gaOf(e);
                    if (ega.equals(host.ga()) || !matcher.matches(ega)) continue;
                    String ev = e.split(":").length > 2 ? e.split(":")[2] : null;
                    if (requestedVersion != null && ev != null && !requestedVersion.equals(ev)) continue;
                    embedded.add(Json.obj("host", host.gav().toString(), "embeds", e, "scope", host.scope, "path", host.pathString()));
                    embeddedRows.add(new String[] {host.gav().toString(), e, host.pathString()});
                }
            }
        }

        boolean used = false;
        for (Hit h : hits) if (h.n.selected && (requestedVersion == null || requestedVersion.equals(h.n.version))) used = true;
        if (!embedded.isEmpty()) used = true;
        int exit = failIfUsed && used ? Exit.ISSUES : Exit.OK;

        // modules summary
        Map<DepSupport.Unit, List<Hit>> byUnit = new LinkedHashMap<>();
        for (DepSupport.Unit u : units) byUnit.put(u, new ArrayList<>());
        for (Hit h : hits) byUnit.get(h.unit).add(h);
        Set<String> entryPoints = new LinkedHashSet<>();
        for (Hit h : hits) if (h.n.selected && !h.n.isDirect()) entryPoints.add(h.n.path().get(0).gav().toString());

        if (ctx.ui.json) {
            List<Object> mods = new ArrayList<>();
            int modulesUsing = 0;
            for (Map.Entry<DepSupport.Unit, List<Hit>> e : byUnit.entrySet()) {
                List<Object> occ = new ArrayList<>();
                List<String> selected = new ArrayList<>();
                for (Hit h : e.getValue()) {
                    DepNode n = h.n;
                    if (n.selected && !selected.contains(n.gav().toString())) selected.add(n.gav().toString());
                    occ.add(Json.obj("artifact", n.ga(), "version", n.version, "selected", n.selected, "omitted", n.omitted,
                            "winnerVersion", n.winner == null ? null : n.winner.version, "scope", n.selected ? n.scope : n.declaredScope,
                            "depth", n.depth, "direct", n.isDirect(), "via", n.path().get(0).gav().toString(), "path", n.pathString(),
                            "relocatedFrom", n.relocatedFrom, "managedFrom", n.premanagedVersion));
                }
                if (!selected.isEmpty()) modulesUsing++;
                mods.add(Json.obj("module", e.getKey().label, "path", e.getKey().relPath, "uses", !selected.isEmpty(), "selected", selected, "occurrences", occ));
            }
            Map<String, Object> project = units.isEmpty() ? null : Json.obj("target", projectLabel, "modulesUsing", modulesUsing, "modules", mods,
                    "entryPoints", new ArrayList<>(entryPoints), "embedded", deep ? embedded : null);
            Map<String, Object> central = glob ? null : Json.obj("known", known, "versions", versionRows, "totalDependents", total,
                    "directDependents", direct, "vulnerableDependents", noVulns ? null : vulnerableDependents,
                    "latest", versions.isEmpty() ? null : versions.get(versions.size() - 1));
            ctx.ui.emitJson(Json.obj("tool", "blast", "artifact", glob ? parts[0] + ":" + parts[1] : ga, "version", requestedVersion,
                    "usedByProject", units.isEmpty() ? null : used, "central", central, "project", project));
            return exit;
        }

        Ui ui = ctx.ui;
        String subject = (glob ? parts[0] + ":" + parts[1] : ga) + (requestedVersion != null ? ":" + requestedVersion : "");
        ui.title(ui.bold("Blast radius") + " " + ui.dim(ui.dot()) + " " + subject);
        if (!glob) {
            ui.section("On Maven Central (deps.dev dependents)");
            if (!known) ui.note("  deps.dev has no dependents data for " + ga);
            else {
                Ui.Table tb = new Ui.Table("Version", "Released", "Direct", "Indirect", "Total", "Vulnerabilities", "").rightAlign(2, 3, 4);
                for (int i = 0; i < query.size(); i++) {
                    String v = query.get(i);
                    DepsDev.Dependents d = deps.get(i);
                    List<Osv.Vuln> vs = vmap.getOrDefault(new Gav(gav.groupId, gav.artifactId, v).toString(), List.of());
                    String vul = noVulns ? "" : vs.isEmpty() ? ui.dim("none known") : ui.severity(vs.get(0).severity) + " " + vs.size();
                    String mark = (projectVersions.contains(v) ? ui.cyan("used by project") : "") + (v.equals(requestedVersion) && !projectVersions.contains(v) ? ui.bold("requested") : "");
                    Long pub = published.get(v);
                    tb.row(v.equals(requestedVersion) ? ui.bold(v) : v, pub == null ? "" : Ui.date(pub), d == null ? "?" : fmt(d.direct),
                            d == null ? "?" : fmt(d.indirect), d == null ? "?" : fmt(d.total), vul, mark);
                }
                ui.table(tb);
                ui.println();
                ui.line(ui.bold(fmt(total)) + " packages depend on the versions shown (" + fmt(direct) + " directly)"
                        + (noVulns || vulnerableDependents == 0 ? "" : ", " + ui.red(fmt(vulnerableDependents) + " of them on a vulnerable version")));
                if (versions.size() > query.size()) ui.note("  " + (versions.size() - query.size()) + " older versions not shown (--all-versions)");
            }
        }
        if (units.isEmpty()) {
            ui.println();
            ui.note("No project here: run inside a Maven project (or -f path/to/pom.xml) to see the paths that pull it in.");
            return exit;
        }
        ui.section("In your project · " + projectLabel);
        int usingCount = 0;
        for (Map.Entry<DepSupport.Unit, List<Hit>> e : byUnit.entrySet()) {
            DepSupport.Unit u = e.getKey();
            List<Hit> l = e.getValue();
            List<String> sel = new ArrayList<>();
            for (Hit h : l) if (h.n.selected) sel.add(h.n.gav().toString() + " [" + h.n.scope + "]");
            String name = u.label + (u.relPath != null && !".".equals(u.relPath) ? ui.dim(" (" + u.relPath + ")") : "");
            if (l.isEmpty()) {
                ui.good(name + ": not used");
                continue;
            }
            if (!sel.isEmpty()) usingCount++;
            if (sel.isEmpty()) ui.good(name + ": only omitted requests (another version wins)");
            else ui.warn(name + ": uses " + String.join(", ", new LinkedHashSet<>(sel)));
            for (Hit h : l) {
                DepNode n = h.n;
                String status = n.selected ? (n.isDirect() ? ui.yellow("direct") : ui.yellow("transitive")) : ui.dim("omitted (" + n.omitted + (n.winner != null ? " with " + n.winner.version : "") + ")");
                ui.line("  " + status + "  " + n.pathString() + (n.relocatedFrom != null ? ui.dim(" (relocated from " + n.relocatedFrom + ")") : ""));
            }
        }
        if (!embeddedRows.isEmpty()) {
            ui.section("Embedded copies (shaded inside other JARs)");
            for (String[] r : embeddedRows) ui.warn(r[0] + " bundles " + ui.bold(r[1]) + ui.dim("  via " + r[2]));
        } else if (deep) {
            ui.println();
            ui.good("No embedded copies found in " + ui.dim("the resolved JARs"));
        }
        ui.println();
        if (!used) ui.good("The project does not use " + subject);
        else if (usingCount == 0) {
            ui.fail("No module resolves " + subject + " directly, but " + Ui.plural(embeddedRows.size(), "JAR") + " on the classpath bundle" + (embeddedRows.size() == 1 ? "s" : "") + " a copy");
        } else {
            ui.fail(Ui.plural(usingCount, "module") + " of " + units.size() + (usingCount == 1 ? " uses " : " use ") + subject
                    + (entryPoints.isEmpty() ? "" : "; pulled in transitively by " + String.join(", ", entryPoints)));
            if (!entryPoints.isEmpty()) ui.note("  To remove or replace it, upgrade those dependencies, add an <exclusion>, or pin a fixed version in <dependencyManagement>.");
        }
        return exit;
    }

    private static String fmt(long n) { return String.format(java.util.Locale.ROOT, "%,d", n); }
}
