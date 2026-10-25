package in.slashmark.maven.tools;

import in.slashmark.maven.bytecode.Jar;
import in.slashmark.maven.cli.Args;
import in.slashmark.maven.cli.Command;
import in.slashmark.maven.cli.Ctx;
import in.slashmark.maven.cli.Exit;
import in.slashmark.maven.cli.Project;
import in.slashmark.maven.cli.Ui;
import in.slashmark.maven.cli.UsageException;
import in.slashmark.maven.data.Epss;
import in.slashmark.maven.data.Kev;
import in.slashmark.maven.data.Osv;
import in.slashmark.maven.model.Dependency;
import in.slashmark.maven.model.Gav;
import in.slashmark.maven.model.MavenVersion;
import in.slashmark.maven.model.ModelBuilder;
import in.slashmark.maven.model.Pom;
import in.slashmark.maven.resolve.DepNode;
import in.slashmark.maven.resolve.Graph;
import in.slashmark.maven.resolve.Resolver;
import in.slashmark.maven.util.HttpException;
import in.slashmark.maven.util.Json;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Zero-Day Impact Scanner: Given a CVE, show every affected path in every module and the minimal fix. */
public final class Impact extends Command {
    @Override public String name() { return "impact"; }
    @Override public String title() { return "Zero-Day Impact Scanner"; }
    @Override public String group() { return "Live threat intelligence"; }
    @Override public String summary() { return "Given a CVE, show every affected path in every module and the minimal fix"; }

    @Override
    public String help() {
        return String.join("\n",
                "Usage: sm-maven impact <CVE-or-GHSA-id> [group:artifact[:version]] [options]",
                "",
                summary() + ".",
                "",
                "Fetches the advisory live from OSV and finds every module where an affected version is resolved:",
                "the full dependency path(s), scope, direct or transitive, and copies shaded into other JARs",
                "(detected from embedded META-INF/maven pom.properties). For each occurrence it proposes the",
                "smallest change - bump the declared version or property, or pin the version in",
                "<dependencyManagement> - using the first published release that is not affected, and verifies",
                "it by re-resolving the module. Exit code 1 when the project is affected, 0 when it is not.",
                "",
                "Options:",
                "  --no-shaded            Do not inspect JARs for shaded/bundled copies",
                "  --no-verify            Do not re-resolve modules to verify the proposed changes",
                "",
                "Examples:",
                "  sm-maven impact CVE-2021-44228",
                "  sm-maven impact GHSA-36p3-wjmg-h94x -f services/pom.xml --json",
                "  sm-maven impact CVE-2022-22965 com.example:my-service:1.4.0");
    }

    @Override public Set<String> flags() { return Set.of("no-shaded", "no-verify"); }

    /** One affected (or safe) occurrence of an advisory's package in a module. */
    static final class Occurrence {
        String module;
        DepNode node;          // the dependency (or the host JAR for shaded copies)
        Gav gav;               // the affected coordinates (embedded ones for shaded copies)
        boolean shaded;
        String fixedIn, recommended;
        Map<String, Object> change;
        List<Object> paths = new ArrayList<>();
    }

    @Override
    public int run(Ctx ctx, Args args) throws Exception {
        String raw = args.pos(0);
        if (raw == null) throw new UsageException("give an advisory id, e.g. sm-maven impact CVE-2021-44228");
        String id = normalizeId(raw);
        boolean shadedScan = !args.flag("no-shaded");
        boolean verify = !args.flag("no-verify");
        if (args.posFrom(2).size() > 0) throw new UsageException("unexpected argument '" + args.pos(2) + "'");

        ctx.osv.setTtl(0);
        ctx.ui.progress("Fetching " + id + " from OSV...");
        Osv.Vuln v = ctx.osv.lookup(id);
        ctx.ui.progressDone();
        if (v == null) throw new UsageException(id + " was not found on OSV (check the id; CVE, GHSA and other OSV ids work)");
        if (v.withdrawn) ctx.ui.warnErr(v.id + " has been withdrawn by its publisher");

        Kev.Entry kev = null;
        Epss.Score epss = null;
        try {
            Map<String, Kev.Entry> cat = ctx.kev.catalog();
            for (String c : v.cves()) if (kev == null) kev = cat.get(c);
        } catch (HttpException e) {
            ctx.ui.warnErr("CISA KEV unavailable: " + e.getMessage());
        }
        try {
            for (Epss.Score s : ctx.epss.scores(v.cves()).values()) if (epss == null || s.epss > epss.epss) epss = s;
        } catch (HttpException e) {
            ctx.ui.warnErr("EPSS unavailable: " + e.getMessage());
        }

        Ctx.Target target = ctx.target(args, 1);
        Project project = target.project;
        List<String> moduleNames = new ArrayList<>();
        List<Graph> graphs = new ArrayList<>();
        List<Project.Module> mods = new ArrayList<>();
        if (project != null) {
            for (Project.Module m : project.codeModules()) {
                if (m.graph() == null) continue;
                mods.add(m);
                graphs.add(m.graph());
                moduleNames.add(m.model.pom.artifactId);
            }
        } else {
            mods.add(null);
            graphs.add(target.graphs.get(0));
            moduleNames.add(target.label);
        }

        List<Occurrence> affected = new ArrayList<>();
        Map<String, List<Object>> safe = new LinkedHashMap<>();
        for (int i = 0; i < graphs.size(); i++) {
            Graph g = graphs.get(i);
            String mod = moduleNames.get(i);
            List<Object> notAffected = new ArrayList<>();
            List<DepNode> resolved = g.resolved();
            for (DepNode n : resolved) {
                if (ctx.models.inReactor(n.gav()) || !v.affected.containsKey(n.ga())) continue;
                if (!v.affects(n.ga(), n.version)) {
                    notAffected.add(Json.obj("artifact", n.gav().toString(), "scope", n.scope));
                    continue;
                }
                Occurrence o = new Occurrence();
                o.module = mod;
                o.node = n;
                o.gav = n.gav();
                for (DepNode x : g.find(x -> x.ga().equals(n.ga()))) {
                    o.paths.add(Json.obj("path", label(g) + " -> " + x.pathString(), "requested", x.version,
                            "selected", x.selected, "omitted", x.selected ? null : x.omitted));
                }
                affected.add(o);
            }
            if (shadedScan) {
                List<DepNode> hosts = new ArrayList<>();
                for (DepNode n : resolved) if (!ctx.models.inReactor(n.gav())) hosts.add(n);
                for (ThreatSupport.Shaded s : ThreatSupport.shaded(ctx, hosts)) {
                    if (!v.affected.containsKey(s.embedded.ga())) continue;
                    if (!v.affects(s.embedded.ga(), s.embedded.version)) {
                        notAffected.add(Json.obj("artifact", s.embedded.toString(), "shadedIn", s.host.gav().toString()));
                        continue;
                    }
                    Occurrence o = new Occurrence();
                    o.module = mod;
                    o.node = s.host;
                    o.gav = s.embedded;
                    o.shaded = true;
                    o.paths.add(Json.obj("path", label(g) + " -> " + s.host.pathString() + " [embeds " + s.embedded + "]", "requested", s.host.version,
                            "selected", true, "omitted", null));
                    affected.add(o);
                }
            }
            safe.put(mod, notAffected);
        }

        // Fixes and minimal changes.
        for (Occurrence o : affected) {
            o.fixedIn = v.fixFor(o.gav.ga(), o.gav.version);
            int idx = moduleNames.indexOf(o.module);
            Project.Module m = mods.get(idx);
            Graph g = graphs.get(idx);
            if (!o.shaded) {
                o.recommended = ThreatSupport.recommend(ctx, o.gav.ga(), o.gav.version, List.of(v));
                o.change = plan(ctx, args, project, m, g, o.node, o.recommended, v);
            } else {
                o.change = planShaded(ctx, args, project, m, g, o, v, verify);
            }
            if (verify && !o.shaded && o.recommended != null) verifyChange(ctx, args, g, o.node.ga(), o.recommended, o.node.depth == 1, v, o.change);
        }

        boolean isAffected = !affected.isEmpty();
        if (ctx.ui.json) {
            ctx.ui.emitJson(json(v, kev, epss, target, moduleNames, affected, safe));
        } else {
            print(ctx.ui, v, kev, epss, target, moduleNames, affected, safe, project);
        }
        return isAffected ? Exit.ISSUES : Exit.OK;
    }

    static String normalizeId(String raw) {
        String t = raw.trim();
        if (Gav.looksLikeGav(t) && t.contains(":")) throw new UsageException("the first argument is the advisory id (e.g. CVE-2021-44228); coordinates go second");
        if (!t.matches("[A-Za-z][A-Za-z0-9]*-[A-Za-z0-9._:-]+")) throw new UsageException("'" + raw + "' is not an advisory id (expected CVE-YYYY-NNNN, GHSA-xxxx-xxxx-xxxx or another OSV id)");
        String up = t.toUpperCase(Locale.ROOT);
        if (up.startsWith("CVE-")) {
            if (!up.matches("CVE-\\d{4}-\\d{4,}")) throw new UsageException("'" + raw + "' is not a valid CVE id (expected CVE-YYYY-NNNN)");
            return up;
        }
        if (up.startsWith("GHSA-")) return "GHSA-" + t.substring(5).toLowerCase(Locale.ROOT);
        return t;
    }

    private static String label(Graph g) { return g.root.gav().toString(); }

    // ---------------------------------------------------------------- planning

    /** The minimal change that moves this module off the vulnerable version. */
    private Map<String, Object> plan(Ctx ctx, Args args, Project project, Project.Module m, Graph g, DepNode n, String to, Osv.Vuln v) throws IOException {
        Map<String, Object> c = new LinkedHashMap<>();
        String ga = n.ga();
        c.put("artifact", ga);
        c.put("from", n.version);
        c.put("to", to);
        if (to == null) {
            c.put("kind", "no-fix");
            c.put("description", "No published release of " + ga + " is free of " + v.displayId()
                    + (v.fixFor(ga, n.version) != null ? " yet (fixed in " + v.fixFor(ga, n.version) + ", not published here)" : "")
                    + "; exclude it or apply the advisory's mitigation");
            return c;
        }
        // Transitive through another module of this build: the fix belongs there.
        DepNode viaModule = null;
        for (DepNode p : n.path()) {
            if (p == n) break;
            if (ctx.models.inReactor(p.gav())) viaModule = p;
        }
        if (viaModule != null && project != null) {
            Project.Module owner = project.module(viaModule.artifactId);
            DepNode inOwner = owner == null || owner.graph() == null ? null : owner.graph().selected(n.groupId, n.artifactId);
            if (owner != null && inOwner != null) {
                Map<String, Object> inner = plan(ctx, args, project, owner, owner.graph(), inOwner, to, v);
                c.putAll(inner);
                c.put("viaModule", owner.model.pom.artifactId);
                c.put("description", inner.get("description") + " (" + n.ga() + " reaches " + (m == null ? "this module" : m.model.pom.artifactId) + " through module " + owner.model.pom.artifactId + ")");
                return c;
            }
        }
        if (n.depth == 1) {
            if (m != null) {
                Decl d = declaration(project, m, n);
                if (d != null) {
                    c.put("kind", d.kind);
                    c.put("file", rel(project, d.file));
                    c.put("line", d.line > 0 ? d.line : null);
                    if (d.property != null) c.put("property", d.property);
                    if ("property".equals(d.kind)) {
                        c.put("description", "Set <" + d.property + "> to " + to + " in " + rel(project, d.file) + (d.line > 0 ? ":" + d.line : ""));
                        c.put("snippet", "<" + d.property + ">" + to + "</" + d.property + ">");
                    } else if ("managed".equals(d.kind)) {
                        c.put("description", "Change the managed version of " + ga + " to " + to + " in <dependencyManagement> of " + rel(project, d.file) + (d.line > 0 ? ":" + d.line : ""));
                        c.put("snippet", "<version>" + to + "</version>");
                    } else {
                        c.put("description", "Bump " + ga + " from " + n.version + " to " + to + " in " + rel(project, d.file) + (d.line > 0 ? ":" + d.line : ""));
                        c.put("snippet", "<version>" + to + "</version>");
                    }
                    return c;
                }
            }
            c.put("kind", "direct");
            c.put("description", "Bump the direct dependency " + ga + " from " + n.version + " to " + to);
            c.put("snippet", "<version>" + to + "</version>");
            return c;
        }
        // Transitive: pin in dependencyManagement (the parent POM covers every module of a multi-module build).
        c.put("kind", "manage");
        Path file = project == null ? null : project.multiModule() ? project.rootModule().pom : m == null ? null : m.pom;
        c.put("file", file == null ? null : rel(project, file));
        c.put("introducedBy", n.path().get(0).gav().toString());
        String[] p = ga.split(":");
        c.put("description", "Pin " + ga + " to " + to + " in <dependencyManagement>" + (file == null ? "" : " of " + rel(project, file))
                + " (it arrives transitively through " + n.path().get(0).ga() + ")");
        c.put("snippet", "<dependency><groupId>" + p[0] + "</groupId><artifactId>" + p[1] + "</artifactId><version>" + to + "</version></dependency>");
        return c;
    }

    /** A shaded copy: find a release of the host that ships a fixed copy (or none). */
    private Map<String, Object> planShaded(Ctx ctx, Args args, Project project, Project.Module m, Graph g, Occurrence o, Osv.Vuln v, boolean verify) throws IOException, HttpException {
        DepNode host = o.node;
        String hostFix = null;
        List<String> newer = new ArrayList<>();
        for (String ver : ctx.versions(host.groupId, host.artifactId, true)) if (MavenVersion.compare(ver, host.version) > 0) newer.add(ver);
        for (String ver : newer) {
            Jar j = ctx.jar(new Gav(host.groupId, host.artifactId, ver));
            if (j == null) continue;
            boolean bad = false;
            for (String e : j.embeddedMavenArtifacts()) {
                Gav eg = Gav.parse(e);
                if (eg.ga().equals(o.gav.ga()) && eg.version != null && v.affects(eg.ga(), eg.version)) bad = true;
            }
            if (!bad) {
                hostFix = ver;
                break;
            }
        }
        if (hostFix == null) {
            Map<String, Object> c = new LinkedHashMap<>();
            c.put("kind", "replace-host");
            c.put("artifact", host.ga());
            c.put("from", host.version);
            c.put("to", null);
            String fix = v.fixFor(o.gav.ga(), o.gav.version);
            c.put("description", "No release of " + host.ga() + " ships a fixed copy of " + o.gav.ga()
                    + (newer.isEmpty() ? " (" + host.version + " is the newest)" : "") + "; replace it with a non-shaded build plus "
                    + o.gav.ga() + (fix == null ? "" : " >= " + fix) + ", or ask its maintainers for a rebuild");
            return c;
        }
        Map<String, Object> c = plan(ctx, args, project, m, g, host, hostFix, v);
        c.put("kind", "upgrade-host:" + c.get("kind"));
        c.put("description", "Upgrade " + host.ga() + " to " + hostFix + " (it no longer embeds a vulnerable " + o.gav.ga() + "): " + c.get("description"));
        if (verify) {
            // Re-resolve and re-inspect the host JAR that would be selected.
            Graph after = resolveWith(ctx, args, g, host.ga(), hostFix, host.depth == 1);
            DepNode sel = after == null ? null : after.selected(host.groupId, host.artifactId);
            boolean ok = sel != null && hostFix.equals(sel.version);
            c.put("verified", ok);
            c.put("resolvedAfter", sel == null ? null : sel.version);
        }
        return c;
    }

    private static void verifyChange(Ctx ctx, Args args, Graph g, String ga, String to, boolean direct, Osv.Vuln v, Map<String, Object> change) throws HttpException {
        Graph after = resolveWith(ctx, args, g, ga, to, direct && change.get("viaModule") == null);
        String[] p = ga.split(":");
        DepNode sel = after == null ? null : after.selected(p[0], p[1]);
        change.put("verified", sel != null && !v.affects(ga, sel.version));
        change.put("resolvedAfter", sel == null ? null : sel.version);
    }

    private static Graph resolveWith(Ctx ctx, Args args, Graph g, String ga, String version, boolean direct) throws HttpException {
        Resolver.Options opt = new Resolver.Options();
        opt.includeTest = !args.flag("no-test");
        if (direct) opt.directOverrides.put(ga, version);
        else opt.pins.put(ga, version);
        ModelBuilder.Model model = g.root;
        return ctx.resolver.resolve(model, opt);
    }

    /** Where a direct dependency's version is declared in the build files. */
    static final class Decl {
        String kind;      // literal | property | managed
        Path file;
        int line;
        String property;
    }

    private static Decl declaration(Project project, Project.Module m, DepNode n) throws IOException {
        List<Path> chain = new ArrayList<>();
        List<Pom> raws = new ArrayList<>();
        Project.Module cur = m;
        while (cur != null && chain.size() < 10) {
            Pom raw = Pom.parse(Files.readAllBytes(cur.pom), cur.pom.toString());
            chain.add(cur.pom);
            raws.add(raw);
            Project.Module next = null;
            if (raw.parent != null) {
                for (Project.Module x : project.modules) {
                    if (x.model.pom.artifactId.equals(raw.parent.artifactId) && x.model.pom.groupId.equals(raw.parent.groupId) && !chain.contains(x.pom)) next = x;
                }
            }
            cur = next;
        }
        Dependency dep = null;
        Path depFile = null;
        for (Dependency d : raws.get(0).dependencies) {
            if (n.artifactId.equals(d.artifactId) && (n.groupId.equals(d.groupId) || (d.groupId != null && d.groupId.contains("${")))) {
                dep = d;
                depFile = chain.get(0);
                break;
            }
        }
        if (dep == null) return null;
        Decl decl = new Decl();
        String version = dep.version;
        decl.file = depFile;
        decl.line = dep.line;
        decl.kind = "literal";
        if (version == null) {
            // Managed: find the <dependencyManagement> entry in this module or a parent of the build.
            for (int i = 0; i < raws.size(); i++) {
                for (Dependency d : raws.get(i).dependencyManagement) {
                    if (n.artifactId.equals(d.artifactId) && (n.groupId.equals(d.groupId) || (d.groupId != null && d.groupId.contains("${")))) {
                        decl.kind = "managed";
                        decl.file = chain.get(i);
                        decl.line = d.line;
                        version = d.version;
                        break;
                    }
                }
                if ("managed".equals(decl.kind)) break;
            }
            if (version == null) return decl.kind.equals("managed") ? decl : null;
        }
        if (version.startsWith("${") && version.endsWith("}")) {
            String prop = version.substring(2, version.length() - 1);
            for (int i = 0; i < raws.size(); i++) {
                if (raws.get(i).properties.containsKey(prop)) {
                    decl.kind = "property";
                    decl.property = prop;
                    decl.file = chain.get(i);
                    decl.line = lineOf(chain.get(i), "<" + prop + ">");
                    return decl;
                }
            }
            decl.kind = "property";
            decl.property = prop;
            decl.line = 0;
        }
        return decl;
    }

    private static int lineOf(Path file, String needle) throws IOException {
        List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        for (int i = 0; i < lines.size(); i++) if (lines.get(i).contains(needle)) return i + 1;
        return 0;
    }

    private static String rel(Project project, Path file) {
        if (file == null) return null;
        if (project == null) return file.toString();
        return project.root.relativize(file).toString().replace('\\', '/');
    }

    // ---------------------------------------------------------------- output

    private static Object occurrenceJson(Occurrence o) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("module", o.module);
        m.put("artifact", o.gav.toString());
        m.put("kind", o.shaded ? "shaded" : "dependency");
        m.put("shadedIn", o.shaded ? o.node.gav().toString() : null);
        m.put("scope", o.node.scope);
        m.put("direct", o.node.depth == 1);
        m.put("optional", o.node.optional);
        m.put("depth", o.node.depth);
        m.put("path", o.node.pathString());
        m.put("paths", o.paths);
        m.put("fixedIn", o.fixedIn);
        m.put("recommended", o.recommended);
        m.put("change", o.change);
        return m;
    }

    private static Object json(Osv.Vuln v, Kev.Entry kev, Epss.Score epss, Ctx.Target target, List<String> modules,
                               List<Occurrence> affected, Map<String, List<Object>> safe) {
        List<Object> packages = new ArrayList<>();
        for (Map.Entry<String, List<Osv.Vuln.Range>> e : v.affected.entrySet()) {
            List<Object> ranges = new ArrayList<>();
            for (Osv.Vuln.Range r : e.getValue()) ranges.add(r.toString());
            packages.add(Json.obj("package", e.getKey(), "ranges", ranges, "fixed", v.fixedVersions(e.getKey())));
        }
        List<Object> occ = new ArrayList<>();
        java.util.LinkedHashSet<String> modsAffected = new java.util.LinkedHashSet<>();
        int direct = 0, transitive = 0, shaded = 0;
        for (Occurrence o : affected) {
            occ.add(occurrenceJson(o));
            modsAffected.add(o.module);
            if (o.shaded) shaded++;
            else if (o.node.depth == 1) direct++;
            else transitive++;
        }
        List<Object> mods = new ArrayList<>();
        for (String m : modules) {
            int n = 0;
            for (Occurrence o : affected) if (o.module.equals(m)) n++;
            mods.add(Json.obj("module", m, "affected", n > 0, "occurrences", n, "notAffected", safe.getOrDefault(m, List.of())));
        }
        return Json.obj("advisory", v.toJson(), "details", v.details, "affectedPackages", packages,
                "kev", kev == null ? null : kev.toJson(), "epss", epss == null ? null : epss.toJson(),
                "target", target.label, "affected", !affected.isEmpty(), "modules", mods, "occurrences", occ,
                "summary", Json.obj("modules", modules.size(), "modulesAffected", modsAffected.size(), "occurrences", affected.size(),
                        "direct", direct, "transitive", transitive, "shaded", shaded));
    }

    @SuppressWarnings("unchecked")
    private static void print(Ui ui, Osv.Vuln v, Kev.Entry kev, Epss.Score epss, Ctx.Target target, List<String> modules,
                              List<Occurrence> affected, Map<String, List<Object>> safe, Project project) {
        List<String> ids = new ArrayList<>(v.cves());
        if (!ids.contains(v.id)) ids.add(v.id);
        ui.title("Zero-Day Impact " + ui.dot() + " " + String.join(" / ", ids));
        if (v.summary != null) ui.line(v.summary);
        StringBuilder risk = new StringBuilder(ui.severity(v.severity));
        if (v.score >= 0) risk.append(" CVSS ").append(String.format(Locale.ROOT, "%.1f", v.score));
        if (kev != null) risk.append(" ").append(ui.dot()).append(" ").append(ui.red("KNOWN EXPLOITED")).append(" (CISA KEV since ").append(kev.dateAdded)
                .append(kev.ransomware ? ", used by ransomware" : "").append(")");
        if (epss != null) risk.append(" ").append(ui.dot()).append(" EPSS ").append(ThreatSupport.pct(epss.epss))
                .append(" (").append(ThreatSupport.percentile(epss.percentile)).append(")");
        ui.line(risk.toString());
        for (Map.Entry<String, List<Osv.Vuln.Range>> e : v.affected.entrySet()) {
            List<String> rs = new ArrayList<>();
            for (Osv.Vuln.Range r : e.getValue()) rs.add(r.toString());
            List<String> fixed = v.fixedVersions(e.getKey());
            ui.line("Affects " + e.getKey() + " " + String.join("; ", rs) + (fixed.isEmpty() ? ui.dim("  (no fix released)") : " " + ui.arrow() + " fixed in " + String.join(", ", fixed)));
        }
        ui.line(ui.dim(v.url()));
        ui.println();

        if (affected.isEmpty()) {
            ui.good("Not affected: no module of " + target.label + " resolves a vulnerable version");
            for (Map.Entry<String, List<Object>> e : safe.entrySet()) {
                for (Object o : e.getValue()) {
                    String shadedIn = Json.str(o, "shadedIn");
                    ui.line(ui.ok() + " " + e.getKey() + ": uses " + Json.str(o, "artifact") + (shadedIn != null ? " (shaded in " + shadedIn + ")" : "") + " which is not affected");
                }
            }
            return;
        }
        java.util.LinkedHashSet<String> hit = new java.util.LinkedHashSet<>();
        for (Occurrence o : affected) hit.add(o.module);
        ui.fail("Affected: " + Ui.plural(affected.size(), "occurrence") + " in " + hit.size() + " of " + Ui.plural(modules.size(), "module"));
        for (String m : modules) {
            String rel = "";
            if (project != null) {
                Project.Module mod = project.module(m);
                if (mod != null && project.multiModule()) rel = " " + ui.dim("(" + mod.relPath + ")");
            }
            ui.section(m + rel);
            boolean any = false;
            for (Occurrence o : affected) {
                if (!o.module.equals(m)) continue;
                any = true;
                String what = o.shaded ? "shaded copy of " + o.gav + " inside " + o.node.gav() : o.gav.toString();
                ui.println("  " + ui.bad() + " " + ui.bold(what) + "  " + ui.dim(o.node.scope + " " + ui.dot() + " " + (o.node.depth == 1 ? "direct" : "transitive, depth " + o.node.depth)));
                for (Object p : o.paths) {
                    boolean sel = Json.bool(p, false, "selected");
                    String note = sel ? "" : ui.dim("  (requests " + Json.str(p, "requested") + ", " + Json.str(p, "omitted") + ")");
                    ui.println("      " + ui.dim("path") + "  " + Json.str(p, "path") + note);
                }
                if (o.fixedIn != null) ui.println("      " + ui.dim("fixed") + " " + o.fixedIn + (o.recommended != null && !o.recommended.equals(o.fixedIn) ? ui.dim(" (first published unaffected release: " + o.recommended + ")") : ""));
                Map<String, Object> c = o.change;
                if (c != null) {
                    Object verified = c.get("verified");
                    String mark = Boolean.TRUE.equals(verified) ? "  " + ui.ok() + ui.dim(" verified by re-resolving") : Boolean.FALSE.equals(verified) ? "  " + ui.warnMark() + ui.dim(" re-resolution still selects " + c.get("resolvedAfter")) : "";
                    ui.println("      " + ui.green("fix") + "   " + c.get("description") + mark);
                    if (c.get("snippet") != null) ui.println("            " + ui.dim(String.valueOf(c.get("snippet"))));
                }
            }
            if (!any) {
                List<Object> s = safe.getOrDefault(m, Collections.emptyList());
                if (s.isEmpty()) ui.println("  " + ui.ok() + " not affected");
                else for (Object o : s) ui.println("  " + ui.ok() + " uses " + Json.str(o, "artifact") + " which is not affected");
            }
        }
        ui.println();
    }
}
