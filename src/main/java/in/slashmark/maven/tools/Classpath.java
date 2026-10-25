package in.slashmark.maven.tools;

import in.slashmark.maven.bytecode.Jar;
import in.slashmark.maven.cli.Args;
import in.slashmark.maven.cli.Command;
import in.slashmark.maven.cli.Ctx;
import in.slashmark.maven.cli.Exit;
import in.slashmark.maven.cli.Project;
import in.slashmark.maven.cli.Ui;
import in.slashmark.maven.model.Gav;
import in.slashmark.maven.resolve.DepNode;
import in.slashmark.maven.util.Hash;
import in.slashmark.maven.util.Json;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/** Classpath Collision Detector: Duplicate classes, split packages and shaded copies across the runtime classpath. */
public final class Classpath extends Command {
    @Override public String name() { return "classpath"; }
    @Override public String title() { return "Classpath Collision Detector"; }
    @Override public String group() { return "Live dependency analysis"; }
    @Override public String summary() { return "Duplicate classes, split packages and shaded copies across the runtime classpath"; }

    @Override
    public Set<String> flags() { return Set.of("strict", "no-classes"); }

    @Override
    public String help() {
        return String.join("\n",
                "Usage: sm-maven classpath [group:artifact[:version]] [options]",
                "",
                summary() + ".",
                "Downloads every JAR of the resolved runtime classpath (plus the module's own target/classes) and",
                "compares their class files: the same class in two JARs with different bytes is a real conflict",
                "(whichever comes first on the classpath wins, the other is silently ignored); identical copies are",
                "harmless. Also finds split packages (a problem for JPMS and sealed packages), shaded/relocated",
                "copies of libraries bundled inside other JARs, and libraries resolved to different versions in",
                "different modules.",
                "",
                "Options:",
                "  --scope <scopes>       Classpath scopes (default compile,runtime; add test or provided as needed)",
                "  --module <name>        Only this module",
                "  --limit <n>            Example classes listed per finding (default 5)",
                "  --no-classes           Do not include the modules' own target/classes",
                "  --strict               Also fail on harmless identical duplicates and split packages",
                "  --no-test              Ignore test-scoped dependencies",
                "",
                "Exit codes: 1 when conflicting duplicates or shaded copies are found (--strict: any finding).",
                "",
                "Examples:",
                "  sm-maven classpath",
                "  sm-maven classpath --scope compile,runtime,test --module app",
                "  sm-maven classpath com.acme:acme-fat:1.0.0 --json");
    }

    /** One element of the classpath. */
    static final class Element {
        final String label;
        final DepNode node;
        final Jar jar;
        final boolean classesDir;
        /** class name (dotted) -> sha1 of the bytes. */
        final Map<String, String> classes = new LinkedHashMap<>();

        Element(String label, DepNode node, Jar jar, boolean classesDir) {
            this.label = label;
            this.node = node;
            this.jar = jar;
            this.classesDir = classesDir;
            if (jar != null) {
                for (String e : jar.classEntries(false)) {
                    String path = e.startsWith("BOOT-INF/classes/") ? e.substring(17) : e.startsWith("WEB-INF/classes/") ? e.substring(16) : e;
                    String name = path.substring(0, path.length() - 6).replace('/', '.');
                    if (name.endsWith("package-info")) continue;
                    byte[] b = jar.entry(e);
                    classes.put(name, b == null ? "" : Hash.sha1Hex(b));
                }
            }
        }

        String ga() { return node == null ? null : node.ga(); }
    }

    static final class DupGroup {
        final List<Element> jars;
        final List<String> classes = new ArrayList<>();
        final List<String> differing = new ArrayList<>();

        DupGroup(List<Element> jars) { this.jars = jars; }

        boolean conflicting() { return !differing.isEmpty(); }
    }

    static final class Shaded {
        final Element host;
        String embeds;          // g:a:v from pom.properties, or the g:a:v of the library whose classes were relocated
        String evidence;        // "pom.properties", "relocated classes", "both"
        final List<String> relocated = new ArrayList<>();
        final List<String> copied = new ArrayList<>();
        String onClasspath;     // g:a:v of the same library on the classpath

        Shaded(Element host) { this.host = host; }
    }

    static final class Report {
        final DepSupport.Unit unit;
        final List<Element> cp = new ArrayList<>();
        final List<String> missing = new ArrayList<>();
        final List<DupGroup> dups = new ArrayList<>();
        final Map<String, List<Element>> split = new TreeMap<>();
        final List<Shaded> shaded = new ArrayList<>();
        int classCount;

        Report(DepSupport.Unit unit) { this.unit = unit; }
    }

    @Override
    public int run(Ctx ctx, Args args) throws Exception {
        Set<String> scopes = DepSupport.scopes(args);
        if (scopes == null) scopes = Set.of("compile", "runtime");
        String module = args.get("module");
        int limit = Math.max(1, args.getInt("limit", 5));
        boolean strict = args.flag("strict");
        boolean noClasses = args.flag("no-classes");

        Ctx.Target t = ctx.target(args, 0);
        List<DepSupport.Unit> units = DepSupport.units(t, module);

        // Download every JAR once, in parallel.
        Map<String, DepNode> needed = new LinkedHashMap<>();
        for (DepSupport.Unit u : units) {
            for (DepNode n : u.graph.resolvedDepthFirst()) {
                if (!scopes.contains(n.scope) || ctx.models.inReactor(n.gav()) || "pom".equals(n.type)) continue;
                needed.putIfAbsent(n.gav().toString(), n);
            }
        }
        if (t.artifact != null) {
            // the published artifact itself is the first element of its own classpath
            needed.putIfAbsent(t.artifact.toString(), null);
        }
        List<String> keys = new ArrayList<>(needed.keySet());
        ctx.ui.progress("Downloading " + keys.size() + " JARs...");
        List<Jar> jars = ctx.http.parallelOrNull(keys, k -> ctx.jar(Gav.parse(k)));
        ctx.ui.progressDone();
        Map<String, Jar> byGav = new HashMap<>();
        for (int i = 0; i < keys.size(); i++) byGav.put(keys.get(i), jars.get(i));
        Map<String, Element> elementCache = new HashMap<>();

        List<Report> reports = new ArrayList<>();
        for (DepSupport.Unit u : units) {
            Report r = new Report(u);
            if (u.module != null && !noClasses && u.module.classesDir() != null) {
                r.cp.add(new Element(u.label + " (target/classes)", null, Jar.read(u.module.classesDir()), true));
            }
            if (t.artifact != null && u.graph.root.gav().equals(t.artifact)) {
                Jar own = byGav.get(t.artifact.toString());
                if (own != null) r.cp.add(new Element(t.artifact.toString(), null, own, false));
            }
            for (DepNode n : u.graph.resolvedDepthFirst()) {
                if (!scopes.contains(n.scope) || "pom".equals(n.type)) continue;
                String k = n.gav().toString();
                if (ctx.models.inReactor(n.gav())) {
                    Project.Module m = t.project == null ? null : t.project.module(n.ga());
                    Path dir = m == null ? null : m.classesDir();
                    if (dir == null) {
                        r.missing.add(k + " (reactor module not compiled)");
                        continue;
                    }
                    Element e = elementCache.get("reactor:" + k);
                    if (e == null) {
                        e = new Element(k + " (target/classes)", n, Jar.read(dir), true);
                        elementCache.put("reactor:" + k, e);
                    }
                    r.cp.add(e);
                    continue;
                }
                Jar j = byGav.get(k);
                if (j == null) {
                    r.missing.add(k);
                    continue;
                }
                Element e = elementCache.get(k);
                if (e == null || e.node != n) {
                    e = new Element(k, n, j, false);
                    elementCache.put(k, e);
                }
                r.cp.add(e);
            }
            analyse(r);
            reports.add(r);
        }

        // Version skew across modules.
        Map<String, Map<String, String>> skew = new TreeMap<>();
        if (reports.size() > 1) {
            Map<String, Map<String, String>> vers = new TreeMap<>();
            for (Report r : reports) {
                for (Element e : r.cp) {
                    if (e.node == null || e.classesDir) continue;
                    vers.computeIfAbsent(e.ga(), k -> new LinkedHashMap<>()).put(r.unit.label, e.node.version);
                }
            }
            for (Map.Entry<String, Map<String, String>> e : vers.entrySet()) {
                if (new LinkedHashSet<>(e.getValue().values()).size() > 1) skew.put(e.getKey(), e.getValue());
            }
        }

        int conflicts = 0, harmless = 0, splits = 0, shadedCount = 0;
        for (Report r : reports) {
            for (DupGroup g : r.dups) if (g.conflicting()) conflicts++; else harmless++;
            splits += r.split.size();
            shadedCount += r.shaded.size();
        }
        boolean issues = conflicts > 0 || shadedCount > 0 || (strict && (harmless > 0 || splits > 0 || !skew.isEmpty()));
        int exit = issues ? Exit.ISSUES : Exit.OK;

        if (ctx.ui.json) {
            List<Object> mods = new ArrayList<>();
            for (Report r : reports) mods.add(toJson(r, limit));
            List<Object> sk = new ArrayList<>();
            for (Map.Entry<String, Map<String, String>> e : skew.entrySet()) sk.add(Json.obj("artifact", e.getKey(), "versions", e.getValue()));
            ctx.ui.emitJson(Json.obj("tool", "classpath", "target", t.label, "scopes", new ArrayList<>(new TreeSet<>(scopes)), "modules", mods,
                    "versionSkew", sk, "summary", Json.obj("conflictingDuplicates", conflicts, "harmlessDuplicates", harmless,
                            "splitPackages", splits, "shadedCopies", shadedCount, "versionSkew", skew.size())));
            return exit;
        }
        print(ctx.ui, t, reports, skew, scopes, limit, conflicts, harmless, splits, shadedCount);
        return exit;
    }

    // ---------------------------------------------------------------- analysis

    static void analyse(Report r) {
        Map<String, List<Element>> owners = new LinkedHashMap<>();
        for (Element e : r.cp) {
            r.classCount += e.classes.size();
            for (String c : e.classes.keySet()) owners.computeIfAbsent(c, k -> new ArrayList<>()).add(e);
        }
        // Duplicate classes grouped by the set of JARs that contain them.
        Map<String, DupGroup> groups = new LinkedHashMap<>();
        for (Map.Entry<String, List<Element>> o : owners.entrySet()) {
            List<Element> l = o.getValue();
            if (l.size() < 2) continue;
            StringBuilder key = new StringBuilder();
            for (Element e : l) key.append(e.label).append('|');
            DupGroup g = groups.computeIfAbsent(key.toString(), k -> new DupGroup(l));
            g.classes.add(o.getKey());
            Set<String> hashes = new LinkedHashSet<>();
            for (Element e : l) hashes.add(e.classes.get(o.getKey()));
            if (hashes.size() > 1) g.differing.add(o.getKey());
        }
        r.dups.addAll(groups.values());
        r.dups.sort((a, b) -> Boolean.compare(b.conflicting(), a.conflicting()));

        // Split packages: one package spread over several classpath elements.
        Map<String, Set<Element>> pkgs = new TreeMap<>();
        for (Element e : r.cp) {
            for (String c : e.classes.keySet()) {
                int i = c.lastIndexOf('.');
                pkgs.computeIfAbsent(i < 0 ? "" : c.substring(0, i), k -> new LinkedHashSet<>()).add(e);
            }
        }
        for (Map.Entry<String, Set<Element>> p : pkgs.entrySet()) if (p.getValue().size() > 1 && !p.getKey().isEmpty()) r.split.put(p.getKey(), new ArrayList<>(p.getValue()));

        // Shaded copies: embedded pom.properties of other artifacts, and relocated classes of other classpath JARs.
        Map<String, Element> classOwner = new HashMap<>();
        for (Map.Entry<String, List<Element>> o : owners.entrySet()) classOwner.put(o.getKey(), o.getValue().get(0));
        Map<String, Element> byGa = new HashMap<>();
        for (Element e : r.cp) if (e.ga() != null) byGa.putIfAbsent(e.ga(), e);
        for (Element host : r.cp) {
            if (host.classesDir || host.jar == null) continue;
            Map<String, Shaded> found = new LinkedHashMap<>();
            for (String emb : host.jar.embeddedMavenArtifacts()) {
                String ga = DepSupport.gaOf(emb);
                if (ga.equals(host.ga()) || (host.node == null && host.label.startsWith(ga + ":"))) continue;
                Shaded s = found.computeIfAbsent(ga, k -> new Shaded(host));
                s.embeds = emb;
                s.evidence = "pom.properties";
            }
            for (String c : host.classes.keySet()) {
                String[] seg = c.split("\\.");
                for (int k = 1; k + 3 <= seg.length; k++) {
                    String suffix = String.join(".", java.util.Arrays.copyOfRange(seg, k, seg.length));
                    List<Element> ow = owners.get(suffix);
                    if (ow == null) continue;
                    Element orig = null;
                    for (Element x : ow) if (x != host) { orig = x; break; }
                    if (orig == null || orig.ga() == null) continue;
                    Shaded s = found.computeIfAbsent(orig.ga(), kk -> new Shaded(host));
                    if (s.embeds == null) s.embeds = orig.node.gav().toString();
                    s.evidence = "pom.properties".equals(s.evidence) || "both".equals(s.evidence) ? "both" : "relocated classes";
                    s.relocated.add(c + " = " + suffix);
                    break;
                }
            }
            for (Map.Entry<String, Shaded> e : found.entrySet()) {
                Shaded s = e.getValue();
                Element same = byGa.get(e.getKey());
                if (same != null && same != host) {
                    s.onClasspath = same.node.gav().toString();
                    // unrelocated copies: classes of the library at their original names inside the host
                    for (String c : same.classes.keySet()) if (host.classes.containsKey(c)) s.copied.add(c);
                }
                r.shaded.add(s);
            }
        }
    }

    // ---------------------------------------------------------------- output

    private static List<String> labels(List<Element> l) {
        List<String> out = new ArrayList<>();
        for (Element e : l) out.add(e.label);
        return out;
    }

    private static List<String> head(List<String> l, int n) { return l.size() <= n ? l : l.subList(0, n); }

    private static Object toJson(Report r, int limit) {
        List<Object> cp = new ArrayList<>();
        for (Element e : r.cp) cp.add(Json.obj("artifact", e.label, "scope", e.node == null ? null : e.node.scope, "classes", e.classes.size(),
                "source", e.classesDir ? "classes" : "jar"));
        List<Object> dups = new ArrayList<>();
        for (DupGroup g : r.dups) {
            dups.add(Json.obj("jars", labels(g.jars), "winner", g.jars.get(0).label, "classes", g.classes.size(), "conflicting", g.differing.size(),
                    "identical", g.classes.size() - g.differing.size(), "severity", g.conflicting() ? "conflict" : "harmless",
                    "examples", head(g.classes, limit), "conflictingClasses", head(g.differing, limit)));
        }
        List<Object> split = new ArrayList<>();
        for (Map.Entry<String, List<Element>> s : r.split.entrySet()) split.add(Json.obj("package", s.getKey(), "jars", labels(s.getValue())));
        List<Object> shaded = new ArrayList<>();
        for (Shaded s : r.shaded) {
            String ver = s.embeds.split(":").length > 2 ? s.embeds.split(":")[2] : null;
            String cpv = s.onClasspath == null ? null : s.onClasspath.split(":")[2];
            shaded.add(Json.obj("jar", s.host.label, "embeds", s.embeds, "evidence", s.evidence, "relocatedClasses", s.relocated.size(),
                    "copiedClasses", s.copied.size(), "examples", head(s.relocated.isEmpty() ? s.copied : s.relocated, limit),
                    "onClasspath", s.onClasspath, "sameVersion", ver == null || cpv == null ? null : ver.equals(cpv)));
        }
        return Json.obj("module", r.unit.label, "path", r.unit.relPath, "jars", r.cp.size(), "classes", r.classCount, "classpath", cp,
                "missing", r.missing, "duplicates", dups, "splitPackages", split, "shaded", shaded);
    }

    private static void print(Ui ui, Ctx.Target t, List<Report> reports, Map<String, Map<String, String>> skew, Set<String> scopes, int limit,
                              int conflicts, int harmless, int splits, int shadedCount) {
        ui.title(ui.bold("Classpath collisions") + " " + ui.dim(ui.dot()) + " " + t.label + ui.dim("  (scopes: " + String.join(",", new TreeSet<>(scopes)) + ")"));
        for (Report r : reports) {
            ui.section(r.unit.label + (r.unit.relPath != null && !".".equals(r.unit.relPath) ? "  (" + r.unit.relPath + ")" : ""));
            ui.note("  " + Ui.plural(r.cp.size(), "classpath entry", "classpath entries") + ", " + Ui.plural(r.classCount, "class", "classes"));
            for (String m : r.missing) ui.warn("no JAR for " + m);
            if (r.dups.isEmpty() && r.split.isEmpty() && r.shaded.isEmpty()) {
                ui.good("No duplicate classes, split packages or shaded copies");
                continue;
            }
            if (!r.dups.isEmpty()) {
                ui.println();
                ui.println("  " + ui.bold("Duplicate classes"));
                for (DupGroup g : r.dups) {
                    String jars = String.join(ui.unicode() ? " ⇄ " : " <-> ", labels(g.jars));
                    if (g.conflicting()) {
                        ui.fail(jars + ": " + Ui.plural(g.classes.size(), "class", "classes") + ", " + ui.red(g.differing.size() + " with different bytes")
                                + ui.dim(" - " + g.jars.get(0).label + " wins (first on the classpath)"));
                        ui.line("    " + ui.dim(String.join(", ", head(g.differing, limit)) + (g.differing.size() > limit ? ", ..." : "")));
                    } else {
                        ui.println(ui.info() + " " + jars + ": " + Ui.plural(g.classes.size(), "class", "classes") + ui.green(" identical") + ui.dim(" - harmless"));
                    }
                }
            }
            if (!r.split.isEmpty()) {
                ui.println();
                ui.println("  " + ui.bold("Split packages"));
                for (Map.Entry<String, List<Element>> s : r.split.entrySet()) {
                    ui.warn(s.getKey() + ": " + String.join(", ", labels(s.getValue())));
                }
            }
            if (!r.shaded.isEmpty()) {
                ui.println();
                ui.println("  " + ui.bold("Shaded copies"));
                for (Shaded s : r.shaded) {
                    String ev = s.evidence.equals("both") ? "pom.properties + relocated classes" : s.evidence;
                    String extra = s.onClasspath == null ? "" : s.onClasspath.equals(s.embeds) ? "; the same version is also on the classpath" : "; " + s.onClasspath + " is also on the classpath";
                    ui.fail(s.host.label + " bundles " + ui.bold(s.embeds) + ui.dim(" (" + ev + ")") + extra);
                    List<String> ex = s.relocated.isEmpty() ? s.copied : s.relocated;
                    if (!ex.isEmpty()) ui.line("    " + ui.dim((s.relocated.isEmpty() ? "copied: " : "relocated: ") + String.join(", ", head(ex, limit)) + (ex.size() > limit ? ", ..." : "")));
                    ui.line("    " + ui.dim("Vulnerability scanners keyed on coordinates miss this copy; check it with: sm-maven blast " + DepSupport.gaOf(s.embeds) + " --deep"));
                }
            }
        }
        if (!skew.isEmpty()) {
            ui.section("Different versions across modules");
            for (Map.Entry<String, Map<String, String>> e : skew.entrySet()) {
                List<String> l = new ArrayList<>();
                for (Map.Entry<String, String> m : e.getValue().entrySet()) l.add(m.getKey().split(":")[1] + " " + m.getValue());
                ui.warn(e.getKey() + ": " + String.join(", ", l));
            }
        }
        ui.println();
        String sum = Ui.plural(conflicts, "conflicting duplicate") + ", " + Ui.plural(harmless, "harmless duplicate") + ", "
                + Ui.plural(splits, "split package") + ", " + Ui.plural(shadedCount, "shaded copy", "shaded copies")
                + (skew.isEmpty() ? "" : ", " + Ui.plural(skew.size(), "version skew", "version skews"));
        if (conflicts > 0 || shadedCount > 0) {
            ui.fail(sum);
            ui.note("  Exclude the redundant artifact (<exclusion>) or keep exactly one implementation of each API on the classpath.");
        } else if (harmless > 0 || splits > 0 || !skew.isEmpty()) ui.warn(sum);
        else ui.good(sum);
    }
}
