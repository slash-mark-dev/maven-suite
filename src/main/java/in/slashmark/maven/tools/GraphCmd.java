package in.slashmark.maven.tools;

import in.slashmark.maven.cli.Args;
import in.slashmark.maven.cli.Command;
import in.slashmark.maven.cli.Ctx;
import in.slashmark.maven.cli.Exit;
import in.slashmark.maven.cli.Ui;
import in.slashmark.maven.cli.UsageException;
import in.slashmark.maven.data.Osv;
import in.slashmark.maven.model.MavenVersion;
import in.slashmark.maven.resolve.DepNode;
import in.slashmark.maven.resolve.Graph;
import in.slashmark.maven.util.Json;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Live Dependency Graph: Resolve the dependency graph live from Central: tree, DOT, Mermaid or interactive HTML. */
public final class GraphCmd extends Command {
    @Override public String name() { return "graph"; }
    @Override public String title() { return "Live Dependency Graph"; }
    @Override public String group() { return "Live dependency analysis"; }
    @Override public String summary() { return "Resolve the dependency graph live from Central: tree, DOT, Mermaid or interactive HTML"; }

    @Override
    public Set<String> flags() { return Set.of("vulns", "no-omitted", "html", "dot", "mermaid"); }

    @Override
    public String help() {
        return String.join("\n",
                "Usage: sm-maven graph [group:artifact[:version]] [options]",
                "",
                summary() + ".",
                "Resolves every module (or a published artifact) from the live repositories with Maven's exact",
                "mediation rules and shows the result. The tree marks versions omitted for conflict or duplicate,",
                "versions managed by <dependencyManagement>, ranges, relocations and the effective scope.",
                "",
                "Options:",
                "  --format <fmt>         tree (default), json, dot (Graphviz), mermaid, html (interactive, self-contained)",
                "  -o, --output <file>    Write the graph to a file instead of stdout",
                "  --scope <scopes>       Only these resolved scopes, e.g. compile,runtime",
                "  --depth <n>            Only show the first n levels (1 = direct dependencies)",
                "  --filter <g:a>         Only show paths leading to matching artifacts (globs: org.apache.*:*, *jackson*)",
                "  --module <name>        Only this module of a multi-module project",
                "  --vulns                Mark artifacts with known vulnerabilities (OSV)",
                "  --no-omitted           Hide versions omitted for conflict/duplicate",
                "  --no-test              Ignore test-scoped dependencies",
                "",
                "Examples:",
                "  sm-maven graph",
                "  sm-maven graph --filter com.fasterxml.jackson.core:jackson-databind",
                "  sm-maven graph --format html --vulns -o deps.html",
                "  sm-maven graph --format dot --scope compile,runtime | dot -Tsvg > deps.svg",
                "  sm-maven graph org.springframework:spring-beans:6.1.14 --format mermaid");
    }

    /** A node kept after filtering, with its kept children. */
    static final class VNode {
        final DepNode n;
        final List<VNode> kids = new ArrayList<>();
        final boolean match;

        VNode(DepNode n, boolean match) {
            this.n = n;
            this.match = match;
        }
    }

    private static final class Opts {
        Set<String> scopes;
        int depth = Integer.MAX_VALUE;
        DepSupport.Matcher filter;
        boolean hideOmitted;
    }

    private static List<VNode> build(List<DepNode> nodes, Opts o) {
        List<VNode> out = new ArrayList<>();
        for (DepNode n : nodes) {
            if (n.depth > o.depth) continue;
            if (!n.selected) {
                if (n.omitted == null || "unreachable".equals(n.omitted) || o.hideOmitted || DepSupport.rangeSibling(n)) continue;
            } else if (o.scopes != null && !o.scopes.contains(n.scope)) continue;
            boolean match = o.filter.isEmpty() || o.filter.matches(n);
            VNode v = new VNode(n, match);
            if (n.selected && n.cycleTarget == null) v.kids.addAll(build(n.children, o));
            if (!o.filter.isEmpty() && !match && v.kids.isEmpty()) continue;
            out.add(v);
        }
        return out;
    }

    private static final class View {
        final DepSupport.Unit unit;
        final List<VNode> roots;

        View(DepSupport.Unit unit, List<VNode> roots) {
            this.unit = unit;
            this.roots = roots;
        }
    }

    @Override
    public int run(Ctx ctx, Args args) throws Exception {
        String format = args.get("format", "tree").toLowerCase(Locale.ROOT);
        if (args.flag("html")) format = "html";
        if (args.flag("dot")) format = "dot";
        if (args.flag("mermaid")) format = "mermaid";
        if (!List.of("tree", "json", "dot", "mermaid", "html").contains(format)) {
            throw new UsageException("unknown --format '" + format + "' (use tree, json, dot, mermaid or html)");
        }
        Opts o = new Opts();
        o.scopes = DepSupport.scopes(args);
        int depth = args.getInt("depth", 0);
        if (args.has("depth") && depth < 1) throw new UsageException("--depth must be at least 1");
        if (depth > 0) o.depth = depth;
        o.filter = new DepSupport.Matcher(args.getAll("filter"));
        o.hideOmitted = args.flag("no-omitted");
        boolean vulns = args.flag("vulns");
        String output = args.get("output");
        String module = args.get("module");

        Ctx.Target t = ctx.target(args, 0);
        List<DepSupport.Unit> units = DepSupport.units(t, module);
        Map<String, List<Osv.Vuln>> vmap = vulns ? ctx.vulnerabilities(DepSupport.selectedGavs(units)) : Map.of();

        List<View> views = new ArrayList<>();
        for (DepSupport.Unit u : units) views.add(new View(u, build(u.graph.direct, o)));

        Map<String, Object> doc = json(t, views, vmap, o, vulns);
        String rendered;
        switch (format) {
            case "dot": rendered = dot(t.label, views, vmap); break;
            case "mermaid": rendered = mermaid(views, vmap); break;
            case "html": rendered = html(t.label, doc); break;
            case "json": rendered = Json.write(doc) + "\n"; break;
            default: rendered = null;
        }
        if (output != null) {
            String text = rendered != null ? rendered : plainTree(ctx, views, vmap, o);
            DepSupport.write(output, text);
            doc.put("outputFile", output);
        }
        if (ctx.ui.json) {
            ctx.ui.emitJson(doc);
            return Exit.OK;
        }
        if (output != null) {
            ctx.ui.good("Wrote " + format + " graph of " + Ui.plural(views.size(), "module") + " to " + output);
            printProblems(ctx, t);
            return Exit.OK;
        }
        if (rendered != null) {
            ctx.ui.out().print(rendered.endsWith("\n") ? rendered : rendered + "\n");
            ctx.ui.out().flush();
            return Exit.OK;
        }
        printTree(ctx, t, views, vmap, o);
        return Exit.OK;
    }

    private static void printProblems(Ctx ctx, Ctx.Target t) {
        for (String p : t.problems()) ctx.ui.warn(p);
    }

    // ---------------------------------------------------------------- tree

    private static void printTree(Ctx ctx, Ctx.Target t, List<View> views, Map<String, List<Osv.Vuln>> vmap, Opts o) {
        Ui ui = ctx.ui;
        ui.title(ctx.ui.bold("Dependency graph") + " " + ui.dim(ui.dot()) + " " + t.label);
        if (!o.filter.isEmpty()) ui.note("filter: " + String.join(", ", o.filter.raw()));
        for (View v : views) {
            ui.println();
            ui.println(ui.bold(v.unit.label) + (v.unit.relPath != null && !".".equals(v.unit.relPath) ? ui.dim("  (" + v.unit.relPath + ")") : ""));
            if (v.roots.isEmpty()) ui.println("  " + ui.dim(o.filter.isEmpty() ? "(no dependencies)" : "(no match)"));
            StringBuilder b = new StringBuilder();
            renderTree(ui, v.roots, "", vmap, b, ui.color());
            ui.out().print(b);
            Stats s = stats(v.unit.graph);
            ui.note("  " + s.line());
        }
        List<String> problems = t.problems();
        if (!problems.isEmpty()) {
            ui.section("Problems");
            for (String p : problems) ui.warn(p);
        }
    }

    private static String plainTree(Ctx ctx, List<View> views, Map<String, List<Osv.Vuln>> vmap, Opts o) {
        StringBuilder b = new StringBuilder();
        Ui plain = new Ui(ctx.ui.out(), ctx.ui.err(), false, false, false, false, !ctx.ui.unicode());
        for (View v : views) {
            b.append(v.unit.label).append('\n');
            renderTree(plain, v.roots, "", vmap, b, false);
            b.append(stats(v.unit.graph).line()).append("\n\n");
        }
        return b.toString();
    }

    private static void renderTree(Ui ui, List<VNode> nodes, String indent, Map<String, List<Osv.Vuln>> vmap, StringBuilder b, boolean color) {
        boolean ascii = !ui.unicode();
        for (int i = 0; i < nodes.size(); i++) {
            VNode v = nodes.get(i);
            boolean last = i == nodes.size() - 1;
            b.append(indent).append(ascii ? (last ? "\\- " : "+- ") : (last ? "└─ " : "├─ "));
            b.append(label(ui, v.n, vmap)).append('\n');
            renderTree(ui, v.kids, indent + (last ? "   " : (ascii ? "|  " : "│  ")), vmap, b, color);
        }
    }

    static String label(Ui ui, DepNode n, Map<String, List<Osv.Vuln>> vmap) {
        StringBuilder b = new StringBuilder();
        String coords = n.groupId + ":" + ui.bold(n.artifactId) + ":" + (n.type.equals("jar") ? "" : n.type + ":")
                + (n.classifier == null ? "" : n.classifier + ":");
        List<String> notes = new ArrayList<>();
        if (n.premanagedVersion != null) notes.add("managed from " + n.premanagedVersion);
        if (n.premanagedScope != null) notes.add("scope managed from " + n.premanagedScope);
        if (n.range != null) notes.add("range " + n.range);
        if (n.relocatedFrom != null) notes.add("relocated from " + n.relocatedFrom);
        if (n.optional) notes.add("optional");
        if (!n.selected) {
            String why;
            if ("conflict".equals(n.omitted)) {
                boolean newer = MavenVersion.compare(n.version, n.winner.version) > 0;
                why = "omitted for conflict with " + n.winner.version + (newer ? " - newer version lost" : "");
            } else why = "omitted for " + n.omitted;
            String s = "(" + n.groupId + ":" + n.artifactId + ":" + n.version + " [" + n.declaredScope + "] " + why
                    + (notes.isEmpty() ? "" : "; " + String.join("; ", notes)) + ")";
            boolean lostNewer = "conflict".equals(n.omitted) && MavenVersion.compare(n.version, n.winner.version) > 0;
            return lostNewer ? ui.yellow(s) : ui.dim(s);
        }
        b.append(coords).append(ui.cyan(n.version)).append(' ').append(ui.dim("[" + n.scope + "]"));
        if (!notes.isEmpty()) b.append(' ').append(ui.magenta("(" + String.join("; ", notes) + ")"));
        List<Osv.Vuln> vs = vmap.get(n.gav().toString());
        if (vs != null && !vs.isEmpty()) {
            List<String> ids = new ArrayList<>();
            for (Osv.Vuln x : vs) ids.add(DepSupport.vulnId(x));
            b.append(' ').append(ui.severity(vs.get(0).severity)).append(' ')
                    .append(ui.red(Ui.plural(vs.size(), "vulnerability", "vulnerabilities") + ": " + String.join(", ", ids)));
        }
        return b.toString();
    }

    // ---------------------------------------------------------------- statistics

    static final class Stats {
        int resolved, direct, transitive, conflicts, downgrades, managed, relocated, ranges, maxDepth;

        String line() {
            return Ui.plural(resolved, "artifact") + " (" + direct + " direct, " + transitive + " transitive, depth " + maxDepth + ")"
                    + " · " + Ui.plural(conflicts, "conflict") + (downgrades > 0 ? " (" + downgrades + " downgrade" + (downgrades > 1 ? "s" : "") + ")" : "")
                    + (managed > 0 ? " · " + managed + " managed" : "") + (relocated > 0 ? " · " + relocated + " relocated" : "")
                    + (ranges > 0 ? " · " + Ui.plural(ranges, "range") : "");
        }

        Object toJson() {
            return Json.obj("resolved", resolved, "direct", direct, "transitive", transitive, "maxDepth", maxDepth, "conflicts", conflicts,
                    "downgrades", downgrades, "managed", managed, "relocated", relocated, "ranges", ranges);
        }
    }

    static Stats stats(Graph g) {
        Stats s = new Stats();
        for (DepNode n : g.resolved()) {
            s.resolved++;
            if (n.isDirect()) s.direct++;
            else s.transitive++;
            s.maxDepth = Math.max(s.maxDepth, n.depth);
            if (n.premanagedVersion != null) s.managed++;
            if (n.relocatedFrom != null) s.relocated++;
            if (n.range != null) s.ranges++;
        }
        s.conflicts = g.conflicts.size();
        for (Graph.Conflict c : g.conflicts) if (c.downgrade()) s.downgrades++;
        return s;
    }

    // ---------------------------------------------------------------- JSON

    private static Map<String, Object> json(Ctx.Target t, List<View> views, Map<String, List<Osv.Vuln>> vmap, Opts o, boolean vulns) {
        List<Object> mods = new ArrayList<>();
        for (View v : views) {
            List<Object> conflicts = new ArrayList<>();
            for (Graph.Conflict c : v.unit.graph.conflicts) {
                if (!o.filter.isEmpty() && !o.filter.matches(c.winner.ga())) continue;
                conflicts.add(c.toJson());
            }
            mods.add(Json.obj("module", v.unit.label, "path", v.unit.relPath, "stats", stats(v.unit.graph).toJson(),
                    "dependencies", nodesJson(v.roots, vmap), "conflicts", conflicts, "problems", v.unit.graph.allProblems()));
        }
        Map<String, Object> vulnSummary = null;
        if (vulns) {
            Map<String, Object> byGav = new LinkedHashMap<>();
            for (Map.Entry<String, List<Osv.Vuln>> e : vmap.entrySet()) {
                if (e.getValue().isEmpty()) continue;
                List<Object> l = new ArrayList<>();
                for (Osv.Vuln x : e.getValue()) l.add(Json.obj("id", x.id, "cve", cve(x), "severity", x.severity, "score", x.score >= 0 ? x.score : null, "summary", x.summary));
                byGav.put(e.getKey(), l);
            }
            vulnSummary = byGav;
        }
        return Json.obj("tool", "graph", "target", t.label, "filter", o.filter.isEmpty() ? null : o.filter.raw(),
                "scopes", o.scopes == null ? null : new ArrayList<>(o.scopes), "depth", o.depth == Integer.MAX_VALUE ? null : o.depth,
                "modules", mods, "vulnerabilities", vulnSummary);
    }

    private static String cve(Osv.Vuln v) {
        for (String a : v.aliases) if (a.startsWith("CVE-")) return a;
        return null;
    }

    private static List<Object> nodesJson(List<VNode> nodes, Map<String, List<Osv.Vuln>> vmap) {
        List<Object> out = new ArrayList<>();
        for (VNode v : nodes) {
            DepNode n = v.n;
            List<String> ids = new ArrayList<>();
            String sev = null;
            List<Osv.Vuln> vs = n.selected ? vmap.get(n.gav().toString()) : null;
            if (vs != null && !vs.isEmpty()) {
                for (Osv.Vuln x : vs) ids.add(DepSupport.vulnId(x));
                sev = vs.get(0).severity;
            }
            Map<String, Object> m = Json.obj("groupId", n.groupId, "artifactId", n.artifactId, "version", n.version,
                    "type", "jar".equals(n.type) ? null : n.type, "classifier", n.classifier,
                    "scope", n.selected ? n.scope : n.declaredScope, "optional", n.optional ? Boolean.TRUE : null, "depth", n.depth,
                    "managedFrom", n.premanagedVersion, "range", n.range, "relocatedFrom", n.relocatedFrom,
                    "omitted", n.selected ? null : n.omitted, "winnerVersion", !n.selected && n.winner != null ? n.winner.version : null,
                    "vulnerabilities", ids.isEmpty() ? null : ids, "severity", sev);
            if (!v.kids.isEmpty()) m.put("dependencies", nodesJson(v.kids, vmap));
            out.add(m);
        }
        return out;
    }

    // ---------------------------------------------------------------- DOT / Mermaid

    private static String dotEsc(String s) { return s.replace("\\", "\\\\").replace("\"", "\\\""); }

    private static String dot(String label, List<View> views, Map<String, List<Osv.Vuln>> vmap) {
        StringBuilder b = new StringBuilder();
        b.append("digraph \"").append(dotEsc(label)).append("\" {\n");
        b.append("  rankdir=LR;\n");
        b.append("  node [shape=box, style=\"rounded,filled\", fillcolor=\"#ffffff\", fontname=\"Helvetica\", fontsize=10];\n");
        b.append("  edge [fontname=\"Helvetica\", fontsize=9, color=\"#64748b\"];\n");
        Set<String> nodes = new LinkedHashSet<>(), edges = new LinkedHashSet<>();
        for (View v : views) {
            String root = v.unit.label;
            if (nodes.add(root)) {
                b.append("  \"").append(dotEsc(root)).append("\" [label=\"").append(dotEsc(v.unit.graph.root.pom.artifactId + "\\n" + v.unit.graph.root.gav().version))
                        .append("\", fillcolor=\"#dbeafe\", penwidth=2];\n");
            }
            dotWalk(root, v.roots, vmap, nodes, edges, b);
        }
        for (String e : edges) b.append(e);
        b.append("}\n");
        return b.toString();
    }

    private static void dotWalk(String parent, List<VNode> kids, Map<String, List<Osv.Vuln>> vmap, Set<String> nodes, Set<String> edges, StringBuilder b) {
        for (VNode v : kids) {
            DepNode n = v.n;
            String id = n.gav().toString();
            if (nodes.add(id)) {
                List<Osv.Vuln> vs = vmap.get(id);
                boolean vuln = n.selected && vs != null && !vs.isEmpty();
                String fill = !n.selected ? "#f1f5f9" : vuln ? "#fecaca" : n.isDirect() ? "#ecfdf5" : "#ffffff";
                List<String> lab = new ArrayList<>(List.of(n.artifactId, n.version));
                if (n.selected && !"compile".equals(n.scope)) lab.add("(" + n.scope + ")");
                if (vuln) lab.add(Ui.plural(vs.size(), "vuln") + " (" + vs.get(0).severity + ")");
                List<String> escaped = new ArrayList<>();
                for (String s : lab) escaped.add(dotEsc(s));
                b.append("  \"").append(dotEsc(id)).append("\" [label=\"").append(String.join("\\n", escaped)).append("\", fillcolor=\"").append(fill).append('"');
                if (!n.selected) b.append(", style=\"rounded,dashed,filled\", fontcolor=\"#64748b\"");
                if (vuln) b.append(", color=\"#b91c1c\"");
                b.append(", tooltip=\"").append(dotEsc(id + (vuln ? " - " + vulnIds(vs) : ""))).append("\"];\n");
            }
            String attrs;
            if (n.selected) {
                List<String> a = new ArrayList<>();
                if (n.premanagedVersion != null) a.add("label=\"managed from " + dotEsc(n.premanagedVersion) + "\"");
                else if (n.relocatedFrom != null) a.add("label=\"relocated\"");
                else if (n.range != null) a.add("label=\"" + dotEsc(n.range) + "\"");
                attrs = a.isEmpty() ? "" : " [" + String.join(", ", a) + "]";
            } else {
                attrs = " [style=dashed, color=\"#94a3b8\", label=\"omitted (" + dotEsc(n.omitted) + ")\"]";
            }
            edges.add("  \"" + dotEsc(parent) + "\" -> \"" + dotEsc(id) + "\"" + attrs + ";\n");
            if (n.selected) dotWalk(id, v.kids, vmap, nodes, edges, b);
        }
    }

    private static String vulnIds(List<Osv.Vuln> vs) {
        List<String> ids = new ArrayList<>();
        for (Osv.Vuln x : vs) ids.add(DepSupport.vulnId(x));
        return String.join(", ", ids);
    }

    private static String mermaid(List<View> views, Map<String, List<Osv.Vuln>> vmap) {
        StringBuilder b = new StringBuilder("graph LR\n");
        Map<String, String> ids = new LinkedHashMap<>();
        Set<String> edges = new LinkedHashSet<>();
        List<String> vulnIds = new ArrayList<>(), omittedIds = new ArrayList<>(), rootIds = new ArrayList<>();
        for (View v : views) {
            String root = v.unit.label;
            if (!ids.containsKey(root)) {
                String id = "n" + ids.size();
                ids.put(root, id);
                rootIds.add(id);
                b.append("  ").append(id).append("[\"").append(mmEsc(v.unit.graph.root.pom.artifactId + " " + v.unit.graph.root.gav().version)).append("\"]\n");
            }
            mmWalk(root, v.roots, vmap, ids, edges, vulnIds, omittedIds, b);
        }
        for (String e : edges) b.append(e);
        b.append("  classDef root fill:#dbeafe,stroke:#1d4ed8,stroke-width:2px\n");
        b.append("  classDef vuln fill:#fecaca,stroke:#b91c1c,color:#7f1d1d\n");
        b.append("  classDef omitted fill:#f1f5f9,stroke:#94a3b8,stroke-dasharray:4 3,color:#64748b\n");
        if (!rootIds.isEmpty()) b.append("  class ").append(String.join(",", rootIds)).append(" root\n");
        if (!vulnIds.isEmpty()) b.append("  class ").append(String.join(",", vulnIds)).append(" vuln\n");
        if (!omittedIds.isEmpty()) b.append("  class ").append(String.join(",", omittedIds)).append(" omitted\n");
        return b.toString();
    }

    private static String mmEsc(String s) { return s.replace("\"", "#quot;").replace("<", "#lt;").replace(">", "#gt;"); }

    private static void mmWalk(String parent, List<VNode> kids, Map<String, List<Osv.Vuln>> vmap, Map<String, String> ids, Set<String> edges,
                               List<String> vulnIds, List<String> omittedIds, StringBuilder b) {
        for (VNode v : kids) {
            DepNode n = v.n;
            String key = n.gav().toString();
            String id = ids.get(key);
            if (id == null) {
                id = "n" + ids.size();
                ids.put(key, id);
                List<Osv.Vuln> vs = vmap.get(key);
                String text = n.groupId + ":" + n.artifactId + " " + n.version;
                if (n.selected && !"compile".equals(n.scope)) text += " (" + n.scope + ")";
                if (n.selected && vs != null && !vs.isEmpty()) {
                    text += " ⚠ " + vulnIds(vs);
                    vulnIds.add(id);
                }
                if (!n.selected) omittedIds.add(id);
                b.append("  ").append(id).append("[\"").append(mmEsc(text)).append("\"]\n");
            }
            String from = ids.get(parent);
            if (n.selected) {
                String lab = n.premanagedVersion != null ? "managed from " + n.premanagedVersion : n.relocatedFrom != null ? "relocated" : n.range != null ? n.range : null;
                edges.add("  " + from + (lab == null ? " --> " : " -->|" + mmEsc(lab) + "| ") + id + "\n");
                mmWalk(key, v.kids, vmap, ids, edges, vulnIds, omittedIds, b);
            } else {
                edges.add("  " + from + " -.->|omitted " + n.omitted + "| " + id + "\n");
            }
        }
    }

    // ---------------------------------------------------------------- HTML

    private static String html(String label, Map<String, Object> doc) {
        String data = Json.write(doc, false).replace("</", "<\\/").replace("<!--", "<\\!--");
        String title = label.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
        return HTML.replace("@@TITLE@@", title).replace("@@DATA@@", data);
    }

    private static final String HTML = String.join("\n",
            "<!doctype html>",
            "<html lang=\"en\">",
            "<head>",
            "<meta charset=\"utf-8\">",
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
            "<title>Dependency graph · @@TITLE@@</title>",
            "<style>",
            ":root{--bg:#f8fafc;--panel:#ffffff;--fg:#0f172a;--muted:#64748b;--line:#e2e8f0;--accent:#2563eb;--warn:#b45309;--bad:#b91c1c;--badbg:#fee2e2;--ok:#047857;--hl:#fef08a;}",
            "@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0b1220;--panel:#111a2e;--fg:#e2e8f0;--muted:#94a3b8;--line:#1e293b;--accent:#60a5fa;--warn:#fbbf24;--bad:#f87171;--badbg:#3f1d1d;--ok:#34d399;--hl:#854d0e;}}",
            ":root[data-theme=dark]{--bg:#0b1220;--panel:#111a2e;--fg:#e2e8f0;--muted:#94a3b8;--line:#1e293b;--accent:#60a5fa;--warn:#fbbf24;--bad:#f87171;--badbg:#3f1d1d;--ok:#34d399;--hl:#854d0e;}",
            "*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}",
            "header{position:sticky;top:0;background:var(--panel);border-bottom:1px solid var(--line);padding:12px 16px;z-index:1}",
            "h1{font-size:16px;margin:0 0 8px}h1 small{color:var(--muted);font-weight:400}",
            ".bar{display:flex;flex-wrap:wrap;gap:8px;align-items:center}",
            "input[type=search]{flex:1 1 240px;min-width:0;padding:6px 10px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg)}",
            "button,label.chk{padding:5px 10px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);cursor:pointer;font-size:13px}",
            "main{padding:12px 16px;max-width:1200px}",
            "section{background:var(--panel);border:1px solid var(--line);border-radius:8px;margin:0 0 12px;padding:10px 12px;overflow-x:auto}",
            "section h2{font-size:14px;margin:0 0 4px}.stats{color:var(--muted);font-size:12px;margin-bottom:6px}",
            "ul{list-style:none;margin:0;padding-left:18px}ul.root{padding-left:0}li{white-space:nowrap}",
            ".tw{display:inline-block;width:16px;color:var(--muted);cursor:pointer;user-select:none}",
            ".g{color:var(--muted)}.a{font-weight:600}.v{color:var(--accent)}.s{color:var(--muted);font-size:12px}",
            ".note{color:var(--warn);font-size:12px;margin-left:6px}.om{opacity:.6}.om .a{font-weight:400}.lost{color:var(--warn);opacity:1}",
            ".badge{display:inline-block;margin-left:6px;padding:0 6px;border-radius:9px;font-size:11px;background:var(--badbg);color:var(--bad);font-weight:600}",
            "mark{background:var(--hl);color:inherit}.hidden{display:none}.empty{color:var(--muted)}",
            "</style>",
            "</head>",
            "<body>",
            "<header>",
            "<h1>Dependency graph <small>@@TITLE@@ · sm-maven</small></h1>",
            "<div class=\"bar\">",
            "<input type=\"search\" id=\"q\" placeholder=\"Search group:artifact or version…\" aria-label=\"Search\">",
            "<button id=\"exp\">Expand all</button><button id=\"col\">Collapse all</button>",
            "<label class=\"chk\"><input type=\"checkbox\" id=\"om\" checked> omitted</label>",
            "<label class=\"chk\"><input type=\"checkbox\" id=\"vo\"> vulnerable only</label>",
            "</div>",
            "</header>",
            "<main id=\"m\"></main>",
            "<script>",
            "const DATA=@@DATA@@;",
            "const m=document.getElementById('m');",
            "function esc(s){return String(s).replace(/[&<>\"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[c]));}",
            "function node(n){",
            " const li=document.createElement('li');",
            " const om=!!n.omitted;",
            " li.dataset.key=(n.groupId+':'+n.artifactId+':'+n.version).toLowerCase();",
            " li.dataset.vuln=n.vulnerabilities?'1':'';",
            " if(om)li.dataset.omitted='1';",
            " const kids=n.dependencies||[];",
            " let h='<span class=\"tw\">'+(kids.length?'▾':'')+'</span>';",
            " h+='<span class=\"lbl'+(om?' om':'')+'\"><span class=\"g\">'+esc(n.groupId)+':</span><span class=\"a\">'+esc(n.artifactId)+'</span>:<span class=\"v\">'+esc(n.version)+'</span> <span class=\"s\">'+esc(n.scope||'')+'</span>';",
            " const notes=[];",
            " if(n.managedFrom)notes.push('managed from '+n.managedFrom);",
            " if(n.range)notes.push('range '+n.range);",
            " if(n.relocatedFrom)notes.push('relocated from '+n.relocatedFrom);",
            " if(n.optional)notes.push('optional');",
            " if(om)notes.push('omitted for '+n.omitted+(n.winnerVersion?' with '+n.winnerVersion:''));",
            " h+='</span>';",
            " if(notes.length)h+='<span class=\"note'+(om&&n.omitted==='conflict'?' lost':'')+'\">'+esc(notes.join('; '))+'</span>';",
            " if(n.vulnerabilities)h+='<span class=\"badge\" title=\"'+esc(n.vulnerabilities.join(', '))+'\">'+esc((n.severity||'').toUpperCase())+' · '+n.vulnerabilities.length+' vuln'+(n.vulnerabilities.length>1?'s':'')+'</span>';",
            " li.innerHTML=h;",
            " if(kids.length){const ul=document.createElement('ul');kids.forEach(k=>ul.appendChild(node(k)));li.appendChild(ul);",
            "  li.querySelector('.tw').addEventListener('click',()=>{ul.classList.toggle('hidden');li.querySelector('.tw').textContent=ul.classList.contains('hidden')?'▸':'▾';});}",
            " return li;",
            "}",
            "DATA.modules.forEach(mod=>{",
            " const s=document.createElement('section');const st=mod.stats||{};",
            " s.innerHTML='<h2>'+esc(mod.module)+'</h2><div class=\"stats\">'+st.resolved+' artifacts · '+st.direct+' direct · '+st.transitive+' transitive · '+st.conflicts+' conflicts'+(st.downgrades?' ('+st.downgrades+' downgrades)':'')+'</div>';",
            " const ul=document.createElement('ul');ul.className='root';(mod.dependencies||[]).forEach(n=>ul.appendChild(node(n)));",
            " if(!(mod.dependencies||[]).length)s.insertAdjacentHTML('beforeend','<div class=\"empty\">No dependencies</div>');",
            " s.appendChild(ul);m.appendChild(s);",
            "});",
            "const q=document.getElementById('q'),om=document.getElementById('om'),vo=document.getElementById('vo');",
            "function apply(){",
            " const t=q.value.trim().toLowerCase();",
            " document.querySelectorAll('mark').forEach(x=>x.replaceWith(document.createTextNode(x.textContent)));",
            " const walk=li=>{let any=false;const ul=li.querySelector(':scope>ul');",
            "  if(ul)ul.querySelectorAll(':scope>li').forEach(c=>{if(walk(c))any=true;});",
            "  let self=(!t||li.dataset.key.includes(t))&&(!vo.checked||li.dataset.vuln==='1');",
            "  if(li.dataset.omitted&&!om.checked)self=false,any=false;",
            "  const show=self||any;li.classList.toggle('hidden',!show);",
            "  if((t||vo.checked)&&any&&ul){ul.classList.remove('hidden');}",
            "  if(t&&self){li.querySelectorAll(':scope>.lbl .a,:scope>.lbl .g').forEach(e=>{const i=e.textContent.toLowerCase().indexOf(t);if(i>=0){const x=e.textContent;e.innerHTML=esc(x.slice(0,i))+'<mark>'+esc(x.slice(i,i+t.length))+'</mark>'+esc(x.slice(i+t.length));}});}",
            "  return show;};",
            " document.querySelectorAll('ul.root>li').forEach(walk);",
            "}",
            "q.addEventListener('input',apply);om.addEventListener('change',apply);vo.addEventListener('change',apply);",
            "document.getElementById('exp').onclick=()=>document.querySelectorAll('li>ul').forEach(u=>{u.classList.remove('hidden');u.parentElement.querySelector('.tw').textContent='▾';});",
            "document.getElementById('col').onclick=()=>document.querySelectorAll('li>ul').forEach(u=>{u.classList.add('hidden');u.parentElement.querySelector('.tw').textContent='▸';});",
            "</script>",
            "</body>",
            "</html>",
            "");
}
