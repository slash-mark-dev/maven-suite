package in.slashmark.maven.tools;

import in.slashmark.maven.cli.Args;
import in.slashmark.maven.cli.Command;
import in.slashmark.maven.cli.Ctx;
import in.slashmark.maven.cli.Exit;
import in.slashmark.maven.cli.Ui;
import in.slashmark.maven.cli.UsageException;
import in.slashmark.maven.model.Gav;
import in.slashmark.maven.model.MavenVersion;
import in.slashmark.maven.resolve.DepNode;
import in.slashmark.maven.resolve.Graph;
import in.slashmark.maven.resolve.Resolver;
import in.slashmark.maven.util.Json;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Conflict Resolution Simulator: Explain every version conflict (nearest wins) and simulate pins before you edit the POM. */
public final class ResolveCmd extends Command {
    @Override public String name() { return "resolve"; }
    @Override public String title() { return "Conflict Resolution Simulator"; }
    @Override public String group() { return "Live dependency analysis"; }
    @Override public String summary() { return "Explain every version conflict (nearest wins) and simulate pins before you edit the POM"; }

    @Override
    public Set<String> flags() { return Set.of("fix"); }

    @Override
    public String help() {
        return String.join("\n",
                "Usage: sm-maven resolve [group:artifact[:version]] [options]",
                "",
                summary() + ".",
                "For every artifact requested in more than one version it shows the competing paths, which rule",
                "Maven applied (direct declaration, nearest wins, first declaration, dependencyManagement, ranges)",
                "and flags silent downgrades. --pin/--set re-resolve the project as if you had edited the POM and",
                "show exactly what would change, plus the snippet to apply.",
                "",
                "Options:",
                "  --pin <g:a:v>          Simulate a <dependencyManagement> pin (repeatable, comma separated)",
                "  --set <g:a:v>          Simulate changing the version of a direct dependency (repeatable)",
                "  --fix                  Simulate pinning every downgraded artifact to its highest requested version",
                "  --filter <g:a>         Only conflicts of matching artifacts (globs allowed)",
                "  --scope <scopes>       Only conflicts whose selected scope is in this list, e.g. compile,runtime",
                "  --module <name>        Only this module",
                "  --no-test              Ignore test-scoped dependencies",
                "",
                "Exit codes: 1 when a downgrade is present (in the simulated result when simulating).",
                "",
                "Examples:",
                "  sm-maven resolve",
                "  sm-maven resolve --filter jackson-databind",
                "  sm-maven resolve --pin com.fasterxml.jackson.core:jackson-databind:2.18.2",
                "  sm-maven resolve --fix --json");
    }

    /** Explanation of one conflict. */
    static final class Explained {
        final DepSupport.Unit unit;
        final Graph.Conflict c;
        String rule, why, severity;
        String fixAction, fixVersion, fixFile;
        int fixLine;

        Explained(DepSupport.Unit unit, Graph.Conflict c) {
            this.unit = unit;
            this.c = c;
        }
    }

    static String pomFile(DepSupport.Unit u) {
        if (u.relPath == null) return u.label + " (published POM)";
        return ".".equals(u.relPath) ? "pom.xml" : u.relPath + "/pom.xml";
    }

    static Explained explain(DepSupport.Unit u, Graph.Conflict c) {
        Explained e = new Explained(u, c);
        DepNode w = c.winner;
        int minOther = Integer.MAX_VALUE;
        DepNode firstOther = null;
        for (DepNode n : c.items) {
            if (n == w) continue;
            if (n.depth < minOther) {
                minOther = n.depth;
                firstOther = n;
            }
        }
        boolean ranges = false;
        for (DepNode n : c.items) if (n.range != null) ranges = true;
        if (w.premanagedVersion != null) {
            e.rule = "dependencyManagement";
            e.why = "<dependencyManagement> forces " + w.version + " (requested " + w.premanagedVersion + " on this path)";
        } else if (w.isDirect()) {
            e.rule = "direct";
            e.why = "declared directly in " + pomFile(u) + (w.declaredLine > 0 ? " line " + w.declaredLine : "") + "; a direct declaration (depth 1) always wins";
        } else if (w.depth < minOther) {
            e.rule = "nearest";
            e.why = "nearest wins: depth " + w.depth + " via " + w.path().get(0).ga() + " beats depth " + minOther;
        } else {
            e.rule = "first-declaration";
            String other = firstOther == null ? "the other path" : firstOther.path().get(0).ga();
            e.why = "first declaration wins: both at depth " + w.depth + ", and " + w.path().get(0).ga() + " is declared before " + other;
        }
        if (ranges) e.why += " (version ranges constrain the candidates)";
        if (c.downgrade()) {
            e.severity = c.majorGap() ? "high" : "medium";
            e.fixVersion = c.highest();
            if (w.isDirect() && w.premanagedVersion == null) {
                e.fixAction = "update-direct";
                e.fixFile = u.relPath == null ? null : pomFile(u);
                e.fixLine = w.declaredLine;
            } else {
                e.fixAction = "manage";
                e.fixFile = u.relPath == null ? null : pomFile(u);
            }
        } else {
            e.severity = "info";
        }
        return e;
    }

    @Override
    public int run(Ctx ctx, Args args) throws Exception {
        List<Gav> pins = coords(args.getAll("pin"), "--pin");
        List<Gav> sets = coords(args.getAll("set"), "--set");
        boolean fix = args.flag("fix");
        DepSupport.Matcher filter = new DepSupport.Matcher(args.getAll("filter"));
        Set<String> scopes = DepSupport.scopes(args);
        String module = args.get("module");
        boolean noTest = args.flag("no-test");
        for (Gav g : pins) DepSupport.requireExists(ctx, g);
        for (Gav g : sets) DepSupport.requireExists(ctx, g);

        Ctx.Target t = ctx.target(args, 0);
        List<DepSupport.Unit> units = DepSupport.units(t, module);

        List<Explained> all = new ArrayList<>();
        Map<DepSupport.Unit, List<Explained>> byUnit = new LinkedHashMap<>();
        for (DepSupport.Unit u : units) {
            List<Explained> l = new ArrayList<>();
            for (Graph.Conflict c : u.graph.conflicts) {
                if (!filter.matches(c.winner.ga())) continue;
                if (scopes != null && !scopes.contains(c.winner.scope)) continue;
                l.add(explain(u, c));
            }
            byUnit.put(u, l);
            all.addAll(l);
        }

        // Pins that would fix every downgrade (highest requested version per artifact).
        Map<String, Gav> fixPins = new LinkedHashMap<>();
        for (Explained e : all) {
            if (e.fixVersion == null) continue;
            Gav cur = fixPins.get(e.c.winner.ga());
            if (cur == null || MavenVersion.compare(e.fixVersion, cur.version) > 0) fixPins.put(e.c.winner.ga(), e.c.winner.gav().withVersion(e.fixVersion));
        }
        List<Gav> manage = new ArrayList<>(fixPins.values());

        // Simulation.
        Map<String, String> simPins = new LinkedHashMap<>();
        Map<String, String> simSets = new LinkedHashMap<>();
        if (fix) for (Gav g : manage) simPins.put(g.ga(), g.version);
        for (Gav g : pins) simPins.put(g.ga(), g.version);
        for (Gav g : sets) simSets.put(g.ga(), g.version);
        boolean simulate = !simPins.isEmpty() || !simSets.isEmpty();
        List<Sim> sims = new ArrayList<>();
        if (simulate) {
            for (DepSupport.Unit u : units) {
                Resolver.Options opt = new Resolver.Options();
                opt.includeTest = !noTest;
                opt.pins.putAll(simPins);
                opt.directOverrides.putAll(simSets);
                ctx.ui.progress("Simulating " + u.name() + "...");
                Graph after = ctx.resolver.resolve(u.graph.root, opt);
                ctx.ui.progressDone();
                sims.add(new Sim(u, after, filter, scopes));
            }
        }
        List<String> unusedPins = new ArrayList<>();
        if (simulate) {
            Set<String> present = new LinkedHashSet<>();
            for (DepSupport.Unit u : units) for (DepNode n : u.graph.find(x -> true)) present.add(n.ga());
            for (String ga : simPins.keySet()) if (!present.contains(ga)) unusedPins.add(ga);
            for (String ga : simSets.keySet()) {
                boolean direct = false;
                for (DepSupport.Unit u : units) for (DepNode d : u.graph.direct) if (d.ga().equals(ga)) direct = true;
                if (!direct) throw new UsageException("--set " + ga + ": not a direct dependency of " + (units.size() == 1 ? units.get(0).label : "any module") + " (use --pin for transitive artifacts)");
            }
        }

        int downgrades = 0;
        for (Explained e : all) if (e.c.downgrade()) downgrades++;
        int simDowngrades = 0;
        for (Sim s : sims) simDowngrades += s.downgradesAfter;
        int exit = (simulate ? simDowngrades : downgrades) > 0 ? Exit.ISSUES : Exit.OK;

        if (ctx.ui.json) {
            List<Object> mods = new ArrayList<>();
            for (Map.Entry<DepSupport.Unit, List<Explained>> en : byUnit.entrySet()) {
                List<Object> cs = new ArrayList<>();
                for (Explained e : en.getValue()) cs.add(toJson(e));
                mods.add(Json.obj("module", en.getKey().label, "path", en.getKey().relPath, "conflicts", cs));
            }
            Map<String, Object> doc = Json.obj("tool", "resolve", "target", t.label, "modules", mods,
                    "summary", Json.obj("conflicts", all.size(), "downgrades", downgrades, "modules", units.size()));
            if (!manage.isEmpty()) {
                List<Object> pl = new ArrayList<>();
                for (Gav g : manage) pl.add(g.toString());
                doc.put("fix", Json.obj("pins", pl, "dependencyManagement", DepSupport.managementSnippet(manage)));
            }
            if (simulate) {
                List<Object> sl = new ArrayList<>();
                for (Sim s : sims) sl.add(s.toJson());
                List<Gav> applied = new ArrayList<>();
                for (Map.Entry<String, String> p : simPins.entrySet()) applied.add(Gav.parse(p.getKey() + ":" + p.getValue()));
                doc.put("simulation", Json.obj("pins", gavStrings(simPins), "overrides", gavStrings(simSets), "modules", sl,
                        "downgradesAfter", simDowngrades, "ineffectivePins", unusedPins.isEmpty() ? null : unusedPins,
                        "dependencyManagement", applied.isEmpty() ? null : DepSupport.managementSnippet(applied)));
            }
            doc.put("problems", t.problems());
            ctx.ui.emitJson(doc);
            return exit;
        }

        Ui ui = ctx.ui;
        ui.title(ui.bold("Version conflicts") + " " + ui.dim(ui.dot()) + " " + t.label);
        if (!filter.isEmpty()) ui.note("filter: " + String.join(", ", filter.raw()));
        for (Map.Entry<DepSupport.Unit, List<Explained>> en : byUnit.entrySet()) {
            DepSupport.Unit u = en.getKey();
            ui.section(u.label + (u.relPath != null && !".".equals(u.relPath) ? "  (" + u.relPath + ")" : ""));
            if (en.getValue().isEmpty()) {
                ui.good("No version conflicts" + (filter.isEmpty() ? "" : " for " + String.join(", ", filter.raw())));
                continue;
            }
            for (Explained e : en.getValue()) printConflict(ui, e);
        }
        ui.println();
        if (downgrades == 0) ui.good(Ui.plural(all.size(), "conflict") + ", no downgrades: every conflict resolved to the highest requested version");
        else ui.fail(Ui.plural(all.size(), "conflict") + ", " + Ui.plural(downgrades, "silent downgrade") + " (an older version wins over a newer one that a dependency asked for)");

        if (fix && manage.isEmpty()) ui.good("Nothing to fix: no downgraded artifacts");
        if (!manage.isEmpty() && !simulate) {
            ui.section("Fix");
            printFix(ui, all, manage);
            ui.note("Preview the result first: sm-maven resolve --fix");
        }
        if (simulate) printSimulation(ui, sims, simPins, simSets, unusedPins, all);
        for (String p : t.problems()) ui.warn(p);
        return exit;
    }

    private static List<String> gavStrings(Map<String, String> m) {
        List<String> l = new ArrayList<>();
        for (Map.Entry<String, String> e : m.entrySet()) l.add(e.getKey() + ":" + e.getValue());
        return l;
    }

    private static List<Gav> coords(List<String> raw, String opt) {
        List<Gav> out = new ArrayList<>();
        for (String s : raw) {
            Gav g;
            try {
                g = Gav.parse(s);
            } catch (IllegalArgumentException e) {
                throw new UsageException(opt + ": " + e.getMessage());
            }
            if (g.version == null) throw new UsageException(opt + " expects groupId:artifactId:version, got '" + s + "'");
            out.add(g);
        }
        return out;
    }

    private static Object toJson(Explained e) {
        List<Object> reqs = new ArrayList<>();
        for (DepNode n : e.c.items) {
            reqs.add(Json.obj("version", n.version, "path", n.pathString(), "depth", n.depth, "selected", n == e.c.winner,
                    "via", n.path().get(0).ga(), "managedFrom", n.premanagedVersion, "range", n.range,
                    "declaredLine", n.isDirect() && n.declaredLine > 0 ? n.declaredLine : null));
        }
        Map<String, Object> fix = e.fixAction == null ? null : Json.obj("action", e.fixAction, "version", e.fixVersion, "file", e.fixFile,
                "line", e.fixLine > 0 ? e.fixLine : null);
        return Json.obj("artifact", e.c.winner.ga(), "selected", e.c.winner.version, "highestRequested", e.c.highest(),
                "downgrade", e.c.downgrade(), "majorGap", e.c.majorGap(), "rule", e.rule, "explanation", e.why, "severity", e.severity,
                "scope", e.c.winner.scope, "requests", reqs, "fix", fix);
    }

    private static void printConflict(Ui ui, Explained e) {
        Graph.Conflict c = e.c;
        DepNode w = c.winner;
        String head = ui.bold(w.ga()) + "  " + ui.cyan(w.version) + " selected";
        if (c.downgrade()) {
            head += ", " + ui.yellow(c.highest()) + " requested " + ui.arrow() + " " + ui.red("DOWNGRADE" + (c.majorGap() ? " across major versions" : ""));
            ui.fail(head);
        } else {
            ui.println(ui.info() + " " + head + ui.dim(" (highest requested version wins)"));
        }
        ui.line("  " + ui.dim("rule:") + " " + e.why);
        Ui.Table tb = new Ui.Table("", "Version", "Depth", "Path");
        for (DepNode n : c.items) {
            String mark = n == w ? ui.ok() : (MavenVersion.compare(n.version, w.version) > 0 ? ui.warnMark() : " ");
            String path = n.pathString() + (n.premanagedVersion != null ? " (managed from " + n.premanagedVersion + ")" : "")
                    + (n.range != null ? " (range " + n.range + ")" : "");
            tb.row(mark, n == w ? ui.bold(n.version) : n.version, n.depth, path);
        }
        ui.out().print(indent(ui, tb));
        if (e.fixAction != null) {
            if ("update-direct".equals(e.fixAction)) {
                ui.line("  " + ui.green("fix:") + " set <version>" + e.fixVersion + "</version> for " + w.ga() + " in " + e.fixFile
                        + (e.fixLine > 0 ? " line " + e.fixLine : ""));
            } else {
                ui.line("  " + ui.green("fix:") + " pin " + w.ga() + ":" + e.fixVersion + " in <dependencyManagement>" + (e.fixFile == null ? "" : " of " + e.fixFile));
            }
        }
        ui.println();
    }

    /** Renders a table through a throwaway buffer so it can be indented under a conflict. */
    private static String indent(Ui ui, Ui.Table tb) {
        java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
        java.io.PrintStream ps = new java.io.PrintStream(bo, true, java.nio.charset.StandardCharsets.UTF_8);
        Ui tmp = new Ui(ps, ps, ui.color(), false, false, false, !ui.unicode());
        tmp.table(tb);
        StringBuilder b = new StringBuilder();
        for (String line : bo.toString(java.nio.charset.StandardCharsets.UTF_8).split("\n")) b.append("    ").append(line).append('\n');
        return b.toString();
    }

    private static void printFix(Ui ui, List<Explained> all, List<Gav> manage) {
        List<String> directEdits = new ArrayList<>();
        for (Explained e : all) {
            if ("update-direct".equals(e.fixAction)) {
                directEdits.add(e.c.winner.ga() + ": " + e.c.winner.version + " " + ui.arrow() + " " + e.fixVersion + " in " + e.fixFile
                        + (e.fixLine > 0 ? " line " + e.fixLine : ""));
            }
        }
        ui.println("  Add to the <dependencyManagement> of the parent POM (applies to transitive versions):");
        ui.println();
        for (String l : DepSupport.managementSnippet(manage).split("\n")) ui.println("    " + ui.green(l));
        if (!directEdits.isEmpty()) {
            ui.println();
            ui.println("  Directly declared versions are not overridden by <dependencyManagement>; also edit them (or drop their <version>):");
            for (String d : new LinkedHashSet<>(directEdits)) ui.line("  " + ui.dot() + " " + d);
        }
    }

    /** Before/after comparison of one module under the simulated pins. */
    static final class Sim {
        final DepSupport.Unit unit;
        final Graph after;
        final List<String[]> changes = new ArrayList<>(); // ga, from, to, scopeFrom, scopeTo
        final List<Explained> conflictsAfter = new ArrayList<>();
        int downgradesBefore, downgradesAfter;

        Sim(DepSupport.Unit u, Graph after, DepSupport.Matcher filter, Set<String> scopes) {
            this.unit = u;
            this.after = after;
            Map<String, DepNode> b = new LinkedHashMap<>(), a = new LinkedHashMap<>();
            for (DepNode n : u.graph.resolved()) b.put(n.ga(), n);
            for (DepNode n : after.resolved()) a.put(n.ga(), n);
            for (Map.Entry<String, DepNode> e : b.entrySet()) {
                DepNode x = a.get(e.getKey());
                DepNode o = e.getValue();
                if (x == null) changes.add(new String[] {e.getKey(), o.version, null, o.scope, null});
                else if (!x.version.equals(o.version) || !x.scope.equals(o.scope)) changes.add(new String[] {e.getKey(), o.version, x.version, o.scope, x.scope});
            }
            for (Map.Entry<String, DepNode> e : a.entrySet()) {
                if (!b.containsKey(e.getKey())) changes.add(new String[] {e.getKey(), null, e.getValue().version, null, e.getValue().scope});
            }
            for (Graph.Conflict c : u.graph.conflicts) {
                if (filter.matches(c.winner.ga()) && (scopes == null || scopes.contains(c.winner.scope)) && c.downgrade()) downgradesBefore++;
            }
            for (Graph.Conflict c : after.conflicts) {
                if (!filter.matches(c.winner.ga()) || (scopes != null && !scopes.contains(c.winner.scope))) continue;
                Explained e = explain(u, c);
                conflictsAfter.add(e);
                if (c.downgrade()) downgradesAfter++;
            }
        }

        Object toJson() {
            List<Object> ch = new ArrayList<>();
            for (String[] c : changes) {
                String kind = c[1] == null ? "added" : c[2] == null ? "removed" : !c[1].equals(c[2]) ? (MavenVersion.compare(c[2], c[1]) > 0 ? "upgraded" : "downgraded") : "scope";
                ch.add(Json.obj("artifact", c[0], "from", c[1], "to", c[2], "scopeFrom", c[3], "scopeTo", c[4], "kind", kind));
            }
            List<Object> rem = new ArrayList<>();
            for (Explained e : conflictsAfter) rem.add(ResolveCmd.toJson(e));
            return Json.obj("module", unit.label, "changes", ch, "downgradesBefore", downgradesBefore, "downgradesAfter", downgradesAfter,
                    "conflictsAfter", rem, "problems", after.allProblems());
        }
    }

    private static void printSimulation(Ui ui, List<Sim> sims, Map<String, String> pins, Map<String, String> sets, List<String> unusedPins, List<Explained> before) {
        ui.section("Simulation");
        if (!pins.isEmpty()) ui.line("pins: " + String.join(", ", gavStrings(pins)));
        if (!sets.isEmpty()) ui.line("direct versions: " + String.join(", ", gavStrings(sets)));
        for (String ga : unusedPins) ui.warn(ga + " is not in the dependency graph: pinning it has no effect");
        int after = 0;
        for (Sim s : sims) {
            ui.println();
            ui.println("  " + ui.bold(s.unit.label));
            if (s.changes.isEmpty()) ui.line(ui.dim("no change"));
            else {
                Ui.Table tb = new Ui.Table("Artifact", "Before", "After", "");
                for (String[] c : s.changes) {
                    String note;
                    if (c[1] == null) note = ui.green("added");
                    else if (c[2] == null) note = ui.yellow("removed");
                    else if (!c[1].equals(c[2])) note = MavenVersion.compare(c[2], c[1]) > 0 ? ui.green("upgraded") : ui.red("downgraded");
                    else note = "scope " + c[3] + " " + ui.arrow() + " " + c[4];
                    tb.row(c[0], c[1] == null ? "—" : c[1], c[2] == null ? "—" : c[2], note);
                }
                ui.out().print(indent(ui, tb));
            }
            for (Explained e : s.conflictsAfter) {
                if (e.c.downgrade()) ui.line(ui.bad() + " still downgraded: " + e.c.winner.ga() + " " + e.c.winner.version + " (" + e.c.highest() + " requested) - " + e.why);
            }
            for (String p : s.after.allProblems()) ui.warn("  " + p);
            after += s.downgradesAfter;
        }
        int beforeCount = 0;
        for (Explained e : before) if (e.c.downgrade()) beforeCount++;
        ui.println();
        if (after == 0) ui.good("Downgrades: " + beforeCount + " " + ui.arrow() + " 0 with these changes");
        else ui.fail("Downgrades: " + beforeCount + " " + ui.arrow() + " " + after + " with these changes");
        if (!pins.isEmpty()) {
            List<Gav> l = new ArrayList<>();
            for (Map.Entry<String, String> p : pins.entrySet()) l.add(Gav.parse(p.getKey() + ":" + p.getValue()));
            ui.println();
            ui.println("  To apply, add to <dependencyManagement> (and update directly declared versions of the same artifacts):");
            ui.println();
            for (String line : DepSupport.managementSnippet(l).split("\n")) ui.println("    " + ui.green(line));
        }
    }
}
