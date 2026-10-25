package in.slashmark.maven.tools;

import in.slashmark.maven.cli.Args;
import in.slashmark.maven.cli.Command;
import in.slashmark.maven.cli.Ctx;
import in.slashmark.maven.cli.Project;
import in.slashmark.maven.cli.Ui;
import in.slashmark.maven.cli.UsageException;
import in.slashmark.maven.model.Gav;
import in.slashmark.maven.model.MavenVersion;
import in.slashmark.maven.model.ModelBuilder;
import in.slashmark.maven.resolve.DepNode;
import in.slashmark.maven.resolve.Graph;
import in.slashmark.maven.resolve.Resolver;
import in.slashmark.maven.util.Json;
import in.slashmark.maven.watch.Watcher;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/** Transitive Drift Monitor: Snapshot resolved versions and alert when transitive versions drift (ranges, new releases). */
public final class Drift extends Command {
    @Override public String name() { return "drift"; }
    @Override public String title() { return "Transitive Drift Monitor"; }
    @Override public String group() { return "Live dependency analysis"; }
    @Override public String summary() { return "Snapshot resolved versions and alert when transitive versions drift (ranges, new releases)"; }

    @Override
    public Set<String> flags() { return Set.of("update", "transitive"); }

    @Override
    public String help() {
        return String.join("\n",
                "Usage: sm-maven drift [group:artifact[:version]] [options]",
                "",
                summary() + ".",
                "The first run records a snapshot of every resolved version (default .sm-maven/drift.json in the",
                "project, commit it next to pom.xml). Later runs resolve again from the live repositories and report",
                "artifacts that were added, removed or changed - typically transitive versions you never declared,",
                "moved by a version range when a new release is published, or by a changed parent/BOM.",
                "",
                "Options:",
                "  --snapshot <file>      Snapshot file (default <project>/.sm-maven/drift.json)",
                "  --baseline, --update   Record the current resolution as the new snapshot (accept the drift)",
                "  --transitive           Only report artifacts that are not declared directly",
                "  --no-test              Ignore test-scoped dependencies",
                "",
                Watcher.HELP,
                "",
                "Exit codes: 1 when the resolution drifted from the snapshot (in --watch mode: when new drift appears).",
                "",
                "Examples:",
                "  sm-maven drift                      # first run records the snapshot",
                "  sm-maven drift --json               # later: compare, exit 1 on drift",
                "  sm-maven drift --baseline           # accept the current versions",
                "  sm-maven drift --watch --interval 1h --channel ops");
    }

    /** One resolved artifact as stored in the snapshot. */
    static final class Entry {
        String version, scope, range, path, managedFrom;
        boolean direct, optional;

        Object toJson() {
            return Json.obj("version", version, "scope", scope, "direct", direct, "optional", optional ? Boolean.TRUE : null,
                    "range", range, "managedFrom", managedFrom, "path", path);
        }

        static Entry of(Object o) {
            Entry e = new Entry();
            e.version = Json.str(o, "version");
            e.scope = Json.str(o, "scope");
            e.direct = Json.bool(o, false, "direct");
            e.optional = Json.bool(o, false, "optional");
            e.range = Json.str(o, "range");
            e.managedFrom = Json.str(o, "managedFrom");
            e.path = Json.str(o, "path");
            return e;
        }
    }

    /** Module key (groupId:artifactId) -> artifact key -> entry. */
    static Map<String, Map<String, Entry>> capture(List<Graph> graphs) {
        Map<String, Map<String, Entry>> out = new LinkedHashMap<>();
        for (Graph g : graphs) {
            Map<String, Entry> m = new LinkedHashMap<>();
            for (DepNode n : g.resolved()) {
                Entry e = new Entry();
                e.version = n.version;
                e.scope = n.scope;
                e.direct = n.isDirect();
                e.optional = n.optional;
                e.range = n.range;
                e.managedFrom = n.premanagedVersion;
                e.path = n.pathString();
                m.put(key(n), e);
            }
            out.put(g.root.gav().ga(), m);
        }
        return out;
    }

    static String key(DepNode n) {
        return n.ga() + ("jar".equals(n.type) ? "" : ":" + n.type) + (n.classifier == null ? "" : ":" + n.classifier);
    }

    /** A difference between the snapshot and the current resolution. */
    static final class Change {
        String module, artifact, kind, from, to, scopeFrom, scopeTo, range, reason, path, severity;
        boolean direct;

        String key() { return module + "|" + artifact + "|" + kind + "|" + from + "->" + to + (scopeFrom != null && !scopeFrom.equals(scopeTo) ? "|" + scopeFrom + "->" + scopeTo : ""); }

        Object toJson() {
            return Json.obj("module", module, "artifact", artifact, "change", kind, "from", from, "to", to, "scopeFrom", scopeFrom, "scopeTo", scopeTo,
                    "direct", direct, "range", range, "reason", reason, "path", path, "severity", severity);
        }

        String line() {
            String what;
            switch (kind) {
                case "added": what = "added " + to; break;
                case "removed": what = "removed (was " + from + ")"; break;
                case "scope": what = "scope " + scopeFrom + " -> " + scopeTo; break;
                default: what = from + " -> " + to;
            }
            return artifact + " " + what + " in " + module + (reason == null ? "" : " (" + reason + ")");
        }
    }

    static List<Change> compare(Map<String, Map<String, Entry>> before, Map<String, Map<String, Entry>> now, boolean transitiveOnly) {
        List<Change> out = new ArrayList<>();
        Set<String> modules = new LinkedHashSet<>(before.keySet());
        modules.addAll(now.keySet());
        for (String mod : modules) {
            Map<String, Entry> b = before.getOrDefault(mod, Map.of()), a = now.getOrDefault(mod, Map.of());
            if (!before.containsKey(mod) || !now.containsKey(mod)) {
                Change c = new Change();
                c.module = mod;
                c.artifact = mod;
                c.kind = before.containsKey(mod) ? "module-removed" : "module-added";
                c.severity = "info";
                c.reason = before.containsKey(mod) ? "module no longer in the project" : "new module, not in the snapshot";
                out.add(c);
                continue;
            }
            List<Change> mc = new ArrayList<>();
            Set<String> keys = new LinkedHashSet<>(b.keySet());
            keys.addAll(a.keySet());
            for (String k : keys) {
                Entry o = b.get(k), n = a.get(k);
                Change c = new Change();
                c.module = mod;
                c.artifact = k;
                if (o == null) {
                    c.kind = "added";
                    c.to = n.version;
                    c.scopeTo = n.scope;
                } else if (n == null) {
                    c.kind = "removed";
                    c.from = o.version;
                    c.scopeFrom = o.scope;
                } else if (!o.version.equals(n.version)) {
                    c.kind = MavenVersion.compare(n.version, o.version) > 0 ? "upgraded" : "downgraded";
                    c.from = o.version;
                    c.to = n.version;
                    c.scopeFrom = o.scope;
                    c.scopeTo = n.scope;
                } else if (!o.scope.equals(n.scope)) {
                    c.kind = "scope";
                    c.from = o.version;
                    c.to = n.version;
                    c.scopeFrom = o.scope;
                    c.scopeTo = n.scope;
                } else continue;
                Entry cur = n != null ? n : o;
                c.direct = cur.direct || (o != null && o.direct);
                c.range = n != null && n.range != null ? n.range : o != null ? o.range : null;
                c.path = cur.path;
                if (transitiveOnly && c.direct) continue;
                mc.add(c);
            }
            // Explain each change, using the other changes of the module (a parent that moved drags its children).
            Map<String, Change> byGa = new LinkedHashMap<>();
            for (Change c : mc) byGa.put(DepSupport.gaOf(c.artifact), c);
            for (Change c : mc) {
                c.reason = reason(c, byGa, a.get(c.artifact));
                c.severity = severity(c);
            }
            out.addAll(mc);
        }
        return out;
    }

    private static String reason(Change c, Map<String, Change> byGa, Entry now) {
        String ancestor = null;
        if (c.path != null) {
            String[] steps = c.path.split(" -> ");
            for (int i = 0; i < steps.length - 1; i++) {
                Change p = byGa.get(DepSupport.gaOf(steps[i]));
                if (p != null && p != c) {
                    ancestor = p.artifact + (p.to != null ? " " + (p.from == null ? "" : p.from + " -> ") + p.to : "");
                    break;
                }
            }
        }
        switch (c.kind) {
            case "added":
                return ancestor != null ? "new dependency of " + ancestor : c.direct ? "declared in pom.xml" : "new transitive dependency";
            case "removed":
                return ancestor != null ? "no longer needed by " + ancestor : c.direct ? "declaration removed from pom.xml" : "no longer resolved";
            case "scope":
                return "scope derivation changed";
            default:
                if (c.range != null) return "range " + c.range + " now resolves to " + c.to;
                if (now != null && now.managedFrom != null) return "dependencyManagement now forces " + c.to;
                if (c.direct) return "declared version changed";
                if (ancestor != null) return "follows " + ancestor;
                return "mediation picked a different version";
        }
    }

    private static String severity(Change c) {
        switch (c.kind) {
            case "downgraded": return "high";
            case "upgraded": {
                if (MavenVersion.of(c.from).major() != MavenVersion.of(c.to).major()) return "high";
                return c.direct ? "low" : "medium";
            }
            case "added": return c.direct ? "low" : "medium";
            case "removed":
            case "scope": return "low";
            default: return "info";
        }
    }

    @Override
    public int run(Ctx ctx, Args args) throws Exception {
        boolean update = args.flag("baseline") || args.flag("update");
        boolean transitiveOnly = args.flag("transitive");
        boolean noTest = args.flag("no-test");
        String snapOpt = args.get("snapshot");
        boolean watch = args.flag("watch");
        // A one-off check fails on any drift; a watch loop alerts and fails on new drift (Watcher's default).
        if (!watch && !args.options().containsKey("fail-on")) args.options().put("fail-on", new ArrayList<>(List.of("any")));

        String spec = args.pos(0);
        Gav artifact = null;
        String scope;
        Path snapFile;
        if (spec != null && Gav.looksLikeGav(spec)) {
            try {
                artifact = Gav.parse(spec);
            } catch (IllegalArgumentException e) {
                throw new UsageException(e.getMessage());
            }
            scope = artifact.toString();
            snapFile = snapOpt != null ? Paths.get(snapOpt) : ctx.state("drift-snapshot", scope).file();
        } else if (spec != null) {
            throw new UsageException("expected group:artifact[:version], got '" + spec + "'");
        } else {
            Project p = ctx.project();
            scope = p.rootModule().pom.toString();
            snapFile = snapOpt != null ? Paths.get(snapOpt) : p.root.resolve(".sm-maven").resolve("drift.json");
        }
        final Gav target = artifact;
        final Path file = snapFile;
        final String[] info = new String[3]; // [0] "recorded" when a snapshot was written, [1] snapshot date, [2] artifact count

        Watcher.Cycle cycle = c -> {
            ctx.live(0); // fresh metadata every cycle: ranges and "latest" must see new releases
            List<Graph> graphs = resolve(ctx, target, noTest);
            Map<String, Map<String, Entry>> now = capture(graphs);
            int count = 0;
            for (Map<String, Entry> m : now.values()) count += m.size();
            info[2] = String.valueOf(count);
            if ((c == 1 && update) || !Files.isRegularFile(file)) {
                save(file, scope, now);
                info[0] = "recorded";
                info[1] = Instant.now().toString();
                return new ArrayList<>();
            }
            info[0] = null;
            Map<String, Object> snap = load(file);
            info[1] = Json.str(snap, "createdAt");
            Map<String, Map<String, Entry>> before = new LinkedHashMap<>();
            for (Map.Entry<String, Object> m : Json.map(snap, "modules").entrySet()) {
                Map<String, Entry> em = new LinkedHashMap<>();
                for (Map.Entry<String, Object> e : Json.map(m.getValue()).entrySet()) em.put(e.getKey(), Entry.of(e.getValue()));
                before.put(m.getKey(), em);
            }
            List<Watcher.Finding> out = new ArrayList<>();
            for (Change ch : compare(before, now, transitiveOnly)) out.add(new Watcher.Finding(ch.key(), ch.severity, ch.line(), ch.toJson()));
            return out;
        };
        Watcher.Printer printer = (all, fresh, c, baseline) -> print(ctx.ui, file, info, all, fresh, c);
        return Watcher.run(ctx, args, "drift", scope, "drifted versions", cycle, printer);
    }

    private static List<Graph> resolve(Ctx ctx, Gav target, boolean noTest) throws Exception {
        Resolver.Options opt = new Resolver.Options();
        opt.includeTest = !noTest;
        List<Graph> out = new ArrayList<>();
        if (target != null) {
            Gav g = ctx.resolveLatest(target);
            ModelBuilder.Model m = ctx.models.buildRemote(g);
            if (m == null) throw new UsageException(g + " was not found on " + ctx.repos.remotes().get(0).url);
            out.add(ctx.resolver.resolve(m, opt));
            return out;
        }
        Project p = ctx.project();
        for (Project.Module m : p.codeModules()) {
            ctx.ui.progress("Resolving " + m.model.pom.artifactId + "...");
            out.add(ctx.resolver.resolve(m.model, opt));
        }
        ctx.ui.progressDone();
        return out;
    }

    private static void save(Path file, String scope, Map<String, Map<String, Entry>> now) throws IOException {
        Map<String, Object> mods = new LinkedHashMap<>();
        for (Map.Entry<String, Map<String, Entry>> m : now.entrySet()) {
            Map<String, Object> em = new LinkedHashMap<>();
            for (String k : new TreeSet<>(m.getValue().keySet())) em.put(k, m.getValue().get(k).toJson());
            mods.put(m.getKey(), em);
        }
        Map<String, Object> doc = Json.obj("tool", "sm-maven drift", "schema", 1, "createdAt", Instant.now().toString(),
                "target", scope.endsWith("pom.xml") ? null : scope, "modules", mods);
        Path abs = file.toAbsolutePath();
        if (abs.getParent() != null) Files.createDirectories(abs.getParent());
        Files.writeString(abs, Json.write(doc) + "\n", StandardCharsets.UTF_8);
    }

    private static Map<String, Object> load(Path file) throws IOException {
        try {
            Map<String, Object> m = Json.parseObject(Files.readString(file, StandardCharsets.UTF_8));
            if (!(Json.get(m, "modules") instanceof Map)) throw new IllegalArgumentException("no \"modules\"");
            return m;
        } catch (IllegalArgumentException e) {
            throw new UsageException(file + " is not a drift snapshot (" + e.getMessage() + "); re-create it with --baseline");
        }
    }

    private static void print(Ui ui, Path file, String[] info, List<Watcher.Finding> all, Set<String> fresh, int cycle) {
        String when = info[1] == null ? "" : Ui.date(parse(info[1])) + " (" + Ui.ago(parse(info[1])) + ")";
        if (cycle == 1) ui.title(ui.bold("Transitive drift") + " " + ui.dim(ui.dot()) + " " + file);
        if ("recorded".equals(info[0])) {
            ui.good("Snapshot recorded: " + info[2] + " resolved artifacts " + ui.arrow() + " " + file);
            ui.note("  Later runs compare against it; commit it to track drift in CI.");
            return;
        }
        if (all.isEmpty()) {
            ui.good("No drift: all " + info[2] + " resolved artifacts match the snapshot of " + when);
            return;
        }
        ui.fail(Ui.plural(all.size(), "change") + " since the snapshot of " + when + (fresh.isEmpty() ? "" : " (" + fresh.size() + " new)"));
        Ui.Table t = new Ui.Table("", "Module", "Artifact", "Change", "Before", "After", "Why");
        for (Watcher.Finding f : all) {
            Object j = f.json;
            String kind = Json.str(j, "change");
            String change;
            switch (kind) {
                case "downgraded": change = ui.red("downgraded"); break;
                case "upgraded": change = ui.yellow("upgraded"); break;
                case "added": change = ui.green("added"); break;
                case "removed": change = ui.dim("removed"); break;
                default: change = kind;
            }
            boolean direct = Json.bool(j, false, "direct");
            String art = Json.str(j, "artifact") + (direct ? ui.dim(" (direct)") : "");
            String mod = Json.str(j, "module");
            mod = mod.substring(mod.indexOf(':') + 1);
            String before = Json.str(j, "from"), after = Json.str(j, "to");
            if ("scope".equals(kind)) {
                before = Json.str(j, "scopeFrom");
                after = Json.str(j, "scopeTo");
            }
            t.row(fresh.contains(f.key) ? ui.yellow("NEW") : "", mod, art, change, before == null ? "—" : before, after == null ? "—" : after, Json.str(j, "reason"));
        }
        ui.table(t);
        boolean ranges = false;
        for (Watcher.Finding f : all) if (Json.str(f.json, "range") != null) ranges = true;
        ui.println();
        if (ranges) ui.note("  Version ranges make builds non-reproducible: pin them to a fixed version or in <dependencyManagement>.");
        ui.note("  Accept the current versions as the new snapshot: sm-maven drift --baseline");
    }

    private static long parse(String iso) {
        try {
            return Instant.parse(iso).toEpochMilli();
        } catch (RuntimeException e) {
            return 0;
        }
    }
}
