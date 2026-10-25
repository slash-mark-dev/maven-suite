package in.slashmark.maven.tools;

import in.slashmark.maven.cli.Args;
import in.slashmark.maven.cli.Command;
import in.slashmark.maven.cli.Ctx;
import in.slashmark.maven.cli.Ui;
import in.slashmark.maven.cli.UsageException;
import in.slashmark.maven.model.Gav;
import in.slashmark.maven.model.ModelBuilder;
import in.slashmark.maven.model.Pom;
import in.slashmark.maven.repo.Metadata;
import in.slashmark.maven.resolve.DepNode;
import in.slashmark.maven.resolve.Graph;
import in.slashmark.maven.util.Http;
import in.slashmark.maven.util.HttpException;
import in.slashmark.maven.watch.Watcher;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Relocation &amp; Retirement Alerts: Relocated, retired and abandoned artifacts with their successors. */
public final class Relocations extends Command {
    @Override public String name() { return "relocations"; }
    @Override public String title() { return "Relocation & Retirement Alerts"; }
    @Override public String group() { return "Release intelligence"; }
    @Override public String summary() { return "Relocated, retired and abandoned artifacts with their successors"; }

    @Override
    public String help() {
        return String.join("\n",
                "Usage: sm-maven relocations [group:artifact[:version]] [options]",
                "",
                summary() + ".",
                "It walks the whole resolved tree and reports, with the exact replacement coordinates:",
                "  relocated          the POM you depend on is a <relocation> stub (Maven silently swapped it)",
                "  relocated-newer    newer releases of the artifact are relocation stubs: it moved",
                "  retired            a well-known artifact that was renamed or ended (javax -> jakarta, ...)",
                "  archived           the source repository is archived on GitHub (no successor declared)",
                "Watch-capable: repeated runs alert only on new findings.",
                "",
                "Options:",
                "  --direct               Only direct dependencies (default: the whole tree)",
                "  --no-github            Skip the GitHub archived-repository check",
                "",
                Watcher.HELP,
                "",
                "Examples:",
                "  sm-maven relocations",
                "  sm-maven relocations --fail-on any --json",
                "  sm-maven relocations --watch --interval 6h --channel team-slack");
    }

    @Override
    public Set<String> flags() { return Set.of("direct", "no-github"); }

    /** One finding with its replacement. */
    private static final class Item {
        String kind, severity, artifact, replacement, replacementLatest, reason, note, path, declaredIn;
        boolean direct;
        Set<String> modules = new LinkedHashSet<>();
        DepNode node;

        String key() { return kind + ":" + artifact; }
    }

    @Override
    public int run(Ctx ctx, Args args) throws Exception {
        boolean directOnly = args.flag("direct");
        boolean github = !args.flag("no-github");
        if (args.positionals().size() > 1) throw new UsageException("relocations takes at most one coordinate, got " + args.positionals());
        Ctx.Target target = ctx.target(args, 0);
        String scope = ReleaseSupport.scope(target);
        List<Item> current = new ArrayList<>();

        Watcher.Cycle cycle = c -> {
            if (c > 1) ctx.live(0);
            current.clear();
            current.addAll(collect(ctx, target, directOnly, github));
            List<Watcher.Finding> out = new ArrayList<>();
            for (Item it : current) {
                String line = it.artifact + " " + it.kind + (it.replacement != null ? " -> use " + it.replacement : "") + (it.reason != null ? " (" + it.reason + ")" : "");
                out.add(new Watcher.Finding(it.key(), it.severity, line, toJson(it)));
            }
            return out;
        };
        Watcher.Printer printer = (all, fresh, c, baseline) -> print(ctx.ui, target, current, fresh, c);
        return Watcher.run(ctx, args, name(), scope, "relocated or retired artifacts", cycle, printer);
    }

    private static List<Item> collect(Ctx ctx, Ctx.Target target, boolean directOnly, boolean github) throws Exception {
        Map<String, Item> items = new LinkedHashMap<>();
        Set<String> reactor = ctx.models.reactorGavs();
        // 1. Relocations Maven applied while resolving (DepNode.relocatedFrom).
        for (Graph g : target.graphs) {
            String module = g.root.pom.artifactId;
            for (DepNode n : g.resolved()) {
                if (n.relocatedFrom == null || (directOnly && !n.isDirect())) continue;
                Item it = items.get("relocated:" + n.relocatedFrom);
                if (it == null) {
                    it = new Item();
                    it.kind = "relocated";
                    it.severity = "medium";
                    it.artifact = n.relocatedFrom;
                    it.replacement = n.gav().toString();
                    it.node = n;
                    it.direct = n.isDirect();
                    it.path = pathString(n);
                    it.declaredIn = n.isDirect() ? declared(target, g, n) : null;
                    Gav from = ReleaseSupport.parseGav(n.relocatedFrom);
                    String msg = relocationMessage(ctx, from);
                    it.reason = "the POM of " + from + " is a relocation to " + n.gav() + (msg != null ? ": \"" + msg + "\"" : "");
                    it.replacementLatest = latest(ctx, n.groupId, n.artifactId);
                    items.put(it.key(), it);
                }
                it.modules.add(module);
            }
        }
        // 2. Every other dependency: retired names, newer relocation stubs, archived repositories.
        List<ReleaseSupport.Dep> deps = ReleaseSupport.dependencies(ctx, target, !directOnly);
        ctx.ui.progress("Checking " + Ui.plural(deps.size(), "artifact") + " for relocations and retirement...");
        List<Http.Result<List<Item>>> res = ctx.http.parallel(deps, d -> check(ctx, target, d, github));
        ctx.ui.progressDone();
        for (int i = 0; i < res.size(); i++) {
            if (!res.get(i).ok()) {
                ctx.ui.warnErr("could not check " + deps.get(i).ga() + ": " + res.get(i).error.getMessage());
                continue;
            }
            for (Item it : res.get(i).value) {
                if (reactor.contains(it.artifact)) continue;
                Item prev = items.putIfAbsent(it.key(), it);
                if (prev != null) prev.modules.addAll(it.modules);
            }
        }
        List<Item> out = new ArrayList<>(items.values());
        out.sort((a, b) -> {
            int c = Integer.compare(rank(b.severity), rank(a.severity));
            return c != 0 ? c : a.artifact.compareTo(b.artifact);
        });
        return out;
    }

    private static int rank(String s) { return "high".equals(s) ? 3 : "medium".equals(s) ? 2 : "low".equals(s) ? 1 : 0; }

    private static List<Item> check(Ctx ctx, Ctx.Target target, ReleaseSupport.Dep d, boolean github) throws HttpException {
        List<Item> out = new ArrayList<>();
        DepNode n = d.node;
        String gav = n.gav().toString();
        // Retired / renamed without a relocation POM.
        ReleaseSupport.Successor s = ReleaseSupport.RETIRED.get(n.ga());
        if (s != null) {
            Item it = base(target, d, "retired", "medium");
            it.reason = s.reason;
            it.note = s.note;
            String latest = latest(ctx, s.replacement.split(":")[0], s.replacement.split(":")[1]);
            it.replacement = latest != null ? latest : s.replacement;
            it.replacementLatest = latest;
            out.add(it);
        }
        // Newer versions are relocation stubs: the artifact moved after the version in use.
        if (n.relocatedFrom == null) {
            Metadata md = ctx.repos.metadata(n.groupId, n.artifactId);
            String newest = md == null ? null : md.newest(true);
            if (newest != null && !newest.equals(n.version)) {
                ModelBuilder.Model m = ctx.models.buildRemote(new Gav(n.groupId, n.artifactId, newest));
                Pom.Relocation r = m == null ? null : m.pom.relocation;
                if (r != null) {
                    Gav to = new Gav(r.groupId != null ? r.groupId : n.groupId, r.artifactId != null ? r.artifactId : n.artifactId, r.version != null ? r.version : newest);
                    if (!to.ga().equals(n.ga()) || !to.version.equals(newest)) {
                        Item it = base(target, d, "relocated-newer", "low");
                        it.reason = n.ga() + " " + newest + " is a relocation to " + to + (r.message != null ? ": \"" + r.message + "\"" : "") + "; future releases are published there";
                        it.replacementLatest = latest(ctx, to.groupId, to.artifactId);
                        it.replacement = it.replacementLatest != null ? to.ga() + ":" + it.replacementLatest.substring(it.replacementLatest.lastIndexOf(':') + 1) : to.toString();
                        out.add(it);
                    }
                }
            }
        }
        // Archived source repository.
        if (github) {
            ReleaseSupport.RepoInfo ri = ReleaseSupport.sourceRepo(ctx, n.gav());
            ReleaseSupport.github(ctx, ri);
            if (ri.found && ri.archived) {
                Item it = base(target, d, "archived", "high");
                it.reason = "GitHub repository " + ri.repo + " is archived: no more fixes or security patches";
                it.note = "no successor is declared: replace it, vendor the code or fork " + ri.repo;
                out.add(it);
            } else if (ri.error != null) {
                ctx.ui.debug(gav + ": " + ri.error);
            }
        }
        return out;
    }

    private static Item base(Ctx.Target target, ReleaseSupport.Dep d, String kind, String severity) {
        Item it = new Item();
        it.kind = kind;
        it.severity = severity;
        it.artifact = d.gav().toString();
        it.node = d.node;
        it.direct = d.direct;
        it.modules.addAll(d.modules);
        it.path = pathString(d.node);
        if (d.directIn != null) it.declaredIn = declared(target, d.directIn, d.node);
        return it;
    }

    private static String pathString(DepNode n) {
        StringBuilder b = new StringBuilder();
        for (DepNode x : n.path()) {
            if (b.length() > 0) b.append(" -> ");
            b.append(x.relocatedFrom != null ? x.relocatedFrom + " (relocated to " + x.gav() + ")" : x.gav().toString());
        }
        return b.toString();
    }

    private static String declared(Ctx.Target target, Graph g, DepNode n) {
        if (g.root.pom.file == null) return null;
        java.nio.file.Path file = g.root.pom.file;
        String f = target.project != null && file.startsWith(target.project.root)
                ? target.project.root.relativize(file).toString().replace('\\', '/') : file.toString();
        return n.declaredLine > 0 ? f + ":" + n.declaredLine : f;
    }

    private static String relocationMessage(Ctx ctx, Gav from) {
        try {
            ModelBuilder.Model m = ctx.models.buildRemote(from);
            if (m != null && m.pom.relocation != null) return m.pom.relocation.message;
        } catch (HttpException e) {
            ctx.ui.debug("relocation POM " + from + ": " + e.getMessage());
        }
        return null;
    }

    /** Newest final release as g:a:v (null when the artifact is not on the repository). */
    private static String latest(Ctx ctx, String g, String a) throws HttpException {
        Metadata md = ctx.repos.metadata(g, a);
        String v = md == null ? null : md.newest(true);
        return v == null ? null : g + ":" + a + ":" + v;
    }

    private static Map<String, Object> toJson(Item it) {
        String[] p = it.artifact.split(":");
        return ReleaseSupport.o("kind", it.kind, "artifact", it.artifact, "groupId", p[0], "artifactId", p[1], "version", p.length > 2 ? p[2] : null,
                "replacement", it.replacement, "replacementLatest", it.replacementLatest, "reason", it.reason, "note", it.note,
                "direct", it.direct, "modules", new ArrayList<>(it.modules), "path", it.path, "declaredIn", it.declaredIn);
    }

    private static void print(Ui ui, Ctx.Target target, List<Item> items, Set<String> fresh, int cycle) {
        if (cycle == 1) ui.title("Relocation & Retirement Alerts  " + ui.dim(target.label));
        else {
            ui.println();
            ui.title("Relocation & Retirement Alerts  " + ui.dim("check #" + cycle));
        }
        if (items.isEmpty()) {
            ui.println();
            ui.good("No relocated, retired or archived artifacts in the tree");
            return;
        }
        boolean allNew = fresh.size() == items.size();
        for (Item it : items) {
            ui.println();
            String mark = "high".equals(it.severity) ? ui.bad() : "medium".equals(it.severity) ? ui.warnMark() : ui.info();
            String tag = !allNew && fresh.contains(it.key()) ? " " + ui.cyan("NEW") : "";
            ui.println(mark + " " + ui.bold(it.kind.toUpperCase(java.util.Locale.ROOT)) + "  " + it.artifact + tag
                    + ui.dim("  (" + (it.direct ? "direct" : "transitive") + ", " + String.join(", ", it.modules) + ")"));
            if (it.reason != null) ui.line(it.reason);
            if (it.replacement != null) {
                ui.line(ui.arrow() + " replace with " + ui.green(ui.bold(it.replacement)));
                if (it.replacementLatest != null && !it.replacementLatest.equals(it.replacement)) ui.line("  newest release: " + it.replacementLatest);
                String[] r = it.replacement.split(":");
                if (it.direct && r.length >= 3) {
                    String sc = it.node != null && !"compile".equals(it.node.scope) ? "<scope>" + it.node.scope + "</scope>" : "";
                    ui.line(ui.dim("  <dependency><groupId>" + r[0] + "</groupId><artifactId>" + r[1] + "</artifactId><version>" + r[2] + "</version>" + sc + "</dependency>"));
                }
            }
            if (it.note != null) ui.line(ui.dim(it.note));
            if (!it.direct && it.path != null) ui.line(ui.dim("via " + it.path));
            else if (it.declaredIn != null) ui.line(ui.dim("declared in " + it.declaredIn));
        }
        ui.println();
        long high = items.stream().filter(i -> "high".equals(i.severity)).count();
        ui.warn(Ui.plural(items.size(), "artifact needs", "artifacts need") + " a successor" + (high > 0 ? " (" + high + " archived)" : ""));
    }
}
