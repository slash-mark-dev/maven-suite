package in.slashmark.maven.tools;

import in.slashmark.maven.cli.Args;
import in.slashmark.maven.cli.Command;
import in.slashmark.maven.cli.Ctx;
import in.slashmark.maven.cli.Ui;
import in.slashmark.maven.cli.UsageException;
import in.slashmark.maven.model.MavenVersion;
import in.slashmark.maven.util.Http;
import in.slashmark.maven.watch.Watcher;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Release Radar: Live feed of new versions across your dependencies. */
public final class Radar extends Command {
    @Override public String name() { return "radar"; }
    @Override public String title() { return "Release Radar"; }
    @Override public String group() { return "Release intelligence"; }
    @Override public String summary() { return "Live feed of new versions across your dependencies"; }

    @Override
    public String help() {
        return String.join("\n",
                "Usage: sm-maven radar [group:artifact[:version]] [options]",
                "",
                summary() + ".",
                "For every dependency it lists the releases newer than the version you resolve, with",
                "the release date and age from Maven Central search and the semantic-version jump",
                "(patch/minor/major). Repository metadata is always fetched fresh. Each run remembers",
                "what it saw, so a scheduled run or --watch only alerts on versions published since the",
                "previous check.",
                "",
                "Options:",
                "  --transitive           Include transitive dependencies (default: direct ones only)",
                "  --pre                  Include pre-releases (alpha, beta, RC, milestones)",
                "  --since <time>         Only versions released within this window, e.g. 7d, 4w",
                "  --min-jump <level>     Hide smaller jumps: patch (default), minor or major",
                "",
                Watcher.HELP,
                "",
                "Examples:",
                "  sm-maven radar",
                "  sm-maven radar --transitive --since 30d",
                "  sm-maven radar --watch --interval 1h --channel team-slack",
                "  sm-maven radar com.acme:acme-utils:1.2.0 --json");
    }

    @Override
    public Set<String> flags() { return Set.of("transitive", "pre"); }

    /** One dependency's view in the current cycle (for human output). */
    private static final class Row {
        ReleaseSupport.Dep dep;
        List<Map<String, Object>> newer = new ArrayList<>();
    }

    @Override
    public int run(Ctx ctx, Args args) throws Exception {
        boolean transitive = args.flag("transitive");
        boolean pre = args.flag("pre");
        long since = args.has("since") ? args.getDuration("since", 0) : 0;
        String minJump = args.get("min-jump", "patch").toLowerCase(java.util.Locale.ROOT);
        int minRank = jumpRank(minJump);
        if (minRank < 0) throw new UsageException("--min-jump expects patch, minor or major, got '" + minJump + "'");
        if (args.positionals().size() > 1) throw new UsageException("radar takes at most one coordinate, got " + args.positionals());

        ctx.live(0);
        Ctx.Target target = ctx.target(args, 0);
        String scope = ReleaseSupport.scope(target);
        List<ReleaseSupport.Dep> deps = ReleaseSupport.dependencies(ctx, target, transitive);
        List<Row> rows = new ArrayList<>();
        int[] upToDate = new int[1];

        Watcher.Cycle cycle = c -> {
            if (c > 1) ctx.live(0);
            rows.clear();
            ctx.ui.progress("Checking " + deps.size() + " dependencies for new releases...");
            List<Http.Result<Row>> res = ctx.http.parallel(deps, d -> check(ctx, d, pre, since, minRank));
            ctx.ui.progressDone();
            List<Watcher.Finding> findings = new ArrayList<>();
            upToDate[0] = 0;
            for (int i = 0; i < res.size(); i++) {
                Http.Result<Row> r = res.get(i);
                if (!r.ok()) {
                    ctx.ui.warnErr("could not check " + deps.get(i).ga() + ": " + r.error.getMessage());
                    continue;
                }
                Row row = r.value;
                if (row.newer.isEmpty()) {
                    upToDate[0]++;
                    continue;
                }
                rows.add(row);
                for (Map<String, Object> v : row.newer) {
                    String key = row.dep.ga() + ":" + v.get("version") + "@" + row.dep.node.version;
                    String jump = (String) v.get("jump");
                    String sev = "major".equals(jump) ? "medium" : "minor".equals(jump) ? "low" : "info";
                    String when = v.get("releasedAt") == null ? "not indexed yet" : "released " + String.valueOf(v.get("releasedAt")).substring(0, 10);
                    String line = row.dep.ga() + " " + row.dep.node.version + " -> " + v.get("version") + " (" + jump + ", " + when + ")";
                    findings.add(new Watcher.Finding(key, sev, line, v));
                }
            }
            rows.sort(Comparator.comparingInt((Row r) -> -jumpRank((String) r.newer.get(r.newer.size() - 1).get("jump")))
                    .thenComparing(r -> r.dep.ga()));
            return findings;
        };

        Watcher.Printer printer = (all, fresh, c, baseline) -> print(ctx.ui, target, deps.size(), transitive, since > 0 || minRank > 1, rows, upToDate[0], all, fresh, c, baseline);
        return Watcher.run(ctx, args, name(), scope, "releases", cycle, printer);
    }

    private static int jumpRank(String j) {
        switch (j == null ? "" : j) {
            case "major": return 3;
            case "minor": return 2;
            case "patch": return 1;
            case "other": return 0;
            default: return -1;
        }
    }

    /** Newer releases of one dependency, oldest first. */
    private static Row check(Ctx ctx, ReleaseSupport.Dep d, boolean pre, long since, int minRank) throws Exception {
        Row row = new Row();
        row.dep = d;
        String g = d.node.groupId, a = d.node.artifactId, cur = d.node.version;
        MavenVersion current = MavenVersion.of(cur);
        boolean allowPre = pre || current.isPreRelease();
        List<String> versions = ctx.versions(g, a, !allowPre);
        List<String> newer = new ArrayList<>();
        for (String v : versions) if (MavenVersion.of(v).compareTo(current) > 0) newer.add(v);
        if (newer.isEmpty()) return row;
        Map<String, Long> times = ReleaseSupport.releaseTimes(ctx, g, a);
        String newest = newer.get(newer.size() - 1);
        long now = System.currentTimeMillis();
        for (String v : newer) {
            MavenVersion mv = MavenVersion.of(v);
            String jump = current.jumpTo(mv);
            if (jumpRank(jump) < minRank && minRank > 1) continue;
            long ts = times.getOrDefault(v, 0L);
            // Versions missing from the search index were published minutes ago: always inside --since.
            if (since > 0 && ts > 0 && now - ts > since) continue;
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("groupId", g);
            m.put("artifactId", a);
            m.put("current", cur);
            m.put("version", v);
            m.put("newest", v.equals(newest));
            m.put("jump", jump);
            m.put("preRelease", mv.isPreRelease());
            m.put("releasedAt", ReleaseSupport.iso(ts));
            m.put("ageDays", ReleaseSupport.ageDays(ts));
            m.put("scope", d.node.scope);
            m.put("direct", d.direct);
            m.put("modules", new ArrayList<>(d.modules));
            m.put("relocatedFrom", d.node.relocatedFrom);
            row.newer.add(m);
        }
        return row;
    }

    private static void print(Ui ui, Ctx.Target target, int checked, boolean transitive, boolean filtered, List<Row> rows, int upToDate,
                              List<Watcher.Finding> all, Set<String> fresh, int cycle, boolean baseline) {
        if (cycle == 1) {
            ui.title("Release Radar  " + ui.dim(target.label));
            ui.note("  " + Ui.plural(checked, (transitive ? "" : "direct ") + "dependency", (transitive ? "" : "direct ") + "dependencies")
                    + " checked against live repository metadata");
        } else {
            ui.println();
            ui.title("Release Radar  " + ui.dim("check #" + cycle + " at " + java.time.Instant.now().toString().substring(11, 19) + " UTC"));
        }
        if (!rows.isEmpty()) {
            Ui.Table t = new Ui.Table("Dependency", "Current", "Latest", "Jump", "Released", "Age", "Newer", "");
            t.rightAlign(6);
            for (Row r : rows) {
                Map<String, Object> latest = r.newer.get(r.newer.size() - 1);
                String jump = (String) latest.get("jump");
                String j = "major".equals(jump) ? ui.red(jump) : "minor".equals(jump) ? ui.yellow(jump) : ui.green(jump);
                Object ts = latest.get("releasedAt");
                Long age = (Long) latest.get("ageDays");
                boolean isNew = false;
                for (Map<String, Object> v : r.newer) {
                    if (fresh.contains(r.dep.ga() + ":" + v.get("version") + "@" + r.dep.node.version)) isNew = true;
                }
                String label = r.dep.ga() + (r.dep.direct ? "" : ui.dim(" (transitive)"));
                t.row(label, r.dep.node.version, ui.bold(String.valueOf(latest.get("version"))), j,
                        ts == null ? ui.yellow("just now") : String.valueOf(ts).substring(0, 10),
                        age == null ? "—" : age == 0 ? "today" : Ui.plural(age, "day"),
                        r.newer.size(), isNew && fresh.size() < all.size() ? ui.cyan("NEW") : "");
            }
            ui.table(t);
        }
        boolean firstRun = !all.isEmpty() && fresh.size() == all.size();
        if (!fresh.isEmpty() && !firstRun && !baseline) {
            ui.section("New since the last check (" + fresh.size() + ")");
            for (Watcher.Finding f : all) if (fresh.contains(f.key)) ui.line(ui.info() + " " + f.line);
        }
        ui.println();
        if (rows.isEmpty()) ui.good(filtered ? "No releases match the filters" : "Every checked dependency is on its newest release");
        else {
            long majors = rows.stream().filter(r -> "major".equals(r.newer.get(r.newer.size() - 1).get("jump"))).count();
            ui.warn(Ui.plural(rows.size(), "dependency has", "dependencies have") + " newer releases (" + all.size() + " versions"
                    + (majors > 0 ? ", " + majors + " with a major jump" : "") + "); " + upToDate
                    + (filtered ? " without releases matching the filters" : " up to date"));
        }
        if (baseline) ui.note("Baseline recorded: these versions will not alert again.");
        else if (firstRun) ui.note("First check: " + Ui.plural(all.size(), "version") + " recorded; later runs report only new releases.");
        else if (fresh.isEmpty()) ui.note("No new releases since the last check.");
        if (!transitive && cycle == 1) ui.note("Add --transitive to include transitive dependencies, --pre for pre-releases.");
    }
}
