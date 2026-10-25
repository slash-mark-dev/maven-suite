package in.slashmark.maven.tools;

import in.slashmark.maven.cli.Args;
import in.slashmark.maven.cli.Command;
import in.slashmark.maven.cli.Ctx;
import in.slashmark.maven.cli.Exit;
import in.slashmark.maven.cli.Ui;
import in.slashmark.maven.cli.UsageException;
import in.slashmark.maven.data.DepsDev;
import in.slashmark.maven.model.Gav;
import in.slashmark.maven.model.MavenVersion;
import in.slashmark.maven.util.Http;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Ecosystem Adoption Tracker: How the ecosystem is distributed across versions. */
public final class Adoption extends Command {
    @Override public String name() { return "adoption"; }
    @Override public String title() { return "Ecosystem Adoption Tracker"; }
    @Override public String group() { return "Release intelligence"; }
    @Override public String summary() { return "How the ecosystem is distributed across versions"; }

    @Override
    public String help() {
        return String.join("\n",
                "Usage: sm-maven adoption [group:artifact[:version]] [options]",
                "",
                summary() + ".",
                "For one artifact (or every direct dependency of the project) it counts the packages",
                "depending on each recent version (deps.dev dependents),",
                "shows the share already on the newest release and recommends whether moving is safe:",
                "  up-to-date  you already use the newest release",
                "  safe        the newest release is broadly adopted (share >= --safe-share, default 20%)",
                "  caution     some adoption, but most of the ecosystem has not moved yet",
                "  wait        almost nobody uses it yet, or it is younger than --min-age days",
                "When the newest release is not safe yet, the most adopted newer version is suggested instead.",
                "",
                "Options:",
                "  --versions <n>         Recent versions to compare per artifact (default 8)",
                "  --safe-share <pct>     Share of dependents that makes a release 'safe' (default 20%)",
                "  --min-age <days>       Releases younger than this are 'wait' unless already safe (default 14)",
                "  --transitive           With a project: include transitive dependencies",
                "",
                "Examples:",
                "  sm-maven adoption",
                "  sm-maven adoption com.acme:acme-core",
                "  sm-maven adoption com.google.guava:guava:31.1-jre --versions 5 --json");
    }

    @Override
    public Set<String> flags() { return Set.of("transitive"); }

    /** Adoption of one artifact. */
    static final class Report {
        String groupId, artifactId, current, newest, mostAdopted, recommended, verdict, reason;
        boolean direct;
        long total;
        double newestShare = -1, currentShare = -1;
        final List<Map<String, Object>> versions = new ArrayList<>();
    }

    @Override
    public int run(Ctx ctx, Args args) throws Exception {
        int maxVersions = args.getInt("versions", 8);
        if (maxVersions < 1) throw new UsageException("--versions must be at least 1");
        double safeShare = args.getDouble("safe-share", 0.20);
        if (safeShare > 1) safeShare = safeShare / 100.0;
        if (safeShare <= 0 || safeShare > 1) throw new UsageException("--safe-share must be between 0 and 100%");
        int minAge = args.getInt("min-age", 14);
        boolean transitive = args.flag("transitive");
        if (args.positionals().size() > 1) throw new UsageException("adoption takes at most one coordinate, got " + args.positionals());

        List<String[]> todo = new ArrayList<>();  // g, a, current (nullable), direct
        String label;
        String p = args.pos(0);
        if (p != null) {
            Gav g = ReleaseSupport.parseGav(p);
            if (ctx.repos.metadata(g.groupId, g.artifactId) == null) throw new UsageException(g.ga() + " was not found on " + ctx.repos.remotes().get(0).url);
            String cur = g.version;
            if (cur == null && ctx.hasProject()) {
                // Use the version the local project resolves, when it has this dependency.
                try {
                    Ctx.Target t = ctx.target(args, 1);
                    for (ReleaseSupport.Dep d : ReleaseSupport.dependencies(ctx, t, true)) if (d.ga().equals(g.ga())) { cur = d.node.version; break; }
                } catch (UsageException | java.io.IOException | in.slashmark.maven.util.HttpException e) {
                    ctx.ui.debug("project not used: " + e.getMessage());
                }
            }
            todo.add(new String[] {g.groupId, g.artifactId, cur, "true"});
            label = g.ga();
        } else {
            Ctx.Target t = ctx.target(args, 0);
            label = t.label;
            for (ReleaseSupport.Dep d : ReleaseSupport.dependencies(ctx, t, transitive)) {
                todo.add(new String[] {d.node.groupId, d.node.artifactId, d.node.version, String.valueOf(d.direct)});
            }
        }
        final double safe = safeShare;
        ctx.ui.progress("Counting dependents on deps.dev for " + Ui.plural(todo.size(), "artifact") + "...");
        List<Http.Result<Report>> res = ctx.http.parallel(todo, x -> analyse(ctx, x, maxVersions, safe, minAge));
        ctx.ui.progressDone();
        List<Report> reports = new ArrayList<>();
        for (int i = 0; i < res.size(); i++) {
            if (res.get(i).ok()) reports.add(res.get(i).value);
            else ctx.ui.warnErr("could not check " + todo.get(i)[0] + ":" + todo.get(i)[1] + ": " + res.get(i).error.getMessage());
        }

        if (ctx.ui.json) {
            List<Object> list = new ArrayList<>();
            for (Report r : reports) list.add(toJson(r));
            ctx.ui.emitJson(ReleaseSupport.o("tool", name(), "target", label, "safeShare", safe, "minAgeDays", minAge, "artifacts", list));
            return Exit.OK;
        }
        print(ctx.ui, label, reports, safe);
        return Exit.OK;
    }

    static Report analyse(Ctx ctx, String[] x, int maxVersions, double safeShare, int minAge) throws Exception {
        Report r = new Report();
        r.groupId = x[0];
        r.artifactId = x[1];
        r.current = x[2];
        r.direct = Boolean.parseBoolean(x[3]);
        String ga = r.groupId + ":" + r.artifactId;
        List<String> all = ctx.versions(r.groupId, r.artifactId, true);
        if (r.current != null && MavenVersion.of(r.current).isPreRelease()) all = ctx.versions(r.groupId, r.artifactId, false);
        List<String> pick = new ArrayList<>(all.subList(Math.max(0, all.size() - maxVersions), all.size()));
        if (r.current != null && !pick.contains(r.current)) {
            pick.add(r.current);
            pick.sort(MavenVersion::compare);
        }
        if (pick.isEmpty()) {
            r.verdict = "no-data";
            r.reason = "no releases published";
            return r;
        }
        r.newest = all.isEmpty() ? pick.get(pick.size() - 1) : all.get(all.size() - 1);
        Map<String, Long> times = ReleaseSupport.releaseTimes(ctx, r.groupId, r.artifactId);
        List<DepsDev.Dependents> counts = new ArrayList<>();
        for (String v : pick) counts.add(ctx.depsDev.dependents(ga, v));
        long total = 0;
        for (DepsDev.Dependents d : counts) if (d != null) total += d.total;
        r.total = total;
        long best = -1;
        for (int i = 0; i < pick.size(); i++) {
            String v = pick.get(i);
            DepsDev.Dependents d = counts.get(i);
            long n = d == null ? 0 : d.total;
            double share = total > 0 ? (double) n / total : 0;
            long ts = times.getOrDefault(v, 0L);
            if (n > best) {
                best = n;
                r.mostAdopted = v;
            }
            if (v.equals(r.newest)) r.newestShare = share;
            if (v.equals(r.current)) r.currentShare = share;
            r.versions.add(ReleaseSupport.o("version", v, "dependents", n, "directDependents", d == null ? 0 : d.direct,
                    "share", round(share), "releasedAt", ReleaseSupport.iso(ts), "ageDays", ReleaseSupport.ageDays(ts),
                    "current", v.equals(r.current), "newest", v.equals(r.newest)));
        }
        if (r.current != null && MavenVersion.compare(r.current, r.newest) >= 0) {
            r.verdict = "up-to-date";
            r.recommended = r.current;
            r.reason = "already on the newest release" + (total > 0 ? " (" + pct(r.newestShare) + " of dependents)" : "");
            if (total == 0) r.mostAdopted = null;
            return r;
        }
        if (total == 0) {
            r.verdict = "no-data";
            r.mostAdopted = null;
            r.reason = "deps.dev reports no dependents for these versions";
            return r;
        }
        long newestTs = times.getOrDefault(r.newest, 0L);
        Long newestAge = ReleaseSupport.ageDays(newestTs);
        String pct = pct(r.newestShare);
        if (r.newestShare >= safeShare) {
            r.verdict = "safe";
            r.recommended = r.newest;
            r.reason = pct + " of dependents already use " + r.newest;
        } else {
            boolean young = newestAge != null && newestAge < minAge;
            r.verdict = young || r.newestShare < safeShare / 4 ? "wait" : "caution";
            r.reason = "only " + pct + " of dependents use " + r.newest + (newestAge != null ? " (released " + Ui.plural(newestAge, "day") + " ago)" : "");
            // Suggest the most adopted version newer than what is used today.
            String alt = null;
            long altN = -1;
            for (Map<String, Object> v : r.versions) {
                String ver = (String) v.get("version");
                if (r.current != null && MavenVersion.compare(ver, r.current) <= 0) continue;
                long n = (Long) v.get("dependents");
                if ((double) n / total >= safeShare && n > altN) {
                    alt = ver;
                    altN = n;
                }
            }
            if (alt != null && !alt.equals(r.newest)) {
                r.recommended = alt;
                r.reason += "; " + alt + " is the proven step (" + pct((double) altN / total) + ")";
            } else if (r.current != null) {
                r.reason += "; stay on " + r.current + " for now";
            }
        }
        return r;
    }

    static double round(double d) { return Math.round(d * 10000) / 10000.0; }

    static String pct(double d) { return String.format(Locale.ROOT, "%.1f%%", d * 100); }

    static Map<String, Object> toJson(Report r) {
        return ReleaseSupport.o("groupId", r.groupId, "artifactId", r.artifactId, "current", r.current, "direct", r.direct,
                "newest", r.newest, "newestShare", r.newestShare >= 0 ? round(r.newestShare) : null,
                "currentShare", r.currentShare >= 0 ? round(r.currentShare) : null, "mostAdopted", r.mostAdopted,
                "totalDependents", r.total, "verdict", r.verdict, "recommended", r.recommended, "reason", r.reason, "versions", r.versions);
    }

    private static String verdict(Ui ui, String v) {
        switch (v) {
            case "up-to-date": return ui.green("up to date");
            case "safe": return ui.green("safe to move");
            case "caution": return ui.yellow("caution");
            case "wait": return ui.red("wait");
            default: return ui.dim("no data");
        }
    }

    private static void print(Ui ui, String label, List<Report> reports, double safeShare) {
        ui.title("Ecosystem Adoption  " + ui.dim(label));
        ui.note("  dependents per version from deps.dev; 'safe' means >= " + pct(safeShare) + " of dependents moved");
        if (reports.size() == 1) {
            Report r = reports.get(0);
            ui.println();
            Ui.Table t = new Ui.Table("Version", "Released", "Dependents", "Share", "", "");
            t.rightAlign(2, 3);
            for (Map<String, Object> v : r.versions) {
                double share = (Double) v.get("share");
                Object rel = v.get("releasedAt");
                String tag = Boolean.TRUE.equals(v.get("current")) ? ui.cyan("← you") : "";
                if (Boolean.TRUE.equals(v.get("newest"))) tag += (tag.isEmpty() ? "" : " ") + ui.bold("newest");
                if (v.get("version").equals(r.mostAdopted)) tag += (tag.isEmpty() ? "" : " ") + ui.dim("most used");
                t.row(v.get("version"), rel == null ? "—" : String.valueOf(rel).substring(0, 10), String.format(Locale.ROOT, "%,d", (Long) v.get("dependents")),
                        pct(share), ui.bar(share * 100, 100, 20), tag);
            }
            ui.table(t);
            ui.println();
            line(ui, r);
            return;
        }
        ui.println();
        Ui.Table t = new Ui.Table("Dependency", "Current", "Newest", "On newest", "Most used", "Verdict", "Recommended");
        t.rightAlign(3);
        for (Report r : reports) {
            t.row(r.groupId + ":" + r.artifactId, r.current == null ? "—" : r.current, r.newest == null ? "—" : r.newest,
                    r.newestShare >= 0 && r.total > 0 ? pct(r.newestShare) : "—", r.mostAdopted == null ? "—" : r.mostAdopted,
                    verdict(ui, r.verdict), r.recommended == null ? "—" : r.recommended);
        }
        ui.table(t);
        ui.println();
        int safe = 0, wait = 0;
        for (Report r : reports) {
            if (r.verdict.equals("safe")) safe++;
            if (r.verdict.equals("wait") || r.verdict.equals("caution")) {
                wait++;
                line(ui, r);
            }
        }
        if (safe > 0) ui.good(Ui.plural(safe, "dependency can", "dependencies can") + " move to the newest release with the ecosystem");
        if (wait == 0 && safe == 0) ui.good("Nothing to move: every dependency is up to date or has no adoption data");
    }

    private static void line(Ui ui, Report r) {
        String ga = r.groupId + ":" + r.artifactId;
        String msg = ga + ": " + verdict(ui, r.verdict) + " - " + r.reason;
        switch (r.verdict) {
            case "safe": case "up-to-date": ui.good(msg); break;
            case "caution": case "wait": ui.warn(msg); break;
            default: ui.note(msg);
        }
        if (("wait".equals(r.verdict) || "caution".equals(r.verdict)) && r.recommended != null) ui.line(ui.arrow() + " move to " + ga + ":" + r.recommended + " for now");
    }
}
