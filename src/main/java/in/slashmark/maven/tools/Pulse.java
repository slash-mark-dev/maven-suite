package in.slashmark.maven.tools;

import in.slashmark.maven.cli.Args;
import in.slashmark.maven.cli.Command;
import in.slashmark.maven.cli.Ctx;
import in.slashmark.maven.cli.Exit;
import in.slashmark.maven.cli.Ui;
import in.slashmark.maven.cli.UsageException;
import in.slashmark.maven.data.DepsDev;
import in.slashmark.maven.model.MavenVersion;
import in.slashmark.maven.util.Http;
import in.slashmark.maven.util.HttpException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Project Pulse: Maintenance health and abandonment risk of every dependency. */
public final class Pulse extends Command {
    @Override public String name() { return "pulse"; }
    @Override public String title() { return "Project Pulse"; }
    @Override public String group() { return "Release intelligence"; }
    @Override public String summary() { return "Maintenance health and abandonment risk of every dependency"; }

    @Override
    public String help() {
        return String.join("\n",
                "Usage: sm-maven pulse [group:artifact[:version]] [options]",
                "",
                summary() + ".",
                "For each dependency it measures the release cadence on Maven Central (median days",
                "between releases, age of the last release), the",
                "source repository's activity on GitHub (archived flag, commits and contributors in the last",
                "90 days) and the OpenSSF Scorecard from deps.dev, and turns them into an abandonment risk",
                "score (0-100, low/medium/high) with the reasons.",
                "",
                "Options:",
                "  --transitive           Include transitive dependencies (default: direct ones only)",
                "  --fail-on <level>      Exit 1 when a dependency reaches this risk: high (default), medium, low, none",
                "  --no-github            Skip GitHub activity checks (release cadence and Scorecard only)",
                "  -n, --limit <n>        Only show the n riskiest dependencies",
                "",
                "Examples:",
                "  sm-maven pulse",
                "  sm-maven pulse --transitive --fail-on medium",
                "  sm-maven pulse com.acme:acme-utils:1.2.0 --json");
    }

    @Override
    public Set<String> flags() { return Set.of("transitive", "no-github"); }

    static int levelRank(String l) {
        switch (l) {
            case "high": return 3;
            case "medium": return 2;
            case "low": return 1;
            case "none": return 99;
            default: return -1;
        }
    }

    /** Health of one dependency. */
    static final class Health {
        ReleaseSupport.Dep dep;
        int releaseCount;
        int releasesLastYear;
        Long medianDays;
        long lastRelease;
        String lastVersion;
        String latest;
        ReleaseSupport.RepoInfo repo;
        double scorecard = -1;
        int maintainedCheck = -1;
        String scorecardDate;
        int score;
        String level;
        final List<String> reasons = new ArrayList<>();
        final List<String> notes = new ArrayList<>();
    }

    @Override
    public int run(Ctx ctx, Args args) throws Exception {
        boolean transitive = args.flag("transitive");
        boolean github = !args.flag("no-github");
        String failOn = args.get("fail-on", "high").toLowerCase(Locale.ROOT);
        if (levelRank(failOn) < 0) throw new UsageException("--fail-on expects high, medium, low or none, got '" + failOn + "'");
        int limit = args.getInt("limit", 0);
        if (limit < 0) throw new UsageException("--limit must be positive");
        if (args.positionals().size() > 1) throw new UsageException("pulse takes at most one coordinate, got " + args.positionals());

        Ctx.Target target = ctx.target(args, 0);
        List<ReleaseSupport.Dep> deps = ReleaseSupport.dependencies(ctx, target, transitive);
        ctx.ui.progress("Measuring the pulse of " + Ui.plural(deps.size(), "dependency", "dependencies") + "...");
        List<Http.Result<Health>> res = ctx.http.parallel(deps, d -> assess(ctx, d, github));
        ctx.ui.progressDone();
        List<Health> all = new ArrayList<>();
        for (int i = 0; i < res.size(); i++) {
            Http.Result<Health> r = res.get(i);
            if (r.ok()) all.add(r.value);
            else ctx.ui.warnErr("could not assess " + deps.get(i).ga() + ": " + r.error.getMessage());
        }
        all.sort(Comparator.comparingInt((Health h) -> -h.score).thenComparing(h -> h.dep.ga()));
        List<Health> shown = limit > 0 && all.size() > limit ? all.subList(0, limit) : all;

        int high = 0, medium = 0, low = 0;
        for (Health h : all) {
            if (h.level.equals("high")) high++;
            else if (h.level.equals("medium")) medium++;
            else low++;
        }
        int worst = 0;
        for (Health h : all) worst = Math.max(worst, levelRank(h.level));
        int exit = worst >= levelRank(failOn) ? Exit.ISSUES : Exit.OK;

        if (ctx.ui.json) {
            List<Object> list = new ArrayList<>();
            for (Health h : shown) list.add(toJson(h));
            ctx.ui.emitJson(ReleaseSupport.o("tool", name(), "target", target.label, "transitive", transitive,
                    "summary", ReleaseSupport.o("total", all.size(), "high", high, "medium", medium, "low", low),
                    "failOn", failOn, "dependencies", list));
            return exit;
        }
        print(ctx.ui, target, shown, all.size(), high, medium, low, github, transitive);
        return exit;
    }

    static Health assess(Ctx ctx, ReleaseSupport.Dep d, boolean github) throws HttpException {
        Health h = new Health();
        h.dep = d;
        long now = System.currentTimeMillis();
        // Release cadence from Central search (final releases only).
        Map<String, Long> times = ReleaseSupport.releaseTimes(ctx, d.node.groupId, d.node.artifactId);
        List<long[]> stable = new ArrayList<>();
        Map<Long, String> byTime = new LinkedHashMap<>();
        for (Map.Entry<String, Long> e : times.entrySet()) {
            MavenVersion mv = MavenVersion.of(e.getKey());
            if (mv.isSnapshot() || mv.isPreRelease()) continue;
            stable.add(new long[] {e.getValue()});
            byTime.put(e.getValue(), e.getKey());
            if (h.latest == null || mv.compareTo(MavenVersion.of(h.latest)) > 0) h.latest = e.getKey();
        }
        stable.sort(Comparator.comparingLong(x -> x[0]));
        h.releaseCount = stable.size();
        if (!stable.isEmpty()) {
            h.lastRelease = stable.get(stable.size() - 1)[0];
            h.lastVersion = byTime.get(h.lastRelease);
        }
        List<Long> gaps = new ArrayList<>();
        for (int i = 1; i < stable.size(); i++) gaps.add((stable.get(i)[0] - stable.get(i - 1)[0]) / ReleaseSupport.DAY);
        for (long[] t : stable) if (now - t[0] <= 365 * ReleaseSupport.DAY) h.releasesLastYear++;
        if (!gaps.isEmpty()) {
            gaps.sort(null);
            int n = gaps.size();
            h.medianDays = n % 2 == 1 ? gaps.get(n / 2) : (gaps.get(n / 2 - 1) + gaps.get(n / 2)) / 2;
        }

        // Source repository, GitHub activity, Scorecard.
        h.repo = ReleaseSupport.sourceRepo(ctx, d.gav());
        if (github) ReleaseSupport.github(ctx, h.repo);
        if (h.repo.projectId != null) {
            try {
                DepsDev.Project p = ctx.depsDev.project(h.repo.projectId);
                if (p != null && p.scorecard >= 0) {
                    h.scorecard = p.scorecard;
                    h.scorecardDate = p.scorecardDate;
                    for (String[] c : p.checks) {
                        if ("Maintained".equals(c[0])) {
                            try { h.maintainedCheck = (int) Double.parseDouble(c[1]); } catch (NumberFormatException ignored) {}
                        }
                    }
                }
            } catch (HttpException e) {
                h.notes.add("deps.dev project lookup failed: " + e.getMessage());
            }
        }
        if (h.repo.error != null) h.notes.add(h.repo.error);
        score(h, now);
        return h;
    }

    /** Abandonment risk: weighted signals, capped at 100. */
    static void score(Health h, long now) {
        int s = 0;
        ReleaseSupport.RepoInfo r = h.repo;
        if (r.found && r.archived) {
            s += 50;
            h.reasons.add("GitHub repository " + r.repo + " is archived (read-only, no further fixes)");
        }
        if (r.checked && !r.found) {
            s += 20;
            h.reasons.add("source repository " + r.repo + " no longer exists on GitHub");
        }
        if (r.found && r.commits90d == 0) {
            s += 20;
            h.reasons.add("no commits in the last 90 days" + (r.pushedAt > 0 ? " (last push " + Ui.ago(r.pushedAt) + ")" : ""));
        } else if (r.found && r.contributors90d == 1) {
            s += 5;
            h.reasons.add("a single active contributor in the last 90 days (bus factor 1)");
        }
        if (r.repo == null) {
            s += 10;
            h.reasons.add("no source repository linked from deps.dev or the POM (activity cannot be checked)");
        }
        if (!r.checked && h.maintainedCheck == 0) {
            s += 15;
            h.reasons.add("OpenSSF Scorecard 'Maintained' check scored 0/10");
        }
        long lastDays = h.lastRelease > 0 ? (now - h.lastRelease) / ReleaseSupport.DAY : -1;
        if (lastDays > 730) {
            s += 20;
            h.reasons.add(String.format(Locale.ROOT, "last release %s was %.1f years ago", h.lastVersion, lastDays / 365.0));
        } else if (lastDays > 365) {
            s += 10;
            h.reasons.add("no release for " + lastDays + " days (last: " + h.lastVersion + ")");
        }
        if (h.medianDays != null && lastDays > 180 && lastDays > 2 * Math.max(1, h.medianDays)) {
            s += 10;
            h.reasons.add("release overdue: " + lastDays + " days since the last one vs a usual cadence of " + h.medianDays + " days");
        }
        if (h.scorecard >= 0 && h.scorecard < 4) {
            s += 10;
            h.reasons.add(String.format(Locale.ROOT, "low OpenSSF Scorecard %.1f/10", h.scorecard));
        }
        h.score = Math.min(100, s);
        h.level = h.score >= 50 ? "high" : h.score >= 25 ? "medium" : "low";
    }

    static Map<String, Object> toJson(Health h) {
        ReleaseSupport.RepoInfo r = h.repo;
        return ReleaseSupport.o(
                "groupId", h.dep.node.groupId,
                "artifactId", h.dep.node.artifactId,
                "version", h.dep.node.version,
                "scope", h.dep.node.scope,
                "direct", h.dep.direct,
                "modules", new ArrayList<>(h.dep.modules),
                "releases", ReleaseSupport.o("count", h.releaseCount, "lastYear", h.releasesLastYear, "medianDaysBetween", h.medianDays,
                        "latest", h.latest, "lastVersion", h.lastVersion, "lastReleasedAt", ReleaseSupport.iso(h.lastRelease),
                        "lastReleaseDays", ReleaseSupport.ageDays(h.lastRelease)),
                "repository", ReleaseSupport.o("github", r.repo, "checked", r.checked, "found", r.checked ? r.found : null,
                        "archived", r.found ? r.archived : null, "pushedAt", ReleaseSupport.iso(r.pushedAt),
                        "commits90d", r.commits90d >= 0 ? r.commits90d : null, "contributors90d", r.contributors90d >= 0 ? r.contributors90d : null),
                "scorecard", h.scorecard >= 0 ? ReleaseSupport.o("score", h.scorecard, "maintained", h.maintainedCheck >= 0 ? h.maintainedCheck : null,
                        "date", h.scorecardDate, "project", r.projectId) : null,
                "risk", ReleaseSupport.o("score", h.score, "level", h.level, "reasons", h.reasons),
                "notes", h.notes);
    }

    private static void print(Ui ui, Ctx.Target target, List<Health> shown, int total, int high, int medium, int low, boolean github, boolean transitive) {
        ui.title("Project Pulse  " + ui.dim(target.label));
        ui.note("  " + Ui.plural(total, transitive ? "dependency" : "direct dependency", transitive ? "dependencies" : "direct dependencies")
                + ": release cadence (Central), activity (GitHub), OpenSSF Scorecard (deps.dev)");
        ui.println();
        Ui.Table t = new Ui.Table("Dependency", "Version", "Releases", "Cadence", "Last release", "Commits 90d", "Scorecard", "Risk");
        t.rightAlign(2, 5, 6);
        for (Health h : shown) {
            ReleaseSupport.RepoInfo r = h.repo;
            String commits = !github ? ui.dim("skipped") : r.repo == null ? ui.dim("no repo") : !r.checked ? ui.dim("?")
                    : !r.found ? ui.red("missing") : r.archived ? ui.red("archived") : r.commits90d == 0 ? ui.yellow("0") : String.valueOf(r.commits90d);
            String risk = h.level.equals("high") ? ui.red("HIGH " + h.score) : h.level.equals("medium") ? ui.yellow("MEDIUM " + h.score) : ui.green("low " + h.score);
            t.row(h.dep.ga(), h.dep.node.version, h.releaseCount,
                    h.medianDays == null ? "—" : "every " + h.medianDays + "d",
                    h.lastRelease > 0 ? Ui.ago(h.lastRelease) : "—",
                    commits,
                    h.scorecard >= 0 ? String.format(Locale.ROOT, "%.1f", h.scorecard) : "—",
                    risk);
        }
        ui.table(t);
        boolean any = false;
        for (Health h : shown) {
            if (h.level.equals("low") || h.reasons.isEmpty()) continue;
            if (!any) ui.section("Why");
            any = true;
            ui.println((h.level.equals("high") ? ui.bad() : ui.warnMark()) + " " + ui.bold(h.dep.ga() + ":" + h.dep.node.version)
                    + "  " + h.level + " risk (" + h.score + "/100)");
            for (String reason : h.reasons) ui.line(ui.dot() + " " + reason);
        }
        ui.println();
        if (high > 0) ui.fail(Ui.plural(high, "dependency looks", "dependencies look") + " abandoned; plan a replacement or fork");
        if (medium > 0) ui.warn(Ui.plural(medium, "dependency shows", "dependencies show") + " weak maintenance signals");
        if (high == 0 && medium == 0) ui.good("All " + Ui.plural(low, "dependency is", "dependencies are") + " actively maintained");
        if (!github) ui.note("GitHub checks were skipped (--no-github).");
    }
}
