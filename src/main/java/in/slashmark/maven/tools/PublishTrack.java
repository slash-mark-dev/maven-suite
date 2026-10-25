package in.slashmark.maven.tools;

import in.slashmark.maven.cli.Args;
import in.slashmark.maven.cli.Command;
import in.slashmark.maven.cli.Ctx;
import in.slashmark.maven.cli.Exit;
import in.slashmark.maven.cli.Project;
import in.slashmark.maven.cli.Ui;
import in.slashmark.maven.cli.UsageException;
import in.slashmark.maven.data.CentralSearch;
import in.slashmark.maven.model.Gav;
import in.slashmark.maven.model.Pom;
import in.slashmark.maven.repo.Metadata;
import in.slashmark.maven.util.Hash;
import in.slashmark.maven.util.Http;
import in.slashmark.maven.util.HttpException;
import in.slashmark.maven.watch.Alerts;
import in.slashmark.maven.watch.State;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Publish Tracker: Follow a release from upload to Central, search index and javadoc.io. */
public final class PublishTrack extends Command {
    @Override public String name() { return "publish-track"; }
    @Override public String title() { return "Publish Tracker"; }
    @Override public String group() { return "Operations"; }
    @Override public String summary() { return "Follow a release from upload to Central, search index and javadoc.io"; }

    @Override
    public Set<String> flags() { return Set.of("wait", "notify"); }

    static final List<String> STAGES = List.of("artifact", "metadata", "search", "javadoc");

    @Override
    public String help() {
        return String.join("\n",
                "Usage: sm-maven publish-track [group:artifact:version ...] [options]",
                "",
                summary() + ".",
                "Follows a release through the stages of Maven Central publishing and shows when each one turned green:",
                "  artifact   the files are on the repository (repo1): pom, main artifact, -sources and -javadoc jars,",
                "             .asc signatures and .md5/.sha1 checksums (the POM checksum is verified)",
                "  metadata   maven-metadata.xml lists the version (what Maven and Gradle use to find it)",
                "  search     the Central search index (search.maven.org) has it",
                "  javadoc    javadoc.io serves its documentation (skipped for pom packaging)",
                "Without coordinates it tracks every module of the project (-f), e.g. right after mvn deploy.",
                "",
                "Options:",
                "  --wait                   Poll until every required stage is green (or --timeout), then alert",
                "  --interval <time>        Time between polls with --wait (default 60s)",
                "  --timeout <time>         Give up waiting after this long (default 2h)",
                "  --stages <list>          Stages that must be green (default: artifact,metadata,search,javadoc)",
                "  --repo <url>             Repository to check instead of Maven Central (e.g. a staging mirror)",
                "  --notify / --no-notify   Alert when done or timed out (default: with --wait, when alert channels exist)",
                "  --channel <name>         Only alert these channels (see: sm-maven alerts list)",
                "",
                "Exit codes: 0 every required stage is green, 1 still pending or failed, 2 usage error.",
                "",
                "Examples:",
                "  sm-maven publish-track in.slashmark:sm-maven-core:1.4.0",
                "  sm-maven publish-track in.slashmark:sm-maven-core:1.4.0 --wait --interval 2m --timeout 4h",
                "  sm-maven publish-track --wait --stages artifact,metadata      (the project's modules)");
    }

    static final class Stage {
        final String id, title;
        boolean required, applicable = true;
        String status = "pending"; // done | pending | failed | error | skipped
        String detail;
        long at;      // when the data source says it happened (Last-Modified, lastUpdated, index timestamp)
        long seenAt;  // when this tool first saw it green (persisted)
        final List<String> missing = new ArrayList<>();
        final List<Object> files = new ArrayList<>();

        Stage(String id, String title) {
            this.id = id;
            this.title = title;
        }

        boolean done() { return status.equals("done"); }

        Map<String, Object> toJson() {
            return OpsCommon.m("id", id, "title", title, "status", status, "required", required, "detail", detail,
                    "at", at > 0 ? Instant.ofEpochMilli(at).toString() : null,
                    "firstSeenGreen", seenAt > 0 ? Instant.ofEpochMilli(seenAt).toString() : null,
                    "missing", missing, "files", files.isEmpty() ? null : files);
        }
    }

    static final class Track {
        final Gav gav;
        String packaging;
        final List<Stage> stages = new ArrayList<>();
        State state;
        long trackingSince;

        Track(Gav gav, String packaging) {
            this.gav = gav;
            this.packaging = packaging;
        }

        boolean complete() {
            for (Stage s : stages) if (s.required && s.applicable && !s.done()) return false;
            return true;
        }

        Stage stage(String id) {
            for (Stage s : stages) if (s.id.equals(id)) return s;
            return null;
        }
    }

    @Override
    public int run(Ctx ctx, Args args) throws Exception {
        boolean wait = args.flag("wait");
        long interval = Math.max(1000, args.getDuration("interval", 60_000));
        long timeout = args.getDuration("timeout", 2 * 3_600_000L);
        List<String> required = args.has("stages") ? args.getAll("stages") : STAGES;
        for (String s : required) if (!STAGES.contains(s)) throw new UsageException("--stages expects a list of " + String.join(", ", STAGES) + ", got '" + s + "'");
        if (required.isEmpty()) throw new UsageException("--stages needs at least one stage");
        String repo = args.get("repo", ctx.repos.remotes().get(0).url);
        while (repo.endsWith("/")) repo = repo.substring(0, repo.length() - 1);
        List<String> channels = args.getAll("channel");
        Alerts alerts = ctx.alerts();
        boolean notify = args.has("notify") ? args.flag("notify") : !args.flag("no-notify") && wait && !alerts.channels().isEmpty();

        List<Track> tracks = new ArrayList<>();
        if (!args.positionals().isEmpty()) {
            for (String p : args.positionals()) {
                if (!Gav.looksLikeGav(p)) throw new UsageException("expected group:artifact:version, got '" + p + "'");
                Gav g = Gav.parse(p);
                if (g.version == null) g = ctx.resolveLatest(g);
                tracks.add(new Track(g, null));
            }
        } else {
            Project pr = ctx.project();
            for (Project.Module m : pr.modules) tracks.add(new Track(m.gav(), m.packaging()));
        }
        for (Track t : tracks) {
            t.stages.add(new Stage("artifact", "Files on " + hostOf(repo)));
            t.stages.add(new Stage("metadata", "Listed in maven-metadata.xml"));
            t.stages.add(new Stage("search", "Central search index"));
            t.stages.add(new Stage("javadoc", "javadoc.io"));
            for (Stage s : t.stages) s.required = required.contains(s.id);
            t.state = ctx.state("publish-track", repo + "|" + t.gav);
        }
        ctx.live(0);

        long start = System.currentTimeMillis();
        int poll = 0;
        boolean done;
        Map<String, String> lastStatus = new LinkedHashMap<>();
        while (true) {
            poll++;
            for (Track t : tracks) {
                ctx.ui.progress("Checking " + t.gav + "...");
                check(ctx, repo, t);
                ctx.ui.progressDone();
                long now = System.currentTimeMillis();
                Map<String, Object> seen = t.state.map("firstSeenGreen");
                for (Stage s : t.stages) {
                    if (s.done()) {
                        Object prev = seen.get(s.id);
                        if (prev == null) seen.put(s.id, Instant.ofEpochMilli(now).toString());
                        s.seenAt = prev == null ? now : parseInstant(String.valueOf(prev));
                    } else {
                        seen.remove(s.id); // retracted (e.g. a re-upload): track it again
                    }
                }
                if (t.state.data().get("trackingSince") == null) t.state.data().put("trackingSince", Instant.ofEpochMilli(now).toString());
                t.trackingSince = parseInstant(String.valueOf(t.state.data().get("trackingSince")));
                t.state.data().put("lastCheck", Instant.ofEpochMilli(now).toString());
                t.state.save();
                if (wait && !ctx.ui.json) {
                    for (Stage s : t.stages) {
                        String k = t.gav + "|" + s.id;
                        String before = lastStatus.put(k, s.status);
                        if (poll > 1 && !s.status.equals(before) && s.applicable) {
                            String msg = (tracks.size() > 1 ? t.gav + " " : "") + s.id + " " + ui(ctx.ui, s) + (s.detail == null ? "" : ctx.ui.dim("  " + s.detail));
                            if (s.done()) ctx.ui.good(msg);
                            else ctx.ui.warn(msg);
                        }
                    }
                }
            }
            done = true;
            for (Track t : tracks) if (!t.complete()) done = false;
            if (!wait || done) break;
            long elapsed = System.currentTimeMillis() - start;
            if (elapsed + interval > timeout) break;
            if (poll == 1 && !ctx.ui.json) {
                print(ctx.ui, tracks, repo);
                ctx.ui.note("waiting for " + pendingNames(tracks) + " (polling every " + (interval / 1000) + "s, timeout " + duration(timeout) + ")");
            }
            try {
                Thread.sleep(interval);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        long waited = System.currentTimeMillis() - start;
        boolean timedOut = wait && !done;

        if (ctx.ui.json) {
            List<Object> arts = new ArrayList<>();
            for (Track t : tracks) arts.add(trackJson(t));
            ctx.ui.emitJson(OpsCommon.m("tool", "publish-track", "repository", OpsCommon.safeUrl(repo), "complete", done, "timedOut", timedOut,
                    "polls", poll, "waitedSeconds", waited / 1000, "requiredStages", required, "artifacts", arts, "checkedAt", Instant.now().toString()));
        } else {
            if (wait && poll > 1) ctx.ui.println();
            print(ctx.ui, tracks, repo);
            ctx.ui.println();
            if (done) ctx.ui.good(ctx.ui.green(ctx.ui.bold("Published")) + " " + ctx.ui.dot() + " " + names(tracks) + " passed every required stage"
                    + (wait && poll > 1 ? " (waited " + duration(waited) + ")" : ""));
            else if (timedOut) ctx.ui.fail("Timed out after " + duration(waited) + ": still waiting for " + pendingNames(tracks));
            else ctx.ui.warn("Not fully published yet: waiting for " + pendingNames(tracks) + ctx.ui.dim("  (use --wait to poll until done)"));
        }

        if (notify && (done || timedOut)) {
            Alerts.Alert a = new Alerts.Alert("publish-track", done ? names(tracks) + " is live on Maven Central" : names(tracks) + " is not fully published after " + duration(waited));
            a.severity = done ? "info" : "medium";
            for (Track t : tracks) for (Stage s : t.stages) {
                if (!s.applicable) continue;
                a.line((tracks.size() > 1 ? t.gav + " " : "") + s.title + ": " + s.status + (s.detail == null ? "" : " (" + s.detail + ")"));
            }
            if (tracks.size() == 1) a.link = "https://central.sonatype.com/artifact/" + tracks.get(0).gav.groupId + "/" + tracks.get(0).gav.artifactId + "/" + tracks.get(0).gav.version;
            List<Object> data = new ArrayList<>();
            for (Track t : tracks) data.add(trackJson(t));
            a.data = data;
            for (Alerts.Delivery d : alerts.send(a, channels)) {
                if (d.ok) ctx.ui.note("  alert sent to " + d.channel);
                else ctx.ui.warnErr("alert to " + d.channel + " failed: " + d.error);
            }
        }
        return done ? Exit.OK : Exit.ISSUES;
    }

    static String hostOf(String url) {
        try {
            String h = java.net.URI.create(url).getHost();
            return h == null ? url : h;
        } catch (RuntimeException e) {
            return url;
        }
    }

    static long parseInstant(String s) {
        try {
            return Instant.parse(s).toEpochMilli();
        } catch (RuntimeException e) {
            return System.currentTimeMillis();
        }
    }

    static String duration(long ms) {
        long s = ms / 1000;
        if (s < 120) return s + "s";
        if (s < 7200) return (s / 60) + " min";
        return String.format(Locale.ROOT, "%.1f h", s / 3600.0);
    }

    private static String names(List<Track> tracks) {
        if (tracks.size() == 1) return tracks.get(0).gav.toString();
        return Ui.plural(tracks.size(), "artifact");
    }

    private static String pendingNames(List<Track> tracks) {
        List<String> l = new ArrayList<>();
        for (Track t : tracks) for (Stage s : t.stages) {
            if (s.required && s.applicable && !s.done()) l.add((tracks.size() > 1 ? t.gav.artifactId + " " : "") + s.id);
        }
        return String.join(", ", l);
    }

    // ---------------------------------------------------------------- checks

    static String extension(String packaging) {
        if (packaging == null) return "jar";
        switch (packaging) {
            case "pom": return null;
            case "war": return "war";
            case "ear": return "ear";
            case "rar": return "rar";
            case "aar": return "aar";
            default: return "jar"; // jar, bundle, maven-plugin, ejb, ...
        }
    }

    private void check(Ctx ctx, String repo, Track t) {
        Stage art = t.stage("artifact"), md = t.stage("metadata"), search = t.stage("search"), jd = t.stage("javadoc");
        String base = repo + "/" + t.gav.path() + "/" + t.gav.artifactId + "-" + t.gav.version;
        // The POM first: it tells the packaging (what other files to expect).
        try {
            checkArtifact(ctx, base, t, art);
        } catch (HttpException e) {
            art.status = "error";
            art.detail = e.getMessage();
        }
        String ext = extension(t.packaging);
        jd.applicable = ext != null && ext.equals("jar");
        if (!jd.applicable) {
            jd.status = "skipped";
            jd.detail = "not applicable to " + t.packaging + " packaging";
        }
        try {
            Http.Response r = ctx.http.get(repo + "/" + t.gav.groupId.replace('.', '/') + "/" + t.gav.artifactId + "/maven-metadata.xml", Http.NO_CACHE, null);
            md.missing.clear();
            if (r.ok()) {
                Metadata m = Metadata.parse(r.body);
                if (m.versions.contains(t.gav.version)) {
                    md.status = "done";
                    md.at = m.lastUpdatedMillis();
                    md.detail = "listed among " + Ui.plural(m.versions.size(), "version")
                            + (t.gav.version.equals(m.release) ? ", current release" : m.release != null ? ", release is " + m.release : "");
                } else {
                    md.status = "pending";
                    md.detail = "not listed yet (newest is " + (m.release != null ? m.release : m.latest) + ")";
                }
            } else if (r.status == 404) {
                md.status = "pending";
                md.detail = "no maven-metadata.xml yet";
            } else {
                md.status = "error";
                md.detail = "HTTP " + r.status;
            }
        } catch (HttpException | RuntimeException e) {
            md.status = "error";
            md.detail = e.getMessage();
        }
        try {
            CentralSearch.Result r = ctx.search.version(t.gav.groupId, t.gav.artifactId, t.gav.version);
            if (r.numFound > 0 && !r.docs.isEmpty()) {
                search.status = "done";
                search.at = r.docs.get(0).timestamp;
                search.detail = "indexed" + (r.docs.get(0).extensions.isEmpty() ? "" : " with " + String.join(" ", r.docs.get(0).extensions));
            } else {
                search.status = "pending";
                search.detail = "not indexed yet";
            }
        } catch (HttpException e) {
            search.status = "error";
            search.detail = e.getMessage();
        }
        if (jd.applicable) {
            String url = ctx.env.javadocIo() + "/doc/" + t.gav.groupId + "/" + t.gav.artifactId + "/" + t.gav.version;
            try {
                Http.Response r = ctx.http.get(url, Http.NO_CACHE, null);
                if (r.ok()) {
                    jd.status = "done";
                    jd.detail = "https://javadoc.io/doc/" + t.gav.groupId + "/" + t.gav.artifactId + "/" + t.gav.version;
                } else if (r.status == 404) {
                    jd.status = "pending";
                    jd.detail = "not available yet";
                } else {
                    jd.status = "error";
                    jd.detail = "HTTP " + r.status;
                }
            } catch (HttpException e) {
                jd.status = "error";
                jd.detail = e.getMessage();
            }
        }
    }

    private void checkArtifact(Ctx ctx, String base, Track t, Stage art) throws HttpException {
        art.missing.clear();
        art.files.clear();
        Http.Response pom = ctx.http.get(base + ".pom", Http.NO_CACHE, null);
        if (pom.status == 404) {
            art.status = "pending";
            art.detail = "not uploaded yet (no POM)";
            art.missing.add(".pom");
            return;
        }
        if (!pom.ok()) {
            art.status = "error";
            art.detail = "HTTP " + pom.status + " for the POM";
            return;
        }
        if (t.packaging == null) {
            try {
                t.packaging = Pom.parse(pom.body, t.gav.toString()).packaging;
            } catch (RuntimeException e) {
                t.packaging = "jar";
            }
        }
        art.at = lastModified(pom);
        String ext = extension(t.packaging);
        List<String> mains = new ArrayList<>();
        mains.add(".pom");
        if (ext != null) {
            mains.add("." + ext);
            if (ext.equals("jar")) {
                mains.add("-sources.jar");
                mains.add("-javadoc.jar");
            }
        }
        List<String> suffixes = new ArrayList<>();
        for (String m : mains) {
            if (!m.equals(".pom")) suffixes.add(m);
            suffixes.add(m + ".asc");
            suffixes.add(m + ".sha1");
            suffixes.add(m + ".md5");
        }
        List<Http.Result<Http.Response>> heads = ctx.http.parallel(suffixes, s -> ctx.http.head(base + s));
        Map<String, Integer> status = new LinkedHashMap<>();
        status.put(".pom", 200);
        for (int i = 0; i < suffixes.size(); i++) {
            Http.Result<Http.Response> r = heads.get(i);
            status.put(suffixes.get(i), r.ok() ? r.value.status : 0);
        }
        // POM checksum against its .sha1
        String checksum = "unverified";
        if (status.getOrDefault(".pom.sha1", 0) == 200) {
            Http.Response sha = ctx.http.get(base + ".pom.sha1", Http.NO_CACHE, null);
            if (sha.ok()) {
                String want = sha.text().trim().split("\\s+")[0].toLowerCase(Locale.ROOT);
                checksum = want.equals(Hash.sha1Hex(pom.body)) ? "ok" : "mismatch";
            }
        }
        for (String m : mains) {
            art.files.add(OpsCommon.m("file", t.gav.artifactId + "-" + t.gav.version + m, "present", status.getOrDefault(m, 0) == 200,
                    "signature", status.getOrDefault(m + ".asc", 0) == 200,
                    "sha1", status.getOrDefault(m + ".sha1", 0) == 200, "md5", status.getOrDefault(m + ".md5", 0) == 200));
        }
        for (Map.Entry<String, Integer> e : status.entrySet()) if (e.getValue() != 200) art.missing.add(e.getKey());
        if (checksum.equals("mismatch")) {
            art.status = "failed";
            art.detail = "POM checksum does not match its .sha1 (corrupt or partial upload)";
        } else if (art.missing.isEmpty()) {
            art.status = "done";
            art.detail = Ui.plural(mains.size(), "file") + " with signatures and checksums" + (checksum.equals("ok") ? ", POM sha1 verified" : "");
        } else {
            art.status = "pending";
            art.detail = "missing " + String.join(", ", art.missing);
        }
    }

    private static long lastModified(Http.Response r) {
        String lm = r.header("last-modified");
        if (lm == null) return 0;
        try {
            return ZonedDateTime.parse(lm, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant().toEpochMilli();
        } catch (RuntimeException e) {
            return 0;
        }
    }

    // ---------------------------------------------------------------- output

    private static String ui(Ui ui, Stage s) {
        switch (s.status) {
            case "done": return ui.green("done");
            case "failed": return ui.red("FAILED");
            case "error": return ui.red("error");
            case "skipped": return ui.dim("n/a");
            default: return ui.yellow("pending");
        }
    }

    private static Map<String, Object> trackJson(Track t) {
        List<Object> st = new ArrayList<>();
        for (Stage s : t.stages) st.add(s.toJson());
        Stage art = t.stage("artifact");
        return OpsCommon.m("artifact", t.gav.toString(), "packaging", t.packaging, "complete", t.complete(),
                "uploadedAt", art.at > 0 ? Instant.ofEpochMilli(art.at).toString() : null, "stages", st);
    }

    private static void print(Ui ui, List<Track> tracks, String repo) {
        for (Track t : tracks) {
            ui.title("Publish Tracker " + ui.dot() + " " + t.gav + (t.packaging == null ? "" : ui.dim(" (" + t.packaging + ")")));
            Stage art = t.stage("artifact");
            ui.note("repository " + OpsCommon.safeUrl(repo) + (art.at > 0 ? " " + ui.dot() + " uploaded " + Ui.ago(art.at) + " (" + Instant.ofEpochMilli(art.at).toString().substring(0, 16).replace('T', ' ') + " UTC)" : ""));
            Ui.Table tb = new Ui.Table("", "Stage", "Status", "Since", "After upload", "Detail");
            for (Stage s : t.stages) {
                String mark = s.done() ? ui.ok() : s.status.equals("skipped") ? ui.dim(ui.dot()) : s.status.equals("pending") ? ui.warnMark() : ui.bad();
                // Data timestamps (Last-Modified, lastUpdated, index time) are exact; otherwise the first time this tool saw
                // the stage green is only meaningful when tracking started before it turned green.
                long when = s.at > 0 ? s.at : s.seenAt > t.trackingSince + 1000 ? s.seenAt : 0;
                String since = !s.done() ? "" : when > 0 ? Ui.ago(when) : s.seenAt > 0 ? ui.dim("seen " + Ui.ago(s.seenAt)) : "";
                String after = s.done() && art.at > 0 && when > 0 && s != art ? "+" + duration(Math.max(0, when - art.at)) : "";
                tb.row(mark, s.title + (s.required || !s.applicable ? "" : ui.dim(" (optional)")), ui(ui, s), since, after,
                        s.detail == null ? "" : s.detail);
            }
            ui.table(tb);
            if (t != tracks.get(tracks.size() - 1)) ui.println();
        }
    }
}
