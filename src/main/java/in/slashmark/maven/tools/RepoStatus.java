package in.slashmark.maven.tools;

import in.slashmark.maven.cli.Args;
import in.slashmark.maven.cli.Command;
import in.slashmark.maven.cli.Ctx;
import in.slashmark.maven.cli.Exit;
import in.slashmark.maven.cli.Ui;
import in.slashmark.maven.cli.UsageException;
import in.slashmark.maven.model.Gav;
import in.slashmark.maven.repo.Metadata;
import in.slashmark.maven.repo.Repos;
import in.slashmark.maven.repo.Settings;
import in.slashmark.maven.util.Hash;
import in.slashmark.maven.util.Http;
import in.slashmark.maven.util.HttpException;
import in.slashmark.maven.watch.Alerts;
import in.slashmark.maven.watch.State;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Repository Health Monitor: Live status, latency, auth and freshness of Central, mirrors and private repositories. */
public final class RepoStatus extends Command {
    @Override public String name() { return "repo-status"; }
    @Override public String title() { return "Repository Health Monitor"; }
    @Override public String group() { return "Operations"; }
    @Override public String summary() { return "Live status, latency, auth and freshness of Central, mirrors and private repositories"; }

    @Override
    public Set<String> flags() { return Set.of("watch", "notify"); }

    static final String DEFAULT_PROBE = "org.apache.logging.log4j:log4j-api";

    @Override
    public String help() {
        return String.join("\n",
                "Usage: sm-maven repo-status [options]",
                "",
                summary() + ".",
                "Probes every repository the build would use: Maven Central, <repositories> of the project (-f), repositories",
                "of active settings.xml profiles, settings.xml mirrors and any -r URL. For each one it measures latency over",
                "several samples (p50/p95), reports the HTTP status, whether authentication is required and accepted",
                "(credentials come from settings.xml <server> entries with the same id and are never printed), how fresh its",
                "maven-metadata.xml is compared with the other repositories, and warns about plain-HTTP repositories.",
                "",
                "Options:",
                "  -r, --repo <url>         Also probe this repository (repeatable; id=url to match a settings.xml <server>)",
                "  --probe <group:artifact> Artifact whose maven-metadata.xml is fetched (default " + DEFAULT_PROBE + ")",
                "  --samples <n>            Requests per repository for the latency figures (default 5)",
                "  --slow <time>            p95 latency above which a repository counts as degraded (default 1500ms)",
                "  --max-lag <time>         Metadata lag behind the freshest repository that triggers a warning (default 1h)",
                "  --fail-on <state>        Exit 1 when a repository is down (default: down or failing auth), degraded, or none",
                "",
                "Watch options:",
                "  --watch                  Keep probing every --interval and alert when a repository changes state",
                "  --interval <time>        Time between probes (default 5m)",
                "  --cycles <n>             Stop after n probes",
                "  --notify / --no-notify   Send alerts on state changes (default: on when alert channels exist)",
                "  --channel <name>         Only alert these channels (see: sm-maven alerts list)",
                "",
                "States: up, degraded (slow or unexpected status), auth-required (401/403 without credentials),",
                "auth-failed (credentials rejected), down (5xx or unreachable). Exit 1 when the --fail-on condition is met.",
                "",
                "Examples:",
                "  sm-maven repo-status",
                "  sm-maven repo-status -f service/pom.xml --samples 10",
                "  sm-maven repo-status -r corp=https://nexus.example.com/repository/maven-releases",
                "  sm-maven repo-status --watch --interval 2m --channel ops-slack");
    }

    // ---------------------------------------------------------------- targets

    static final class Target {
        String id, url, source;
        /** URL as shown to the user: credentials embedded in a --repo URL appear as ***@. */
        String display;
        String shown() { return display != null ? display : url; }
        final List<String> mirrorOf = new ArrayList<>();
        final Map<String, String> headers = new LinkedHashMap<>();
        boolean credentials;
    }

    static final class Probe {
        Target t;
        String state, error;
        int status;
        final List<Long> samples = new ArrayList<>();
        long p50 = -1, p95 = -1, min = -1, max = -1, firstMs = -1;
        boolean authRequired;
        Boolean authOk;
        boolean metadataFound;
        long lastUpdated;
        String newest;
        Long lagMinutes;
        final List<String> warnings = new ArrayList<>();
    }

    private static void addAuth(Target t, Settings.Server s) {
        if (s == null) return;
        if (s.username != null && s.password != null && !s.passwordEncrypted() && !s.password.contains("${")) {
            t.headers.put("Authorization", "Basic " + Base64.getEncoder().encodeToString((s.username + ":" + s.password).getBytes(StandardCharsets.UTF_8)));
            t.credentials = true;
        }
        for (Map.Entry<String, String> h : s.headers.entrySet()) {
            if (h.getValue() != null && !h.getValue().contains("${")) {
                t.headers.put(h.getKey(), h.getValue());
                t.credentials = true;
            }
        }
    }

    private static String strip(String u) {
        while (u.endsWith("/")) u = u.substring(0, u.length() - 1);
        return u;
    }

    List<Target> targets(Ctx ctx, Args args) throws Exception {
        // Loading the project registers its <repositories> (with settings.xml mirrors applied).
        if (ctx.globals().get("file") != null || ctx.hasProject()) ctx.project();
        Settings settings = ctx.repos.settings();
        List<Target> out = new ArrayList<>();
        for (Repos.Remote r : ctx.repos.remotes()) {
            Target t = new Target();
            t.id = r.id;
            t.url = r.url;
            t.mirrorOf.addAll(r.mirrorOf);
            t.headers.putAll(r.headers());
            t.credentials = r.hasCredentials;
            boolean isMirror = false;
            for (Settings.Mirror m : settings.mirrors) if (r.id.equals(m.id)) isMirror = true;
            boolean fromSettings = false;
            for (Settings.ProfileRepo p : settings.profileRepositories) if (r.id.equals(p.id)) fromSettings = true;
            t.source = isMirror ? "settings mirror" : r.id.equals("central") ? "central" : fromSettings ? "settings profile" : "project";
            t.mirrorOf.remove(t.id);
            out.add(t);
        }
        for (Settings.Mirror m : settings.mirrors) {
            if (m.url == null || m.blocked) continue;
            boolean dup = false;
            for (Target t : out) if (t.url.equals(strip(m.url))) dup = true;
            if (dup) continue;
            Target t = new Target();
            t.id = m.id;
            t.url = strip(m.url);
            t.source = "settings mirror";
            if (m.mirrorOf != null) t.mirrorOf.add(m.mirrorOf);
            addAuth(t, settings.server(m.id));
            out.add(t);
        }
        List<String> extra = new ArrayList<>(args.getAll("repo"));
        extra.addAll(args.getAll("r"));
        int n = 0;
        for (String spec : extra) {
            n++;
            String id = null, url = spec;
            int eq = spec.indexOf('=');
            int scheme = spec.indexOf("://");
            if (eq > 0 && (scheme < 0 || eq < scheme)) {
                id = spec.substring(0, eq);
                url = spec.substring(eq + 1);
            }
            URI u;
            try {
                u = URI.create(url);
            } catch (IllegalArgumentException e) {
                throw new UsageException("--repo expects a URL, got '" + OpsCommon.safeUrl(url) + "'");
            }
            if (u.getScheme() == null || u.getHost() == null || !(u.getScheme().equalsIgnoreCase("http") || u.getScheme().equalsIgnoreCase("https"))) {
                throw new UsageException("--repo expects an http(s) URL, got '" + OpsCommon.safeUrl(url) + "'");
            }
            Target t = new Target();
            t.source = "command line";
            if (u.getRawUserInfo() != null) {
                String ui = java.net.URLDecoder.decode(u.getRawUserInfo(), StandardCharsets.UTF_8);
                t.headers.put("Authorization", "Basic " + Base64.getEncoder().encodeToString(ui.getBytes(StandardCharsets.UTF_8)));
                t.credentials = true;
                url = url.replace(u.getRawUserInfo() + "@", "");
                t.display = strip(url).replaceFirst("://", "://***@");
            }
            t.url = strip(url);
            t.id = id != null ? id : "repo-" + n;
            if (!t.credentials) addAuth(t, settings.server(t.id));
            boolean dup = false;
            for (Target o : out) if (o.url.equals(t.url) && o.headers.equals(t.headers)) dup = true;
            if (!dup) out.add(t);
        }
        return out;
    }

    // ---------------------------------------------------------------- probing

    static long percentile(List<Long> sorted, double p) {
        if (sorted.isEmpty()) return -1;
        int rank = (int) Math.ceil(p * sorted.size());
        return sorted.get(Math.max(0, Math.min(sorted.size() - 1, rank - 1)));
    }

    static Probe probe(Ctx ctx, Target t, Gav probe, int samples, long slowMs) {
        Probe p = new Probe();
        p.t = t;
        String url = t.url + "/" + probe.groupId.replace('.', '/') + "/" + probe.artifactId + "/maven-metadata.xml";
        Http.Response last = null;
        // The first request pays for DNS + TCP (+ TLS) setup: reported separately, not in the percentiles.
        for (int i = -1; i < samples; i++) {
            try {
                Http.Response r = ctx.http.get(url, Http.NO_CACHE, t.headers);
                last = r;
                p.status = r.status;
                if (r.status >= 500 || r.status == 401 || r.status == 403) break;
                if (i < 0) p.firstMs = r.millis;
                else p.samples.add(r.millis);
            } catch (HttpException e) {
                p.status = 0;
                p.error = e.getMessage();
                break;
            }
        }
        List<Long> sorted = new ArrayList<>(p.samples);
        sorted.sort(null);
        if (!sorted.isEmpty()) {
            p.p50 = percentile(sorted, 0.5);
            p.p95 = percentile(sorted, 0.95);
            p.min = sorted.get(0);
            p.max = sorted.get(sorted.size() - 1);
        }
        // Authentication: is it required, and are the configured credentials accepted?
        if (p.status == 401 || p.status == 403) {
            p.authRequired = true;
            p.authOk = t.credentials ? Boolean.FALSE : null;
        } else if (t.credentials && (p.status == 200 || p.status == 404)) {
            p.authOk = Boolean.TRUE;
            try {
                Http.Response anon = ctx.http.get(url, Http.NO_CACHE, null);
                p.authRequired = anon.status == 401 || anon.status == 403;
            } catch (HttpException e) {
                // the authenticated request worked; leave "required" unknown (false)
            }
        }
        if (last != null && last.ok()) {
            try {
                Metadata md = Metadata.parse(last.body);
                p.metadataFound = true;
                p.lastUpdated = md.lastUpdatedMillis();
                p.newest = md.newest(true);
            } catch (RuntimeException e) {
                p.warnings.add("maven-metadata.xml for " + probe + " is not valid XML");
            }
        }
        if (p.status == 0 || p.status >= 500) p.state = "down";
        else if (p.status == 401 || p.status == 403) p.state = t.credentials ? "auth-failed" : "auth-required";
        else if (p.status != 200 && p.status != 404) p.state = "degraded";
        else if (p.p95 > slowMs) p.state = "degraded";
        else p.state = "up";
        if (p.status == 404) p.warnings.add("does not host " + probe + " (the repository answered, but freshness cannot be measured)");
        if (p.state.equals("degraded") && p.p95 > slowMs) p.warnings.add("slow: p95 " + p.p95 + " ms is above " + slowMs + " ms");
        if (p.state.equals("degraded") && p.status != 200 && p.status != 404) p.warnings.add("unexpected HTTP " + p.status + " for maven-metadata.xml");
        if (OpsCommon.insecureHttp(t.url)) p.warnings.add("insecure: plain HTTP (Maven 3.8.1+ blocks external HTTP repositories; use HTTPS)");
        if (p.status >= 500) p.error = "HTTP " + p.status + (p.status == 503 ? " Service Unavailable" : "") + " after retries";
        return p;
    }

    static boolean healthy(String state) { return state.equals("up"); }

    static String severity(Probe p) {
        switch (p.state) {
            case "down": return p.t.id.equals("central") ? "critical" : "high";
            case "auth-failed": return "high";
            case "auth-required": return "medium";
            case "degraded": return "low";
            default: return "info";
        }
    }

    // ---------------------------------------------------------------- run

    @Override
    public int run(Ctx ctx, Args args) throws Exception {
        String probeSpec = args.get("probe", DEFAULT_PROBE);
        Gav probe;
        try {
            probe = Gav.parse(probeSpec);
        } catch (RuntimeException e) {
            throw new UsageException("--probe expects group:artifact, got '" + probeSpec + "'");
        }
        if (probe.groupId == null || probe.artifactId == null || probe.groupId.isEmpty()) throw new UsageException("--probe expects group:artifact, got '" + probeSpec + "'");
        int samples = args.getInt("samples", 5);
        if (samples < 1 || samples > 100) throw new UsageException("--samples must be between 1 and 100");
        long slow = args.getDuration("slow", 1500);
        long maxLag = args.getDuration("max-lag", 3_600_000L);
        String failOn = args.get("fail-on", "down").toLowerCase(Locale.ROOT);
        if (!List.of("down", "degraded", "none").contains(failOn)) throw new UsageException("--fail-on expects down, degraded or none");
        boolean watch = args.flag("watch");
        long interval = Math.max(1000, args.getDuration("interval", 5 * 60_000L));
        int cycles = args.getInt("cycles", watch ? Integer.MAX_VALUE : 1);
        if (cycles < 1) throw new UsageException("--cycles must be at least 1");
        List<String> channels = args.getAll("channel");

        List<Target> targets = targets(ctx, args);
        StringBuilder scope = new StringBuilder();
        for (Target t : targets) scope.append(t.id).append('=').append(t.url).append('\n');
        State state = ctx.state("repo-status", Hash.sha256Hex(scope.toString().getBytes(StandardCharsets.UTF_8)));
        Alerts alerts = ctx.alerts();
        boolean notify = args.has("notify") ? args.flag("notify") : !args.flag("no-notify") && !alerts.channels().isEmpty();

        int exit = Exit.OK;
        for (int c = 1; c <= cycles; c++) {
            if (!ctx.ui.json) ctx.ui.progress("Probing " + Ui.plural(targets.size(), "repository", "repositories") + "...");
            List<Http.Result<Probe>> res = ctx.http.parallel(targets, t -> probe(ctx, t, probe, samples, slow));
            ctx.ui.progressDone();
            List<Probe> probes = new ArrayList<>();
            for (int i = 0; i < res.size(); i++) {
                Probe p = res.get(i).value;
                if (p == null) {
                    p = new Probe();
                    p.t = targets.get(i);
                    p.state = "down";
                    p.error = String.valueOf(res.get(i).error);
                }
                probes.add(p);
            }
            freshness(probes, maxLag);

            // State changes since the previous probe (persisted, so cron runs compare with the last run too).
            Map<String, Object> prev = state.map("states");
            List<Map<String, Object>> changes = new ArrayList<>();
            for (Probe p : probes) {
                Object before = prev.get(p.t.id);
                String from = before == null ? null : String.valueOf(before);
                if (from == null ? !healthy(p.state) : !from.equals(p.state)) {
                    changes.add(OpsCommon.m("id", p.t.id, "from", from, "to", p.state, "severity", healthy(p.state) ? "info" : severity(p)));
                }
                prev.put(p.t.id, p.state);
            }
            state.data().put("lastRun", Instant.now().toString());
            state.save();

            if (ctx.ui.json) ctx.ui.emitJson(json(probes, probe, samples, c, changes));
            else print(ctx.ui, probes, probe, samples, changes, c);

            if (notify && !changes.isEmpty()) sendAlerts(ctx, alerts, channels, probes, changes);

            exit = Exit.OK;
            for (Probe p : probes) {
                boolean bad = !p.state.equals("up") && !p.state.equals("degraded");
                if (failOn.equals("down") && bad) exit = Exit.ISSUES;
                if (failOn.equals("degraded") && !p.state.equals("up")) exit = Exit.ISSUES;
            }
            if (c < cycles) {
                ctx.ui.note("next probe in " + (interval / 1000) + "s");
                try {
                    Thread.sleep(interval);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
        return exit;
    }

    static void freshness(List<Probe> probes, long maxLagMs) {
        long freshest = 0;
        String newest = null;
        for (Probe p : probes) {
            if (!p.metadataFound) continue;
            freshest = Math.max(freshest, p.lastUpdated);
            if (p.newest != null && (newest == null || in.slashmark.maven.model.MavenVersion.compare(p.newest, newest) > 0)) newest = p.newest;
        }
        for (Probe p : probes) {
            if (!p.metadataFound || p.lastUpdated <= 0) continue;
            long lag = Math.max(0, freshest - p.lastUpdated);
            p.lagMinutes = lag / 60_000;
            if (lag > maxLagMs) p.warnings.add("stale metadata: " + (lag / 60_000) + " min behind the freshest repository");
            if (newest != null && p.newest != null && !p.newest.equals(newest)) p.warnings.add("missing newest version " + newest + " (has " + p.newest + ")");
        }
    }

    private static Map<String, Object> json(List<Probe> probes, Gav probe, int samples, int cycle, List<Map<String, Object>> changes) {
        List<Object> repos = new ArrayList<>();
        int up = 0, degraded = 0, down = 0, authRequired = 0, authFailed = 0;
        for (Probe p : probes) {
            switch (p.state) {
                case "up": up++; break;
                case "degraded": degraded++; break;
                case "auth-required": authRequired++; break;
                case "auth-failed": authFailed++; break;
                default: down++;
            }
            repos.add(OpsCommon.m("id", p.t.id, "url", OpsCommon.safeUrl(p.t.shown()), "source", p.t.source, "mirrorOf", p.t.mirrorOf,
                    "state", p.state, "healthy", healthy(p.state), "severity", severity(p), "httpStatus", p.status == 0 ? null : p.status, "error", p.error,
                    "https", p.t.url.toLowerCase(Locale.ROOT).startsWith("https:"), "insecure", OpsCommon.insecureHttp(p.t.url),
                    "latency", OpsCommon.m("firstRequest", p.firstMs < 0 ? null : p.firstMs, "samples", p.samples, "p50", p.p50 < 0 ? null : p.p50, "p95", p.p95 < 0 ? null : p.p95,
                            "min", p.min < 0 ? null : p.min, "max", p.max < 0 ? null : p.max),
                    "auth", OpsCommon.m("configured", p.t.credentials, "required", p.authRequired, "ok", p.authOk),
                    "metadata", OpsCommon.m("found", p.metadataFound, "lastUpdated", p.lastUpdated > 0 ? Instant.ofEpochMilli(p.lastUpdated).toString() : null,
                            "newestVersion", p.newest, "lagMinutes", p.lagMinutes),
                    "warnings", p.warnings));
        }
        return OpsCommon.m("tool", "repo-status", "cycle", cycle, "checkedAt", Instant.now().toString(), "probe", probe.ga(), "samples", samples,
                "summary", OpsCommon.m("total", probes.size(), "up", up, "degraded", degraded, "down", down, "authRequired", authRequired, "authFailed", authFailed),
                "repositories", repos, "changes", changes);
    }

    private static String stateLabel(Ui ui, String s) {
        switch (s) {
            case "up": return ui.ok() + " " + ui.green("up");
            case "degraded": return ui.warnMark() + " " + ui.yellow("degraded");
            case "auth-required": return ui.warnMark() + " " + ui.yellow("auth required");
            case "auth-failed": return ui.bad() + " " + ui.red("auth failed");
            default: return ui.bad() + " " + ui.red("down");
        }
    }

    private static void print(Ui ui, List<Probe> probes, Gav probe, int samples, List<Map<String, Object>> changes, int cycle) {
        if (cycle == 1) {
            ui.title("Repository Health " + ui.dot() + " " + Ui.plural(probes.size(), "repository", "repositories"));
            ui.note("probe: " + probe.ga() + "/maven-metadata.xml " + ui.dot() + " " + Ui.plural(samples, "sample") + " per repository");
        } else {
            ui.section("Probe #" + cycle + " " + ui.dot() + " " + Instant.now().toString().substring(11, 19) + " UTC");
        }
        Ui.Table t = new Ui.Table("Repository", "URL", "State", "HTTP", "p50", "p95", "Auth", "Metadata").rightAlign(3, 4, 5);
        for (Probe p : probes) {
            String auth = p.authOk == Boolean.TRUE ? ui.green("ok") + (p.authRequired ? " (required)" : "")
                    : p.authOk == Boolean.FALSE ? ui.red("rejected")
                    : p.authRequired ? ui.yellow("required") : p.t.credentials ? "configured" : ui.dim("public");
            String md = p.metadataFound ? (p.lastUpdated > 0 ? Ui.ago(p.lastUpdated) : "found") + (p.lagMinutes != null && p.lagMinutes > 0 ? ui.yellow(" (lag " + p.lagMinutes + " min)") : "")
                    : p.status == 404 ? ui.dim("not hosted") : ui.dim("—");
            t.row(p.t.id + (p.t.mirrorOf.isEmpty() ? "" : ui.dim(" (mirror of " + String.join(",", p.t.mirrorOf) + ")")),
                    OpsCommon.safeUrl(p.t.shown()), stateLabel(ui, p.state), p.status == 0 ? "—" : String.valueOf(p.status),
                    p.p50 < 0 ? "—" : p.p50 + " ms", p.p95 < 0 ? "—" : p.p95 + " ms", auth, md);
        }
        ui.table(t);
        boolean any = false;
        for (Probe p : probes) {
            if (p.error != null) {
                if (!any) ui.println();
                any = true;
                ui.fail(p.t.id + ": " + p.error);
            }
            for (String w : p.warnings) {
                if (!any) ui.println();
                any = true;
                if (w.startsWith("does not host")) ui.note("  " + p.t.id + ": " + w);
                else ui.warn(p.t.id + ": " + w);
            }
            if (p.authRequired && !p.t.credentials) {
                ui.line(ui.dim("add a <server><id>" + p.t.id + "</id>... to settings.xml with credentials for this repository"));
            }
        }
        for (Map<String, Object> ch : changes) {
            if (ch.get("from") == null) continue;
            ui.warn("state change: " + ch.get("id") + " " + ch.get("from") + " " + ui.arrow() + " " + ch.get("to"));
        }
        int healthy = 0;
        for (Probe p : probes) if (healthy(p.state)) healthy++;
        ui.println();
        if (healthy == probes.size()) ui.good("All " + Ui.plural(probes.size(), "repository", "repositories") + " healthy");
        else ui.warn(healthy + " of " + Ui.plural(probes.size(), "repository", "repositories") + " healthy");
    }

    private static void sendAlerts(Ctx ctx, Alerts alerts, List<String> channels, List<Probe> probes, List<Map<String, Object>> changes) {
        String top = "info";
        Alerts.Alert a = new Alerts.Alert("repo-status", "");
        int bad = 0;
        for (Map<String, Object> ch : changes) {
            String sev = String.valueOf(ch.get("severity"));
            if (OpsCommon.sevRank(sev) > OpsCommon.sevRank(top)) top = sev;
            if (!healthy(String.valueOf(ch.get("to")))) bad++;
            Probe p = null;
            for (Probe x : probes) if (x.t.id.equals(ch.get("id"))) p = x;
            String detail = p == null ? "" : p.error != null ? " (" + p.error + ")" : p.p95 >= 0 ? " (p95 " + p.p95 + " ms)" : "";
            a.line(ch.get("id") + ": " + (ch.get("from") == null ? "" : ch.get("from") + " -> ") + ch.get("to") + detail);
        }
        a.title = bad > 0 ? Ui.plural(bad, "repository", "repositories") + " unhealthy" : Ui.plural(changes.size(), "repository", "repositories") + " recovered";
        a.severity = top;
        a.data = changes;
        for (Alerts.Delivery d : alerts.send(a, channels)) {
            if (d.ok) ctx.ui.note("  alert sent to " + d.channel);
            else ctx.ui.warnErr("alert to " + d.channel + " failed: " + d.error);
        }
    }
}
