package in.slashmark.maven.tools;

import in.slashmark.maven.bytecode.ClassFile;
import in.slashmark.maven.bytecode.Jar;
import in.slashmark.maven.cli.Args;
import in.slashmark.maven.cli.Command;
import in.slashmark.maven.cli.Ctx;
import in.slashmark.maven.cli.Exit;
import in.slashmark.maven.cli.Ui;
import in.slashmark.maven.cli.UsageException;
import in.slashmark.maven.data.CentralSearch;
import in.slashmark.maven.model.Gav;
import in.slashmark.maven.model.MavenVersion;
import in.slashmark.maven.repo.Metadata;
import in.slashmark.maven.resolve.DepNode;
import in.slashmark.maven.util.HttpException;
import in.slashmark.maven.util.Json;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Malicious Release Guard: Flag suspicious new releases: new signing key, agents, native code, process exec. */
public final class ReleaseGuard extends Command {
    @Override public String name() { return "release-guard"; }
    @Override public String title() { return "Malicious Release Guard"; }
    @Override public String group() { return "Live threat intelligence"; }
    @Override public String summary() { return "Flag suspicious new releases: new signing key, agents, native code, process exec"; }

    @Override
    public String help() {
        return String.join("\n",
                "Usage: sm-maven release-guard [group:artifact[:version]] [options]",
                "",
                summary() + ".",
                "",
                "For every dependency that has newer releases (or for one artifact), the newest release(s) are",
                "compared with the version you use, the way a supply-chain attack would show up:",
                "  signing-key-changed / unsigned   the .asc signature comes from another OpenPGP key, or is gone",
                "  agent-entrypoint                 new Premain-Class / Agent-Class / Launcher-Agent-Class",
                "  native-library                   new .so/.dll/.dylib files",
                "  process-exec, shell-command      new Runtime.exec / ProcessBuilder calls, shell command strings",
                "  dynamic-classloading             new URLClassLoader / defineClass use",
                "  hardcoded-ip, hardcoded-url      new IP addresses or URLs in class constant pools",
                "  native-loading, network-access, script-eval   other new capabilities",
                "  young-release                    published very recently (most malicious releases are caught in days)",
                "Each release gets a risk score (0-100) with the reasons. Exit 1 when a release reaches --threshold.",
                "",
                "Options:",
                "  --releases <n>         Newest n releases to inspect per artifact (default 1)",
                "  --threshold <score>    Score that counts as suspicious (default 40)",
                "  --min-age <time>       Releases younger than this are flagged (default 7d)",
                "  --direct               Only direct dependencies",
                "  --scope <scopes>       Only these dependency scopes (default: all)",
                "  --all                  Also list clean releases",
                "",
                "Examples:",
                "  sm-maven release-guard",
                "  sm-maven release-guard com.acme:acme-agent:1.0.0",
                "  sm-maven release-guard --releases 3 --threshold 30 --json");
    }

    // ---------------------------------------------------------------- signals

    private static final Pattern IPV4 = Pattern.compile("(?<![\\d.])((?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3})(?![\\d.])");
    private static final Pattern URL = Pattern.compile("(?i)\\b((?:https?|ftp)://[^\\s\"'<>|]+)");
    private static final Pattern SHELL = Pattern.compile("(?i)(\\|\\s*(?:ba|z)?sh\\b|\\b(?:ba|z)?sh\\s+-c\\b|\\bcmd(?:\\.exe)?\\s+/c\\b|powershell|\\bcurl\\s+-|\\bwget\\s+(?:-|https?:)|\\bchmod\\s+\\+x|/dev/tcp/|\\bnc\\s+-e\\b)");
    private static final List<String> BENIGN_HOSTS = List.of("www.w3.org", "w3.org", "xml.org", "www.xml.org", "java.sun.com", "xmlns.jcp.org",
            "xml.apache.org", "www.apache.org", "apache.org", "purl.org", "json-schema.org", "localhost", "example.com", "www.example.com",
            "schemas.xmlsoap.org", "schemas.microsoft.com", "www.oracle.com", "jakarta.ee", "xmlpull.org", "ns.adobe.com", "www.slf4j.org", "logging.apache.org");

    /** What a release contains that matters for supply-chain risk. */
    static final class Profile {
        Gav gav;
        boolean hasJar;
        ThreatSupport.Signer signer;
        final Map<String, String> agent = new LinkedHashMap<>();
        final Set<String> natives = new TreeSet<>();
        /** capability -> where (first class seen) */
        final Map<String, String> caps = new LinkedHashMap<>();
        final Map<String, String> ips = new LinkedHashMap<>();
        final Map<String, String> urls = new LinkedHashMap<>();
        final Map<String, String> shell = new LinkedHashMap<>();
        long published;
    }

    static final class Signal {
        final String id;
        final int weight;
        final String detail;

        Signal(String id, int weight, String detail) {
            this.id = id;
            this.weight = weight;
            this.detail = detail;
        }

        Object toJson() { return Json.obj("id", id, "weight", weight, "detail", detail); }
    }

    static final class Review {
        String ga, inUse, release;
        long published;
        final List<Signal> signals = new ArrayList<>();
        int score;
        String level;
        String error;
        boolean direct;
    }

    @Override
    public int run(Ctx ctx, Args args) throws Exception {
        int releases = args.getInt("releases", 1);
        if (releases < 1 || releases > 20) throw new UsageException("--releases expects a number from 1 to 20");
        int threshold = args.getInt("threshold", 40);
        if (threshold < 1 || threshold > 100) throw new UsageException("--threshold expects a score from 1 to 100");
        long minAge = args.getDuration("min-age", 7 * 86_400_000L);
        boolean directOnly = args.flag("direct");
        Set<String> scopes = ThreatSupport.scopes(args.getAll("scope"));
        boolean showAll = args.flag("all");
        if (args.posFrom(1).size() > 0) throw new UsageException("unexpected argument '" + args.pos(1) + "'");

        // What to compare: (g:a, version in use, candidate releases)
        List<String[]> pairs = new ArrayList<>();   // {ga, inUse, release, direct}
        String label;
        int upToDate = 0;
        int checked = 0;
        String p = args.pos(0);
        if (p != null) {
            Gav g;
            try {
                g = Gav.parse(p);
            } catch (IllegalArgumentException e) {
                throw new UsageException(e.getMessage());
            }
            Metadata md = ctx.repos.metadata(g.groupId, g.artifactId);
            if (md == null) throw new UsageException(g.ga() + " was not found on " + ctx.repos.remotes().get(0).url);
            List<String> versions = ctx.versions(g.groupId, g.artifactId, true);
            String inUse = g.version;
            if (inUse == null || inUse.equalsIgnoreCase("latest") || inUse.equalsIgnoreCase("release")) {
                // No version: review the newest release(s) against the release before them.
                if (versions.size() < 2) throw new UsageException(g.ga() + " has only one release; nothing to compare it with");
                inUse = versions.get(Math.max(0, versions.size() - 1 - releases));
            } else if (!md.versions.contains(inUse)) {
                throw new UsageException(g.ga() + ":" + inUse + " was not found on " + ctx.repos.remotes().get(0).url);
            }
            label = g.ga() + ":" + inUse;
            checked = 1;
            List<String> newer = newer(versions, inUse, releases);
            if (newer.isEmpty()) upToDate = 1;
            for (String r : newer) pairs.add(new String[] {g.ga(), inUse, r, "true"});
        } else {
            Ctx.Target t = ctx.target(args, 0);
            label = t.label;
            List<DepNode> deps = t.dependencies(scopes);
            List<DepNode> todo = new ArrayList<>();
            for (DepNode n : deps) {
                if (directOnly && !ThreatSupport.directSomewhere(t, n.ga())) continue;
                if (ctx.models.inReactor(n.gav())) continue;
                todo.add(n);
            }
            checked = todo.size();
            ctx.ui.progress("Checking " + Ui.plural(todo.size(), "dependency", "dependencies") + " for new releases...");
            List<List<String>> versions = ctx.http.parallelOrNull(todo, n -> ctx.versions(n.groupId, n.artifactId, true));
            ctx.ui.progressDone();
            for (int i = 0; i < todo.size(); i++) {
                DepNode n = todo.get(i);
                List<String> vs = versions.get(i);
                List<String> newer = vs == null ? List.of() : newer(vs, n.version, releases);
                if (newer.isEmpty()) upToDate++;
                for (String r : newer) pairs.add(new String[] {n.ga(), n.version, r, String.valueOf(ThreatSupport.directSomewhere(t, n.ga()))});
            }
        }

        // Profile every version involved once, in parallel.
        Set<String> gavs = new LinkedHashSet<>();
        for (String[] pr : pairs) {
            gavs.add(pr[0] + ":" + pr[1]);
            gavs.add(pr[0] + ":" + pr[2]);
        }
        List<String> gavList = new ArrayList<>(gavs);
        ctx.ui.progress("Inspecting " + Ui.plural(gavList.size(), "release") + " (signatures, manifests, bytecode)...");
        List<in.slashmark.maven.util.Http.Result<Profile>> profs = ctx.http.parallel(gavList, s -> profile(ctx, Gav.parse(s)));
        ctx.ui.progressDone();
        Map<String, Profile> profiles = new LinkedHashMap<>();
        Map<String, String> errors = new LinkedHashMap<>();
        for (int i = 0; i < gavList.size(); i++) {
            if (profs.get(i).ok()) profiles.put(gavList.get(i), profs.get(i).value);
            else errors.put(gavList.get(i), String.valueOf(profs.get(i).error.getMessage()));
        }

        long now = System.currentTimeMillis();
        List<Review> reviews = new ArrayList<>();
        for (String[] pr : pairs) {
            Review r = new Review();
            r.ga = pr[0];
            r.inUse = pr[1];
            r.release = pr[2];
            r.direct = Boolean.parseBoolean(pr[3]);
            Profile base = profiles.get(pr[0] + ":" + pr[1]);
            Profile cand = profiles.get(pr[0] + ":" + pr[2]);
            if (base == null || cand == null) {
                r.error = errors.getOrDefault(pr[0] + ":" + pr[2], errors.get(pr[0] + ":" + pr[1]));
                r.level = "unknown";
                reviews.add(r);
                continue;
            }
            r.published = cand.published;
            compare(base, cand, r, now, minAge);
            reviews.add(r);
        }
        reviews.sort((a, b) -> Integer.compare(b.score, a.score));
        int suspicious = 0;
        for (Review r : reviews) if (r.score >= threshold) suspicious++;

        if (ctx.ui.json) {
            List<Object> items = new ArrayList<>();
            for (Review r : reviews) {
                if (!showAll && r.score == 0 && r.error == null) continue;
                items.add(reviewJson(r, threshold, now));
            }
            ctx.ui.emitJson(Json.obj("target", label, "threshold", threshold, "minAgeDays", minAge / 86_400_000.0,
                    "summary", Json.obj("dependencies", checked, "upToDate", upToDate, "releasesReviewed", reviews.size(), "suspicious", suspicious),
                    "releases", items));
        } else {
            print(ctx.ui, label, checked, upToDate, reviews, threshold, suspicious, showAll, now);
        }
        return suspicious > 0 ? Exit.ISSUES : Exit.OK;
    }

    private static List<String> newer(List<String> versions, String inUse, int n) {
        List<String> out = new ArrayList<>();
        for (String v : versions) if (MavenVersion.compare(v, inUse) > 0) out.add(v);
        if (out.size() > n) out = new ArrayList<>(out.subList(out.size() - n, out.size()));
        java.util.Collections.reverse(out);
        return out;
    }

    // ---------------------------------------------------------------- profiling

    static Profile profile(Ctx ctx, Gav gav) throws Exception {
        Profile p = new Profile();
        p.gav = gav;
        Jar jar = ctx.jar(gav);
        p.hasJar = jar != null;
        p.signer = ThreatSupport.signer(ctx, gav, p.hasJar);
        p.published = published(ctx, gav);
        if (jar == null) return p;
        for (String k : List.of("Premain-Class", "Agent-Class", "Launcher-Agent-Class", "Can-Redefine-Classes", "Can-Retransform-Classes", "Boot-Class-Path")) {
            String v = jar.manifestAttr(k);
            if (v != null) p.agent.put(k, v);
        }
        p.natives.addAll(jar.nativeLibs());
        for (String n : jar.nestedJars()) {
            Jar nested = jar.nested(n);
            if (nested != null) for (String x : nested.nativeLibs()) p.natives.add(n + "!/" + x);
        }
        for (ClassFile cf : jar.classes()) {
            String where = cf.className();
            for (ClassFile.Ref r : cf.references) {
                String cap = capability(r);
                if (cap != null) p.caps.putIfAbsent(cap, where + " " + "calls " + r.owner.replace('/', '.') + "." + r.name);
            }
            for (String c : cf.referencedClasses) {
                if (c.equals("java/net/URLClassLoader")) p.caps.putIfAbsent("dynamic-classloading", where + " uses java.net.URLClassLoader");
                if (c.equals("java/lang/ProcessBuilder")) p.caps.putIfAbsent("process-exec", where + " uses java.lang.ProcessBuilder");
                if (c.equals("javax/script/ScriptEngineManager")) p.caps.putIfAbsent("script-eval", where + " uses javax.script.ScriptEngineManager");
            }
            for (String s : cf.strings) {
                Matcher um = URL.matcher(s);
                while (um.find()) {
                    String u = um.group(1);
                    String host = host(u);
                    if (host != null && !BENIGN_HOSTS.contains(host.toLowerCase(Locale.ROOT))) p.urls.putIfAbsent(u, where);
                }
                Matcher im = IPV4.matcher(s);
                while (im.find()) {
                    String ip = im.group(1);
                    if (ip.startsWith("127.") || ip.equals("0.0.0.0") || ip.startsWith("255.")) continue;
                    // Skip version-looking strings such as "1.2.3.4" that are the whole constant.
                    if (s.trim().equals(ip) && ip.matches("\\d\\.\\d{1,2}\\.\\d{1,2}\\.\\d{1,2}")) continue;
                    p.ips.putIfAbsent(ip, where);
                }
                if (SHELL.matcher(s).find()) p.shell.putIfAbsent(s.length() > 80 ? s.substring(0, 77) + "..." : s, where);
            }
        }
        return p;
    }

    private static String capability(ClassFile.Ref r) {
        String o = r.owner;
        switch (o) {
            case "java/lang/Runtime":
                if (r.name.equals("exec")) return "process-exec";
                if (r.name.equals("load") || r.name.equals("loadLibrary")) return "native-loading";
                return null;
            case "java/lang/ProcessBuilder": return "process-exec";
            case "java/lang/System":
                return r.name.equals("load") || r.name.equals("loadLibrary") ? "native-loading" : null;
            case "java/net/URLClassLoader": return "dynamic-classloading";
            case "java/lang/ClassLoader":
            case "java/lang/invoke/MethodHandles$Lookup":
                return r.name.equals("defineClass") ? "dynamic-classloading" : null;
            case "java/net/Socket":
            case "java/net/HttpURLConnection":
                return "network-access";
            case "java/net/URL":
                return r.name.equals("openConnection") || r.name.equals("openStream") ? "network-access" : null;
            case "javax/script/ScriptEngineManager":
            case "javax/script/ScriptEngine":
                return "script-eval";
            default: return null;
        }
    }

    private static String host(String url) {
        int s = url.indexOf("://");
        if (s < 0) return null;
        String rest = url.substring(s + 3);
        int end = rest.length();
        for (char c : new char[] {'/', ':', '?', '#'}) {
            int i = rest.indexOf(c);
            if (i >= 0 && i < end) end = i;
        }
        return rest.substring(0, end);
    }

    private static long published(Ctx ctx, Gav gav) {
        try {
            CentralSearch.Result r = ctx.search.version(gav.groupId, gav.artifactId, gav.version);
            for (CentralSearch.Doc d : r.docs) if (gav.version.equals(d.version) && d.timestamp > 0) return d.timestamp;
        } catch (HttpException e) {
            // release time unknown: the age signal is simply not evaluated
        }
        return 0;
    }

    // ---------------------------------------------------------------- comparison

    static void compare(Profile base, Profile cand, Review r, long now, long minAge) {
        ThreatSupport.Signer a = base.signer, b = cand.signer;
        if (a != null && b == null) {
            r.signals.add(new Signal("unsigned", 30, r.release + " has no PGP signature, " + r.inUse + " was signed by " + a.keyId));
        } else if (a != null && !sameKey(a, b)) {
            r.signals.add(new Signal("signing-key-changed", 35, "signed with key " + b.keyId + " instead of " + a.keyId));
        }
        for (Map.Entry<String, String> e : cand.agent.entrySet()) {
            if (base.agent.containsKey(e.getKey())) continue;
            boolean entry = e.getKey().endsWith("-Class");
            r.signals.add(new Signal("agent-entrypoint", entry ? 30 : 10, "new manifest " + e.getKey() + ": " + e.getValue()));
        }
        List<String> newNatives = new ArrayList<>();
        for (String n : cand.natives) if (!base.natives.contains(n)) newNatives.add(n);
        if (!newNatives.isEmpty()) r.signals.add(new Signal("native-library", 20, "new native code: " + String.join(", ", newNatives)));
        Map<String, Integer> capWeights = Map.of("process-exec", 25, "dynamic-classloading", 20, "native-loading", 10, "network-access", 10, "script-eval", 15);
        for (Map.Entry<String, String> e : cand.caps.entrySet()) {
            if (base.caps.containsKey(e.getKey())) continue;
            r.signals.add(new Signal(e.getKey(), capWeights.getOrDefault(e.getKey(), 10), e.getValue()));
        }
        for (Map.Entry<String, String> e : cand.shell.entrySet()) {
            if (base.shell.containsKey(e.getKey())) continue;
            r.signals.add(new Signal("shell-command", 20, "\"" + e.getKey() + "\" in " + e.getValue()));
            break;
        }
        List<String> newIps = new ArrayList<>();
        for (String ip : cand.ips.keySet()) if (!base.ips.containsKey(ip)) newIps.add(ip + " (" + cand.ips.get(ip) + ")");
        if (!newIps.isEmpty()) r.signals.add(new Signal("hardcoded-ip", 20, "new IP address" + (newIps.size() > 1 ? "es " : " ") + String.join(", ", newIps)));
        List<String> newUrls = new ArrayList<>();
        for (String u : cand.urls.keySet()) if (!base.urls.containsKey(u)) newUrls.add(u);
        if (!newUrls.isEmpty()) r.signals.add(new Signal("hardcoded-url", 10, "new URL" + (newUrls.size() > 1 ? "s " : " ") + String.join(", ", newUrls.subList(0, Math.min(5, newUrls.size())))));
        if (cand.published > 0) {
            long age = now - cand.published;
            if (age < 2 * 86_400_000L) r.signals.add(new Signal("young-release", 15, "published " + Ui.ago(cand.published) + " (" + Ui.date(cand.published) + ")"));
            else if (age < minAge) r.signals.add(new Signal("young-release", 8, "published " + Ui.ago(cand.published) + " (" + Ui.date(cand.published) + ")"));
        }
        int s = 0;
        for (Signal x : r.signals) s += x.weight;
        r.score = Math.min(100, s);
        r.level = r.score >= 60 ? "high" : r.score >= 30 ? "medium" : r.score > 0 ? "low" : "clean";
    }

    private static boolean sameKey(ThreatSupport.Signer a, ThreatSupport.Signer b) {
        if (a.fingerprint != null && b.fingerprint != null) return a.fingerprint.equalsIgnoreCase(b.fingerprint);
        return a.keyId != null && a.keyId.equalsIgnoreCase(b.keyId);
    }

    // ---------------------------------------------------------------- output

    private static Object reviewJson(Review r, int threshold, long now) {
        List<Object> sig = new ArrayList<>();
        for (Signal s : r.signals) sig.add(s.toJson());
        return Json.obj("artifact", r.ga, "inUse", r.inUse, "release", r.release, "direct", r.direct,
                "publishedAt", r.published > 0 ? java.time.Instant.ofEpochMilli(r.published).toString() : null,
                "ageDays", r.published > 0 ? Math.round((now - r.published) / 8_640_000.0) / 10.0 : null,
                "score", r.score, "level", r.level, "suspicious", r.score >= threshold, "signals", sig,
                "recommendation", recommendation(r, threshold), "error", r.error);
    }

    private static String recommendation(Review r, int threshold) {
        if (r.error != null) return null;
        if (r.score >= threshold) {
            return "Do not upgrade to " + r.release + " until it is verified; keep " + r.inUse
                    + " pinned (<dependencyManagement>) and block " + r.ga + ":" + r.release + " in your repository manager";
        }
        if (r.score > 0) return "Review the changes in " + r.release + " before upgrading";
        return null;
    }

    private static void print(Ui ui, String label, int checked, int upToDate, List<Review> reviews, int threshold, int suspicious, boolean all, long now) {
        ui.title("Malicious Release Guard " + ui.dot() + " " + label);
        ui.note(Ui.plural(checked, "artifact") + " checked " + ui.dot() + " " + upToDate + " already on the newest release " + ui.dot()
                + " " + Ui.plural(reviews.size(), "new release") + " reviewed");
        if (reviews.isEmpty()) {
            ui.println();
            ui.good("No newer releases to review");
            return;
        }
        int shown = 0;
        for (Review r : reviews) {
            if (r.error != null) {
                ui.println();
                ui.warn(r.ga + " " + r.inUse + " " + ui.arrow() + " " + r.release + ": could not be inspected (" + r.error + ")");
                continue;
            }
            if (r.score == 0 && !all) continue;
            shown++;
            ui.println();
            String lvl = r.score >= threshold ? ui.red(ui.bold("SUSPICIOUS")) : r.score >= 30 ? ui.yellow("REVIEW") : r.score > 0 ? ui.dim("low risk") : ui.green("clean");
            String mark = r.score >= threshold ? ui.bad() : r.score > 0 ? ui.warnMark() : ui.ok();
            ui.println(mark + " " + ui.bold(r.ga) + " " + r.inUse + " " + ui.arrow() + " " + ui.bold(r.release) + "  " + lvl + "  risk " + r.score + "/100"
                    + (r.published > 0 ? ui.dim("  released " + Ui.ago(r.published)) : ""));
            for (Signal s : r.signals) ui.println("    " + ui.dim(String.format(Locale.ROOT, "+%-3d", s.weight)) + " " + s.id + ui.dim(": ") + s.detail);
            String rec = recommendation(r, threshold);
            if (rec != null && r.score >= threshold) ui.println("    " + ui.yellow(ui.arrow() + " " + rec));
        }
        int clean = 0;
        for (Review r : reviews) if (r.score == 0 && r.error == null) clean++;
        ui.println();
        if (clean > 0 && !all) ui.note(Ui.plural(clean, "release") + " with no risk signals (--all lists them)");
        if (suspicious > 0) ui.fail(Ui.plural(suspicious, "suspicious release") + " (score >= " + threshold + ")");
        else if (shown > 0) ui.good("No release reaches the risk threshold (" + threshold + ")");
        else ui.good("No risk signals in " + Ui.plural(reviews.size(), "new release"));
    }
}
