package in.slashmark.maven.tools;

import in.slashmark.maven.analysis.Licenses;
import in.slashmark.maven.cli.Args;
import in.slashmark.maven.cli.Command;
import in.slashmark.maven.cli.Ctx;
import in.slashmark.maven.cli.Ui;
import in.slashmark.maven.model.Gav;
import in.slashmark.maven.model.MavenVersion;
import in.slashmark.maven.resolve.DepNode;
import in.slashmark.maven.util.Json;
import in.slashmark.maven.watch.Watcher;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** License Change Alert: Flag when a dependency's new release changes license, and enforce your license policy. */
public final class LicenseWatch extends Command {
    @Override public String name() { return "license-watch"; }
    @Override public String title() { return "License Change Alert"; }
    @Override public String group() { return "Live compliance"; }
    @Override public String summary() { return "Flag when a dependency's new release changes license, and enforce your license policy"; }

    /** Applied when neither --allow nor --deny is given. */
    static final List<String> DEFAULT_DENY = List.of("STRONG_COPYLEFT", "NETWORK_COPYLEFT", "SOURCE_AVAILABLE");

    @Override
    public Set<String> flags() { return Set.of("include-test"); }

    @Override
    public String help() {
        return String.join("\n",
                "Usage: sm-maven license-watch [group:artifact[:version]] [options]",
                "",
                summary() + ".",
                "",
                "For every resolved dependency, compares the license of the version in use with the newer",
                "releases on the repository and reports relicensing (e.g. Apache-2.0 -> BUSL-1.1) with the first",
                "version that changed. It also enforces a license policy on the current tree. Licenses are read",
                "from the effective POMs (parents included) and normalised to SPDX ids. With --watch it keeps",
                "checking and alerts your channels when a dependency is relicensed.",
                "",
                "Options:",
                "  --allow <patterns>     Allowed licenses (allowlist mode): SPDX ids, prefixes like LGPL-*, or",
                "                         categories: permissive, weak-copyleft, strong-copyleft,",
                "                         network-copyleft, source-available, public-domain, unknown",
                "  --deny <patterns>      Forbidden licenses (default when neither is given: strong-copyleft,",
                "                         network-copyleft, source-available)",
                "  --include-test         Also check test-scoped dependencies",
                "",
                Watcher.HELP,
                "",
                "Examples:",
                "  sm-maven license-watch",
                "  sm-maven license-watch --allow permissive,weak-copyleft",
                "  sm-maven license-watch --deny 'GPL-*,AGPL-*,BUSL-1.1' --watch --interval 6h",
                "  sm-maven license-watch org.example:widgets:1.0.0");
    }

    /** What one cycle saw, for the human printer. */
    private static final class Seen {
        final Map<String, Integer> categories = new LinkedHashMap<>();
        int dependencies;
        int unknown;
    }

    @Override
    public int run(Ctx ctx, Args args) throws Exception {
        List<String> allow = normalise(args.getAll("allow")), deny = normalise(args.getAll("deny"));
        boolean defaultPolicy = allow.isEmpty() && deny.isEmpty();
        List<String> effDeny = defaultPolicy ? DEFAULT_DENY : deny;
        Set<String> scopes = args.flag("include-test") ? null : Set.of("compile", "runtime", "provided", "system");
        Ctx.Target target = ctx.target(args, 0);
        String scope = target.project != null ? target.project.root.resolve("pom.xml").toString() : target.label;
        Set<String> reactor = ctx.models.reactorGavs();
        Ui ui = ctx.ui;
        Seen seen = new Seen();

        Watcher.Cycle cycle = c -> {
            List<DepNode> nodes = new ArrayList<>();
            for (DepNode n : target.dependencies(scopes)) if (!reactor.contains(n.gav().toString())) nodes.add(n);
            if (target.artifact != null) nodes.add(0, null);   // the artifact itself
            ui.progress("Reading licenses of " + nodes.size() + " artifacts and their newer releases...");
            List<Object[]> results = ctx.http.parallelOrNull(nodes, n -> inspect(ctx, n == null ? target.artifact : n.gav()));
            ui.progressDone();
            seen.categories.clear();
            seen.unknown = 0;
            seen.dependencies = nodes.size();
            List<Watcher.Finding> out = new ArrayList<>();
            for (int i = 0; i < nodes.size(); i++) {
                DepNode n = nodes.get(i);
                Object[] r = results.get(i);
                if (r == null) continue;
                Gav gav = n == null ? target.artifact : n.gav();
                @SuppressWarnings("unchecked")
                List<String> cur = (List<String>) r[0];
                Licenses.Category cat = Licenses.bestOf(cur);
                seen.categories.merge(cat.label, 1, Integer::sum);
                if (cat == Licenses.Category.UNKNOWN) seen.unknown++;
                // ---- policy on the version in use
                String violation = violation(cur, allow, effDeny);
                if (violation != null) {
                    String sev = severityOf(cat);
                    Map<String, Object> j = Json.obj("type", "policy", "artifact", gav.toString(), "licenses", cur, "category", cat.label,
                            "rule", violation, "scope", n == null ? null : n.scope, "direct", n == null ? null : n.isDirect(),
                            "path", n == null ? null : n.pathString());
                    out.add(new Watcher.Finding("policy:" + gav + ":" + String.join("|", cur), sev,
                            gav + " is " + UpgradeKit.licenseText(cur) + " (" + cat.label + "): " + violation + (n == null || n.isDirect() ? "" : " via " + n.path().get(0).ga()), j));
                }
                // ---- relicensing in newer releases
                String changedIn = (String) r[1];
                if (changedIn != null) {
                    @SuppressWarnings("unchecked")
                    List<String> now = (List<String>) r[2];
                    String newest = (String) r[3];
                    Licenses.Category nc = Licenses.bestOf(now);
                    boolean worse = Licenses.rank(nc) > Licenses.rank(cat);
                    String newViolation = violation(now, allow, effDeny);
                    String sev = newViolation != null ? "high" : worse ? "medium" : "low";
                    if (worse && (nc == Licenses.Category.SOURCE_AVAILABLE || nc == Licenses.Category.NETWORK_COPYLEFT)) sev = "high";
                    Map<String, Object> j = Json.obj("type", "relicense", "artifact", gav.ga(), "current", gav.version, "currentLicenses", cur,
                            "fromCategory", cat.label, "changedIn", changedIn, "licenses", now, "category", nc.label, "newest", newest,
                            "moreRestrictive", worse, "policyViolation", newViolation);
                    out.add(new Watcher.Finding("relicense:" + gav.ga() + ":" + changedIn + ":" + String.join("|", now), sev,
                            gav.ga() + " " + changedIn + " is relicensed " + UpgradeKit.licenseText(cur) + " -> " + UpgradeKit.licenseText(now)
                                    + " (" + nc.label + "); you use " + gav.version + (newViolation != null ? ": " + newViolation : ""), j));
                }
            }
            return out;
        };

        Watcher.Printer printer = (all, fresh, cyc, baseline) -> {
            if (cyc == 1) {
                ui.title(title() + " " + ui.dot() + " " + target.label);
                String pol = defaultPolicy ? "deny strong-copyleft, network-copyleft, source-available (default)"
                        : (allow.isEmpty() ? "" : "allow " + String.join(", ", allow)) + (allow.isEmpty() || deny.isEmpty() ? "" : "; ") + (deny.isEmpty() ? "" : "deny " + String.join(", ", deny));
                ui.note("Policy: " + pol);
            }
            List<String> parts = new ArrayList<>();
            for (Map.Entry<String, Integer> e : seen.categories.entrySet()) parts.add(e.getValue() + " " + e.getKey());
            ui.section("Licenses of " + Ui.plural(seen.dependencies, "artifact"));
            ui.line(String.join(", ", parts));
            List<Watcher.Finding> rel = new ArrayList<>(), pol = new ArrayList<>();
            for (Watcher.Finding f : all) (f.key.startsWith("relicense:") ? rel : pol).add(f);
            ui.section("Relicensed in newer releases");
            if (rel.isEmpty()) ui.good("no dependency changed its license in a newer release");
            for (Watcher.Finding f : rel) print(ui, f, fresh.contains(f.key) && !baseline);
            ui.section("Policy violations");
            if (pol.isEmpty()) ui.good("every license complies with the policy");
            for (Watcher.Finding f : pol) print(ui, f, fresh.contains(f.key) && !baseline);
            ui.println();
            if (all.isEmpty()) ui.good("No license issues.");
            else ui.println(ui.bold(Ui.plural(all.size(), "license issue")) + (fresh.isEmpty() || baseline ? "" : ", " + fresh.size() + " new")
                    + (baseline ? ui.dim("  (recorded as baseline)") : ""));
        };
        return Watcher.run(ctx, args, name(), scope, "license issues", cycle, printer);
    }

    private static void print(Ui ui, Watcher.Finding f, boolean isNew) {
        String tag = isNew ? ui.bold(ui.magenta("NEW ")) : "";
        String line = tag + ui.severity(f.severity) + " " + f.line;
        if ("high".equals(f.severity) || "critical".equals(f.severity)) ui.fail(line);
        else ui.warn(line);
        String path = Json.str(f.json, "path");
        if (path != null && path.contains(" -> ")) ui.line("    " + ui.dim("path: " + path));
    }

    /**
     * Current licenses, and when a newer release has different ones: {current, firstChangedVersion,
     * newLicenses, newest}.
     */
    private static Object[] inspect(Ctx ctx, Gav gav) throws Exception {
        List<String> cur = UpgradeKit.licenses(ctx, gav);
        List<String> newer = new ArrayList<>();
        MavenVersion mv = MavenVersion.of(gav.version);
        for (String v : ctx.versions(gav.groupId, gav.artifactId, true)) if (MavenVersion.of(v).compareTo(mv) > 0) newer.add(v);
        if (newer.isEmpty()) return new Object[] {cur, null, null, gav.version};
        String newest = newer.get(newer.size() - 1);
        List<String> latest = UpgradeKit.licenses(ctx, gav.withVersion(newest));
        if (latest.equals(cur)) return new Object[] {cur, null, null, newest};
        // Find the first release with the new license (oldest first, at most the 30 newest releases).
        String first = newest;
        List<String> window = newer.size() > 30 ? newer.subList(newer.size() - 30, newer.size()) : newer;
        for (String v : window) {
            if (UpgradeKit.licenses(ctx, gav.withVersion(v)).equals(latest)) {
                first = v;
                break;
            }
        }
        return new Object[] {cur, first, latest, newest};
    }

    /** Why licenses break the policy (null when fine). Dual-licensed artifacts comply when one option does. */
    static String violation(List<String> ids, List<String> allow, List<String> deny) {
        if (ids.isEmpty()) {
            if (!allow.isEmpty() && !containsUnknown(allow)) return "no license declared (not on the allowlist)";
            if (containsUnknown(deny)) return "no license declared (denied: unknown)";
            return null;
        }
        String firstReason = null;
        for (String id : ids) {
            boolean unknown = Licenses.category(id) == Licenses.Category.UNKNOWN;
            String reason = null;
            if (!allow.isEmpty() && !Licenses.matches(id, allow) && !(unknown && containsUnknown(allow))) reason = id + " is not on the allowlist";
            if (reason == null && (Licenses.matches(id, deny) || (unknown && containsUnknown(deny)))) reason = id + " is denied by " + matchingPattern(id, deny);
            if (reason == null) return null;
            if (firstReason == null) firstReason = reason;
        }
        return firstReason;
    }

    private static boolean containsUnknown(List<String> patterns) {
        for (String p : patterns) if (p.equalsIgnoreCase("UNKNOWN")) return true;
        return false;
    }

    private static String matchingPattern(String id, List<String> patterns) {
        for (String p : patterns) if (Licenses.matches(id, List.of(p))) return p.matches("[A-Z_]+") ? p.toLowerCase(java.util.Locale.ROOT).replace('_', '-') : p;
        return "unknown";
    }

    /** "weak-copyleft" -> WEAK_COPYLEFT so categories can be written either way. */
    static List<String> normalise(List<String> patterns) {
        List<String> out = new ArrayList<>();
        for (String p : patterns) {
            String u = p.trim().toUpperCase(java.util.Locale.ROOT).replace('-', '_').replace(' ', '_');
            boolean category = false;
            for (Licenses.Category c : Licenses.Category.values()) if (c.name().equals(u)) category = true;
            if (u.equals("SOURCE_AVAILABLE") || u.equals("PUBLIC_DOMAIN")) category = true;
            out.add(category ? u : p.trim());
        }
        return out;
    }

    private static String severityOf(Licenses.Category c) {
        switch (c) {
            case NETWORK_COPYLEFT: case SOURCE_AVAILABLE: case STRONG_COPYLEFT: return "high";
            case UNKNOWN: case WEAK_COPYLEFT: return "medium";
            default: return "low";
        }
    }
}
