package in.slashmark.maven.tools;

import in.slashmark.maven.cli.Args;
import in.slashmark.maven.cli.Command;
import in.slashmark.maven.cli.Ctx;
import in.slashmark.maven.cli.Project;
import in.slashmark.maven.cli.Ui;
import in.slashmark.maven.cli.UsageException;
import in.slashmark.maven.data.CentralSearch;
import in.slashmark.maven.model.Gav;
import in.slashmark.maven.model.MavenVersion;
import in.slashmark.maven.resolve.DepNode;
import in.slashmark.maven.util.Http;
import in.slashmark.maven.util.Json;
import in.slashmark.maven.watch.Watcher;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/** Namespace Takeover Watch: Detect look-alike groupIds and dependency-confusion risks for your namespaces. */
public final class Takeover extends Command {
    @Override public String name() { return "takeover"; }
    @Override public String title() { return "Namespace Takeover Watch"; }
    @Override public String group() { return "Live threat intelligence"; }
    @Override public String summary() { return "Detect look-alike groupIds and dependency-confusion risks for your namespaces"; }

    @Override
    public String help() {
        return String.join("\n",
                "Usage: sm-maven takeover [group:artifact[:version]] [options]",
                "",
                summary() + ".",
                "",
                "Your namespaces are the groupIds of the project's modules, their organisation root (com.acme for",
                "com.acme.shop) and any --group. The tool searches Maven Central live for:",
                "  look-alikes   groupIds one keystroke or homoglyph away (com.acrne, com.acmee, org.acme...),",
                "                found by probing variants and by searching your artifact names in other groups",
                "  claimed       internal-looking namespaces of yours (com.acme.internal, .private, .corp...) that",
                "                are published publicly - the dependency-confusion setup",
                "For each hit it lists the artifacts, release age, signing key and why it is suspicious. It is",
                "watch-capable: repeated runs report and alert only on new namespaces.",
                "",
                "Options:",
                "  --group <groupId>      Also protect this namespace (repeatable)",
                "  --internal <groupId>   Also check this internal namespace (repeatable)",
                "  --no-probe             Skip probing typo/homoglyph variants (only artifact-name search)",
                "  --max-probes <n>       Upper bound for variant lookups per check (default 400)",
                "",
                Watcher.HELP,
                "  --cycles <n>           Stop after n checks (watch mode)",
                "  --state <file>         Keep the seen-namespace state in this file",
                "",
                "Examples:",
                "  sm-maven takeover",
                "  sm-maven takeover --group in.slashmark --internal in.slashmark.platform",
                "  sm-maven takeover --watch --interval 6h");
    }

    @Override public Set<String> flags() { return Set.of("no-probe"); }

    static final List<String> INTERNAL_SEGMENTS = List.of("internal", "private", "corp", "intranet", "priv", "infra", "platform-internal");
    static final Map<String, List<String>> TLD_SWAPS = Map.of(
            "com", List.of("org", "net", "io", "co", "cm", "corn", "comm", "con", "dev"),
            "org", List.of("com", "net", "io", "orq", "ogr"),
            "net", List.of("com", "org", "io", "nett"),
            "io", List.of("com", "org", "dev", "lo"),
            "in", List.of("com", "org", "co", "ln"),
            "dev", List.of("com", "io", "org"));
    static final String[][] HOMOGLYPHS = {{"m", "rn"}, {"rn", "m"}, {"w", "vv"}, {"vv", "w"}, {"d", "cl"}, {"cl", "d"}, {"l", "1"}, {"1", "l"},
            {"i", "l"}, {"l", "i"}, {"o", "0"}, {"0", "o"}, {"i", "1"}, {"s", "5"}, {"e", "3"}, {"a", "4"}};
    static final Map<Character, String> QWERTY = new LinkedHashMap<>();
    static {
        String[] rows = {"qwertyuiop", "asdfghjkl", "zxcvbnm"};
        for (int r = 0; r < rows.length; r++) {
            for (int c = 0; c < rows[r].length(); c++) {
                StringBuilder n = new StringBuilder();
                if (c > 0) n.append(rows[r].charAt(c - 1));
                if (c < rows[r].length() - 1) n.append(rows[r].charAt(c + 1));
                QWERTY.put(rows[r].charAt(c), n.toString());
            }
        }
    }

    /** A namespace variant to probe: what it imitates and how. */
    static final class Variant {
        final String groupId, imitates, technique;

        Variant(String groupId, String imitates, String technique) {
            this.groupId = groupId;
            this.imitates = imitates;
            this.technique = technique;
        }
    }

    @Override
    public int run(Ctx ctx, Args args) throws Exception {
        List<String> extraGroups = args.getAll("group");
        List<String> extraInternal = args.getAll("internal");
        for (String g : extraGroups) checkGroup("group", g);
        for (String g : extraInternal) checkGroup("internal", g);
        boolean probe = !args.flag("no-probe");
        int maxProbes = args.getInt("max-probes", 400);
        if (maxProbes < 1) throw new UsageException("--max-probes expects a positive number");
        // Namespace claims are live data: always ask Central.
        ctx.search.setTtl(0);

        Ctx.Target target = ctx.target(args, 0);
        Project project = target.project;
        Set<String> ownGroups = new LinkedHashSet<>();
        Set<String> ownArtifacts = new TreeSet<>();
        if (project != null) {
            for (Project.Module m : project.modules) {
                ownGroups.add(m.model.pom.groupId);
                ownArtifacts.add(m.model.pom.artifactId);
            }
        } else {
            ownGroups.add(target.artifact.groupId);
            ownArtifacts.add(target.artifact.artifactId);
        }
        ownGroups.addAll(extraGroups);
        Set<String> roots = new LinkedHashSet<>();
        for (String g : ownGroups) roots.add(root(g));
        Set<String> namespaces = new LinkedHashSet<>(roots);
        namespaces.addAll(ownGroups);

        // Dependencies: which groups the build uses, and own-namespace artifacts (names worth squatting).
        Map<String, Set<String>> used = new LinkedHashMap<>();
        List<DepNode> deps = target.dependencies(null);
        for (DepNode n : deps) {
            if (ctx.models.inReactor(n.gav())) continue;
            used.computeIfAbsent(n.groupId, k -> new TreeSet<>()).add(n.artifactId);
            if (isOwn(n.groupId, roots)) ownArtifacts.add(n.artifactId);
        }
        // Keys that legitimately sign your namespaces' artifacts.
        Set<String> ownKeys = new LinkedHashSet<>();
        List<DepNode> ownDeps = new ArrayList<>();
        for (DepNode n : deps) if (isOwn(n.groupId, roots) && !ctx.models.inReactor(n.gav()) && ownDeps.size() < 8) ownDeps.add(n);
        for (ThreatSupport.Signer s : ctx.http.parallelOrNull(ownDeps, n -> ThreatSupport.signer(ctx, n.gav(), !"pom".equals(n.type)))) {
            if (s != null && s.keyId != null) ownKeys.add(s.keyId);
        }

        String scope = project != null ? project.rootModule().pom.toString() : target.label;
        Watcher.Cycle cycle = c -> collect(ctx, roots, ownGroups, namespaces, ownArtifacts, used, ownKeys, extraInternal, probe, maxProbes);
        Watcher.Printer printer = (all, fresh, c, baseline) -> print(ctx.ui, target.label, namespaces, all, fresh, c, baseline);
        return Watcher.run(ctx, args, name(), scope, "namespace threats", cycle, printer);
    }

    private static void checkGroup(String option, String g) {
        if (!g.matches("[A-Za-z0-9_\\-]+(\\.[A-Za-z0-9_\\-]+)*")) throw new UsageException("--" + option + " expects a groupId like com.example, got '" + g + "'");
    }

    /** Organisation root: the first two segments of a groupId with three or more (com.acme for com.acme.shop). */
    static String root(String g) {
        String[] p = g.split("\\.");
        return p.length >= 3 ? p[0] + "." + p[1] : g;
    }

    static boolean isOwn(String g, Set<String> roots) {
        for (String r : roots) if (g.equals(r) || g.startsWith(r + ".")) return true;
        return false;
    }

    // ---------------------------------------------------------------- one check

    private List<Watcher.Finding> collect(Ctx ctx, Set<String> roots, Set<String> ownGroups, Set<String> namespaces, Set<String> ownArtifacts,
                                          Map<String, Set<String>> used, Set<String> ownKeys, List<String> extraInternal,
                                          boolean probe, int maxProbes) throws Exception {
        // 1. Look-alike candidates: variants of each root, also with the rest of each own groupId appended.
        Map<String, Variant> candidates = new LinkedHashMap<>();
        if (probe) {
            for (String r : roots) {
                for (Variant v : variants(r)) {
                    if (isOwn(v.groupId, roots)) continue;
                    candidates.putIfAbsent(v.groupId, v);
                    for (String g : ownGroups) {
                        if (g.startsWith(r + ".")) {
                            String full = v.groupId + g.substring(r.length());
                            candidates.putIfAbsent(full, new Variant(full, g, v.technique));
                        }
                    }
                }
            }
        }
        List<String> probes = new ArrayList<>(candidates.keySet());
        if (probes.size() > maxProbes) probes = new ArrayList<>(probes.subList(0, maxProbes));

        // 2. Internal-looking namespaces of yours.
        Map<String, String> internal = new LinkedHashMap<>(); // groupId -> why it looks internal
        for (String ns : namespaces) for (String s : INTERNAL_SEGMENTS) internal.putIfAbsent(ns + "." + s, "internal-looking sub-namespace of " + ns);
        for (String g : used.keySet()) if (looksInternal(g)) internal.putIfAbsent(g, "the build depends on it and it looks internal");
        for (String g : ownGroups) if (looksInternal(g)) internal.putIfAbsent(g, "one of your own groupIds and it looks internal");
        for (String g : extraInternal) internal.put(g, "declared internal (--internal)");

        List<String> lookups = new ArrayList<>(probes);
        for (String g : internal.keySet()) if (!lookups.contains(g)) lookups.add(g);
        ctx.ui.progress("Searching Central for " + Ui.plural(lookups.size(), "namespace") + "...");
        List<Http.Result<CentralSearch.Result>> res = ctx.http.parallel(lookups, g -> ctx.search.group(g, 50));
        // 3. Your artifact names published under other, similar groups.
        List<String> names = new ArrayList<>(ownArtifacts);
        List<Http.Result<CentralSearch.Result>> byName = ctx.http.parallel(names, a -> ctx.search.artifact(a, 100));
        ctx.ui.progressDone();
        int failures = 0;
        Exception firstError = null;
        Map<String, List<CentralSearch.Doc>> hits = new LinkedHashMap<>();
        for (int i = 0; i < lookups.size(); i++) {
            Http.Result<CentralSearch.Result> r = res.get(i);
            if (!r.ok()) {
                failures++;
                if (firstError == null) firstError = r.error;
                continue;
            }
            if (r.value.numFound > 0) {
                List<CentralSearch.Doc> docs = new ArrayList<>();
                for (CentralSearch.Doc d : r.value.docs) if (lookups.get(i).equals(d.groupId)) docs.add(d);
                if (!docs.isEmpty()) hits.put(lookups.get(i), docs);
            }
        }
        if (failures == lookups.size() && firstError != null && !lookups.isEmpty()) throw firstError;
        if (failures > 0) ctx.ui.warnErr(failures + " namespace lookups failed; results may be incomplete");
        Map<String, Set<String>> collisions = new LinkedHashMap<>(); // lookalike group -> your artifact names it reuses
        for (int i = 0; i < names.size(); i++) {
            Http.Result<CentralSearch.Result> r = byName.get(i);
            if (!r.ok()) continue;
            for (CentralSearch.Doc d : r.value.docs) {
                if (d.groupId == null || isOwn(d.groupId, roots)) continue;
                Variant v = candidates.get(d.groupId);
                if (v == null) v = similar(d.groupId, roots, ownGroups);
                if (v == null) continue;
                candidates.putIfAbsent(d.groupId, v);
                collisions.computeIfAbsent(d.groupId, k -> new TreeSet<>()).add(d.artifactId);
                if (!hits.containsKey(d.groupId)) {
                    try {
                        CentralSearch.Result full = ctx.search.group(d.groupId, 50);
                        List<CentralSearch.Doc> docs = new ArrayList<>();
                        for (CentralSearch.Doc x : full.docs) if (d.groupId.equals(x.groupId)) docs.add(x);
                        hits.put(d.groupId, docs.isEmpty() ? new ArrayList<>(List.of(d)) : docs);
                    } catch (Exception e) {
                        hits.put(d.groupId, new ArrayList<>(List.of(d)));
                    }
                }
            }
        }

        List<Watcher.Finding> out = new ArrayList<>();
        long now = System.currentTimeMillis();
        for (Map.Entry<String, List<CentralSearch.Doc>> e : hits.entrySet()) {
            String g = e.getKey();
            boolean isInternal = internal.containsKey(g) && !candidates.containsKey(g);
            Variant v = candidates.get(g);
            if (!isInternal && v == null) continue;
            out.add(finding(ctx, g, e.getValue(), isInternal, v, isInternal ? internal.get(g) : null, collisions.getOrDefault(g, Set.of()),
                    used, ownKeys, roots, now));
        }
        out.sort((a, b) -> Integer.compare(rank(b.severity), rank(a.severity)));
        return out;
    }

    private static int rank(String s) {
        switch (s) {
            case "critical": return 4;
            case "high": return 3;
            case "medium": return 2;
            default: return 1;
        }
    }

    static boolean looksInternal(String g) {
        for (String seg : g.split("\\.")) {
            String s = seg.toLowerCase(Locale.ROOT);
            if (INTERNAL_SEGMENTS.contains(s) || s.endsWith("-internal") || s.equals("intern")) return true;
        }
        return false;
    }

    private static Watcher.Finding finding(Ctx ctx, String g, List<CentralSearch.Doc> docs, boolean internal, Variant v, String internalWhy,
                                           Set<String> collisions, Map<String, Set<String>> used, Set<String> ownKeys, Set<String> roots, long now) {
        List<String> reasons = new ArrayList<>();
        List<Object> artifacts = new ArrayList<>();
        Set<String> keys = new TreeSet<>();
        long newest = 0;
        String highVersion = null;
        List<CentralSearch.Doc> top = docs.subList(0, Math.min(docs.size(), 10));
        List<ThreatSupport.Signer> signers = ctx.http.parallelOrNull(top, d -> d.latestVersion == null ? null
                : ThreatSupport.signer(ctx, new Gav(d.groupId, d.artifactId, d.latestVersion), !"pom".equals(d.packaging)));
        Set<String> names = new TreeSet<>();
        for (int i = 0; i < docs.size(); i++) {
            CentralSearch.Doc d = docs.get(i);
            ThreatSupport.Signer s = i < signers.size() ? signers.get(i) : null;
            if (s != null && s.keyId != null) keys.add(s.keyId);
            newest = Math.max(newest, d.timestamp);
            names.add(d.artifactId);
            if (d.latestVersion != null && MavenVersion.of(d.latestVersion).major() >= 50) highVersion = d.groupId + ":" + d.artifactId + ":" + d.latestVersion;
            artifacts.add(Json.obj("artifact", d.groupId + ":" + d.artifactId, "latestVersion", d.latestVersion, "versions", d.versionCount > 0 ? d.versionCount : null,
                    "publishedAt", d.timestamp > 0 ? java.time.Instant.ofEpochMilli(d.timestamp).toString() : null,
                    "signedBy", s == null ? null : s.keyId));
        }
        Set<String> inUse = used.getOrDefault(g, Set.of());
        String severity;
        if (internal) {
            reasons.add(internalWhy + ", yet " + Ui.plural(docs.size(), "artifact is", "artifacts are") + " published publicly");
            severity = inUse.isEmpty() ? "high" : "critical";
            if (!inUse.isEmpty()) reasons.add("the build resolves " + String.join(", ", inUse) + " from this namespace: it may already be getting the public artifact");
        } else {
            reasons.add(describe(v));
            boolean homoglyph = v.technique.equals("homoglyph");
            severity = !inUse.isEmpty() ? "critical" : homoglyph || !collisions.isEmpty() ? "high" : "medium";
            if (!collisions.isEmpty()) reasons.add("reuses your artifact name" + (collisions.size() > 1 ? "s " : " ") + String.join(", ", collisions));
            if (!inUse.isEmpty()) reasons.add("the build already depends on " + g + ":" + String.join(", ", inUse) + " - check this is intended");
        }
        if (highVersion != null) reasons.add("suspiciously high version " + highVersion.substring(highVersion.lastIndexOf(':') + 1) + " (dependency-confusion pattern: wins any version range)");
        if (newest > 0 && now - newest < 30 * 86_400_000L) reasons.add("published " + Ui.ago(newest));
        Set<String> foreign = new TreeSet<>(keys);
        foreign.removeAll(ownKeys);
        if (!foreign.isEmpty() && !ownKeys.isEmpty()) reasons.add("signed with " + String.join(", ", foreign) + ", not a key that signs your artifacts");
        else if (!foreign.isEmpty()) reasons.add("signed with " + String.join(", ", foreign));

        String type = internal ? "internal-claimed" : "lookalike";
        Map<String, Object> j = new LinkedHashMap<>();
        j.put("type", type);
        j.put("groupId", g);
        j.put("imitates", internal ? null : v.imitates);
        j.put("technique", internal ? null : v.technique);
        j.put("severity", severity);
        j.put("artifacts", artifacts);
        j.put("collidesWith", new ArrayList<>(collisions));
        j.put("inUse", !inUse.isEmpty());
        j.put("signingKeys", new ArrayList<>(keys));
        j.put("newestRelease", newest > 0 ? java.time.Instant.ofEpochMilli(newest).toString() : null);
        j.put("reasons", reasons);
        String line = (internal ? "Internal namespace " + g + " is published publicly" : "Look-alike namespace " + g + " imitates " + v.imitates + " (" + v.technique + ")")
                + ": " + String.join(", ", names);
        String key = type + ":" + g + "[" + String.join(",", names) + "]";
        return new Watcher.Finding(key, severity, line, j);
    }

    static String describe(Variant v) {
        switch (v.technique) {
            case "homoglyph": return "homoglyph of " + v.imitates + " (looks identical in many fonts)";
            case "tld-swap": return "same name as " + v.imitates + " under another top-level domain";
            case "brand-reuse": return "reuses the name of " + v.imitates + " in another namespace";
            default: return "one typo away from " + v.imitates + " (" + v.technique + ")";
        }
    }

    // ---------------------------------------------------------------- variants

    /** Typo, homoglyph and TLD variants of a namespace (only the distinctive segments are altered). */
    static List<Variant> variants(String ns) {
        String[] seg = ns.split("\\.");
        Map<String, Variant> out = new LinkedHashMap<>();
        if (seg.length >= 2) {
            for (String t : TLD_SWAPS.getOrDefault(seg[0], List.of())) {
                String[] c = seg.clone();
                c[0] = t;
                String g = String.join(".", c);
                out.putIfAbsent(g, new Variant(g, ns, t.equals("corn") ? "homoglyph" : "tld-swap"));
            }
        }
        for (int i = seg.length >= 2 ? 1 : 0; i < seg.length; i++) {
            String s = seg[i];
            if (s.length() < 3) continue;
            Map<String, String> vs = new LinkedHashMap<>();
            for (String[] h : HOMOGLYPHS) {
                int from = 0;
                while (true) {
                    int at = s.indexOf(h[0], from);
                    if (at < 0) break;
                    vs.putIfAbsent(s.substring(0, at) + h[1] + s.substring(at + h[0].length()), "homoglyph");
                    from = at + 1;
                }
            }
            for (int k = 0; k < s.length(); k++) vs.putIfAbsent(s.substring(0, k) + s.substring(k + 1), "omission");
            for (int k = 0; k < s.length(); k++) vs.putIfAbsent(s.substring(0, k + 1) + s.charAt(k) + s.substring(k + 1), "repetition");
            for (int k = 0; k + 1 < s.length(); k++) {
                if (s.charAt(k) == s.charAt(k + 1)) continue;
                vs.putIfAbsent(s.substring(0, k) + s.charAt(k + 1) + s.charAt(k) + s.substring(k + 2), "transposition");
            }
            for (int k = 0; k < s.length(); k++) {
                String nb = QWERTY.get(Character.toLowerCase(s.charAt(k)));
                if (nb == null) continue;
                for (char c : nb.toCharArray()) vs.putIfAbsent(s.substring(0, k) + c + s.substring(k + 1), "keyboard-typo");
            }
            for (int k = 1; k < s.length(); k++) vs.putIfAbsent(s.substring(0, k) + "-" + s.substring(k), "hyphenation");
            vs.putIfAbsent(s + "s", "plural");
            for (Map.Entry<String, String> e : vs.entrySet()) {
                if (e.getKey().equals(s) || e.getKey().isEmpty()) continue;
                String[] c = seg.clone();
                c[i] = e.getKey();
                String g = String.join(".", c);
                out.putIfAbsent(g, new Variant(g, ns, e.getValue()));
            }
        }
        out.remove(ns);
        return new ArrayList<>(out.values());
    }

    /** For a group found by artifact-name search: is it a look-alike of one of your namespaces? */
    static Variant similar(String g, Set<String> roots, Set<String> ownGroups) {
        for (String r : roots) {
            String rootPart = root(g);
            if (skeleton(rootPart).equals(skeleton(r)) && !rootPart.equals(r)) return new Variant(g, r, "homoglyph");
            int d = distance(rootPart, r);
            if (d > 0 && d <= 2) return new Variant(g, r, "typo");
            String[] rs = r.split("\\.");
            String[] gs = rootPart.split("\\.");
            if (rs.length == 2 && gs.length == 2 && rs[1].equals(gs[1]) && !rs[0].equals(gs[0])) return new Variant(g, r, "tld-swap");
            if (rs.length == 2 && rs[1].length() >= 4) {
                for (String seg : g.split("\\.")) {
                    if (seg.equals(rs[1]) || seg.startsWith(rs[1] + "-") || seg.endsWith("-" + rs[1])) return new Variant(g, r, "brand-reuse");
                }
            }
        }
        for (String own : ownGroups) {
            int d = distance(g, own);
            if (d > 0 && d <= 2) return new Variant(g, own, "typo");
        }
        return null;
    }

    static String skeleton(String s) {
        return s.toLowerCase(Locale.ROOT).replace("rn", "m").replace("vv", "w").replace("cl", "d").replace('1', 'l').replace('0', 'o')
                .replace('5', 's').replace('3', 'e').replace('4', 'a').replace('i', 'l');
    }

    /** Damerau-Levenshtein (optimal string alignment) distance. */
    static int distance(String a, String b) {
        int[][] d = new int[a.length() + 1][b.length() + 1];
        for (int i = 0; i <= a.length(); i++) d[i][0] = i;
        for (int j = 0; j <= b.length(); j++) d[0][j] = j;
        for (int i = 1; i <= a.length(); i++) {
            for (int j = 1; j <= b.length(); j++) {
                int cost = a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1;
                d[i][j] = Math.min(Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1), d[i - 1][j - 1] + cost);
                if (i > 1 && j > 1 && a.charAt(i - 1) == b.charAt(j - 2) && a.charAt(i - 2) == b.charAt(j - 1)) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
            }
        }
        return d[a.length()][b.length()];
    }

    // ---------------------------------------------------------------- output

    @SuppressWarnings("unchecked")
    private static void print(Ui ui, String label, Set<String> namespaces, List<Watcher.Finding> all, Set<String> fresh, int cycle, boolean baseline) {
        if (cycle == 1) {
            ui.title("Namespace Takeover Watch " + ui.dot() + " " + label);
            ui.note("Protecting " + String.join(", ", namespaces));
        }
        ui.section("Check #" + cycle + " at " + java.time.Instant.now().toString().substring(11, 19) + " UTC");
        if (all.isEmpty()) {
            ui.good("No look-alike or publicly claimed internal namespaces found on Central");
            return;
        }
        List<Watcher.Finding> ordered = new ArrayList<>();
        for (Watcher.Finding f : all) if (fresh.contains(f.key)) ordered.add(f);
        for (Watcher.Finding f : all) if (!fresh.contains(f.key)) ordered.add(f);
        for (Watcher.Finding f : ordered) {
            Map<String, Object> j = (Map<String, Object>) f.json;
            boolean isNew = fresh.contains(f.key) && !baseline;
            String head = "internal-claimed".equals(j.get("type"))
                    ? "Internal namespace " + ui.bold(String.valueOf(j.get("groupId"))) + " is claimed on Central"
                    : "Look-alike " + ui.bold(String.valueOf(j.get("groupId"))) + " imitates " + j.get("imitates") + ui.dim(" (" + j.get("technique") + ")");
            ui.println();
            ui.println((rank(f.severity) >= 3 ? ui.bad() : ui.warnMark()) + " " + (isNew ? ui.yellow("NEW ") : "") + ui.severity(f.severity) + "  " + head);
            for (Object a : (List<Object>) j.get("artifacts")) {
                String pub = Json.str(a, "publishedAt");
                String key = Json.str(a, "signedBy");
                ui.println("    " + Json.str(a, "artifact") + ":" + Json.str(a, "latestVersion")
                        + ui.dim((pub == null ? "" : "  published " + pub.substring(0, 10)) + (key == null ? "" : "  key " + key)));
            }
            for (Object r : (List<Object>) j.get("reasons")) ui.println("    " + ui.dim("- ") + r);
        }
        ui.println();
        int n = fresh.size();
        if (baseline) ui.good("Baseline recorded: " + Ui.plural(all.size(), "namespace threat") + " known; future checks alert only on new ones");
        else if (n == 0) ui.good("No new namespace threats since the last check (" + all.size() + " known)");
        else {
            ui.fail(Ui.plural(n, "new namespace threat") + " (" + all.size() + " in total)");
            ui.note("  Block these groupIds in your repository manager, pin internal artifacts to your private repository,");
            ui.note("  and report impersonation to Central (https://central.sonatype.org/faq/report-malicious-artifact/).");
        }
    }
}
