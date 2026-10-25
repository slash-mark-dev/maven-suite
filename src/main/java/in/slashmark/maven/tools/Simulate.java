package in.slashmark.maven.tools;

import in.slashmark.maven.analysis.Licenses;
import in.slashmark.maven.bytecode.ApiDiff;
import in.slashmark.maven.bytecode.Jar;
import in.slashmark.maven.cli.Args;
import in.slashmark.maven.cli.Command;
import in.slashmark.maven.cli.Ctx;
import in.slashmark.maven.cli.Exit;
import in.slashmark.maven.cli.Project;
import in.slashmark.maven.cli.Ui;
import in.slashmark.maven.cli.UsageException;
import in.slashmark.maven.data.Osv;
import in.slashmark.maven.model.Dependency;
import in.slashmark.maven.model.Gav;
import in.slashmark.maven.model.MavenVersion;
import in.slashmark.maven.resolve.DepNode;
import in.slashmark.maven.resolve.Graph;
import in.slashmark.maven.resolve.Resolver;
import in.slashmark.maven.util.Json;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Upgrade Simulator: Resolve the upgraded tree and check conflicts, vulnerabilities and API breaks first. */
public final class Simulate extends Command {
    @Override public String name() { return "simulate"; }
    @Override public String title() { return "Upgrade Simulator"; }
    @Override public String group() { return "Upgrade intelligence"; }
    @Override public String summary() { return "Resolve the upgraded tree and check conflicts, vulnerabilities and API breaks first"; }

    @Override
    public Set<String> flags() { return Set.of("all-latest", "minor", "patch", "pre", "no-api"); }

    @Override
    public String help() {
        return String.join("\n",
                "Usage: sm-maven simulate <group:artifact[:version]>... [options]",
                "       sm-maven simulate --all-latest | --minor | --patch [options]",
                "",
                summary() + ".",
                "",
                "Re-resolves every module with the upgrade applied (exactly as Maven would: a direct dependency",
                "gets the new version, a transitive one is pinned through dependencyManagement) and reports:",
                "  - the full before/after dependency tree diff, including transitive upgrades, downgrades,",
                "    added and removed artifacts and new version conflicts",
                "  - vulnerabilities fixed and introduced (OSV)",
                "  - binary/source API breaks that hit the project's compiled classes (target/classes), and",
                "    breaks for other dependencies that were compiled against the old version",
                "  - class-file (JDK) level changes against the project's maven.compiler.release",
                "  - license changes",
                "Verdict: SAFE, REVIEW or BREAKING. Exit code 0 only when the upgrade is SAFE.",
                "",
                "Options:",
                "  <g:a:v>                Upgrade to this version (g:a = newest release); repeat for several",
                "  --all-latest           Upgrade every direct dependency to its newest release",
                "  --minor                ... to the newest release with the same major version",
                "  --patch                ... to the newest release with the same major.minor version",
                "  --pre                  Allow pre-releases (alpha, beta, RC, milestones)",
                "  --module <name>        Only simulate these modules (artifactId or path, comma separated)",
                "  --release <N>          Java release the project runs on (default: maven.compiler.release)",
                "  --no-api               Skip the bytecode API check",
                "  --no-test              Leave test-scoped dependencies out",
                "",
                "Examples:",
                "  sm-maven simulate org.apache.logging.log4j:log4j-core:2.24.3",
                "  sm-maven simulate com.acme:acme-core:2.0.0 --json",
                "  sm-maven simulate --minor -f backend/pom.xml");
    }

    /** One requested upgrade. */
    static final class Upgrade {
        final String ga;
        final String to;
        final Set<String> from = new LinkedHashSet<>();
        final List<String> how = new ArrayList<>();

        Upgrade(String ga, String to) {
            this.ga = ga;
            this.to = to;
        }
    }

    /** A change in one module's resolved tree. */
    static final class TreeChange {
        final String module, ga, kind, from, to, scope, path;
        final boolean direct;

        TreeChange(String module, String ga, String kind, String from, String to, String scope, boolean direct, String path) {
            this.module = module;
            this.ga = ga;
            this.kind = kind;
            this.from = from;
            this.to = to;
            this.scope = scope;
            this.direct = direct;
            this.path = path;
        }

        Object toJson() {
            return Json.obj("module", module, "artifact", ga, "change", kind, "from", from, "to", to, "scope", scope, "direct", direct, "path", path);
        }
    }

    @Override
    public int run(Ctx ctx, Args args) throws Exception {
        Ui ui = ctx.ui;
        boolean allLatest = args.flag("all-latest"), minor = args.flag("minor"), patch = args.flag("patch");
        boolean pre = args.flag("pre");
        boolean api = !args.flag("no-api");
        boolean includeTest = !args.flag("no-test");
        List<String> onlyModules = args.getAll("module");
        int policies = (allLatest ? 1 : 0) + (minor ? 1 : 0) + (patch ? 1 : 0);
        if (policies > 1) throw new UsageException("use only one of --all-latest, --minor, --patch");
        String policy = allLatest ? "latest" : minor ? "minor" : patch ? "patch" : null;
        if (args.positionals().isEmpty() && policy == null) {
            throw new UsageException("give the upgrade as coordinates (e.g. org.apache.logging.log4j:log4j-core:2.24.3) or a policy: --all-latest, --minor or --patch");
        }

        Project project = ctx.project();
        Resolver.Options baseOpt = new Resolver.Options();
        baseOpt.includeTest = includeTest;
        project.resolveAll(ctx.resolver, baseOpt, ui);
        int release = UpgradeKit.release(ctx, args, project, 0);

        List<Project.Module> modules = new ArrayList<>();
        for (Project.Module m : project.codeModules()) {
            if (m.graph() == null) continue;
            if (!onlyModules.isEmpty() && !matchesModule(m, onlyModules)) continue;
            modules.add(m);
        }
        if (modules.isEmpty()) throw new UsageException("no module matches --module " + String.join(",", onlyModules));

        // ---------------------------------------------------------------- what to upgrade
        Map<String, Upgrade> upgrades = new LinkedHashMap<>();
        for (String spec : args.positionals()) {
            if (!Gav.looksLikeGav(spec)) throw new UsageException("expected group:artifact[:version], got '" + spec + "'");
            Gav g;
            try {
                g = Gav.parse(spec);
            } catch (IllegalArgumentException e) {
                throw new UsageException(e.getMessage());
            }
            if (g.version == null || g.version.equalsIgnoreCase("latest") || g.version.equalsIgnoreCase("release")) {
                List<String> vs = ctx.versions(g.groupId, g.artifactId, !pre);
                if (vs.isEmpty()) throw new UsageException(g.ga() + " was not found on " + ctx.repos.remotes().get(0).url);
                g = g.withVersion(vs.get(vs.size() - 1));
            } else {
                List<String> vs = ctx.versions(g.groupId, g.artifactId, false);
                if (vs.isEmpty()) throw new UsageException(g.ga() + " was not found on " + ctx.repos.remotes().get(0).url);
                if (!vs.contains(g.version)) throw new UsageException(g + " does not exist (newest: " + vs.get(vs.size() - 1) + ")");
            }
            upgrades.put(g.ga(), new Upgrade(g.ga(), g.version));
        }
        if (policy != null) {
            for (Project.Module m : modules) {
                for (Dependency d : m.model.pom.dependencies) {
                    if (d.version == null || d.version.startsWith("[") || d.version.startsWith("(") || d.version.contains("${")) continue;
                    if (ctx.models.inReactor(d.gav()) || "system".equals(d.scopeOrDefault())) continue;
                    if (upgrades.containsKey(d.ga()) && args.positionals().stream().anyMatch(s -> s.startsWith(d.ga()))) continue;
                    if (!includeTest && "test".equals(d.scopeOrDefault())) continue;
                    String target = newestByPolicy(ctx.versions(d.groupId, d.artifactId, !pre), d.version, policy);
                    if (target == null) continue;
                    Upgrade u = upgrades.get(d.ga());
                    if (u == null || MavenVersion.compare(target, u.to) > 0) upgrades.put(d.ga(), new Upgrade(d.ga(), target));
                }
            }
        }

        // ---------------------------------------------------------------- re-resolve each module
        List<TreeChange> changes = new ArrayList<>();
        List<Object> newConflicts = new ArrayList<>();
        List<String> newProblems = new ArrayList<>();
        Map<String, DepNode> beforeNodes = new LinkedHashMap<>(), afterNodes = new LinkedHashMap<>();
        Map<String, Graph> afterGraphs = new LinkedHashMap<>();
        Set<String> reactor = ctx.models.reactorGavs();
        for (Project.Module m : modules) {
            Graph before = m.graph();
            Resolver.Options o = new Resolver.Options();
            o.includeTest = includeTest;
            for (Upgrade u : upgrades.values()) {
                String[] ga = u.ga.split(":");
                boolean direct = false;
                for (Dependency d : m.model.pom.dependencies) if (d.ga().equals(u.ga)) direct = true;
                DepNode cur = before.selected(ga[0], ga[1]);
                if (direct) {
                    o.directOverrides.put(u.ga, u.to);
                    u.how.add("set <version>" + u.to + "</version> on the dependency in " + rel(m));
                } else if (cur != null) {
                    o.pins.put(u.ga, u.to);
                    u.how.add("manage " + u.ga + ":" + u.to + " in <dependencyManagement> of " + rel(m) + " (transitive via " + cur.path().get(0).ga() + ")");
                } else continue;
                if (cur != null) u.from.add(cur.version);
            }
            if (o.directOverrides.isEmpty() && o.pins.isEmpty()) {
                for (DepNode n : before.resolved()) if (!reactor.contains(n.gav().toString())) {
                    beforeNodes.putIfAbsent(n.gav().toString(), n);
                    afterNodes.putIfAbsent(n.gav().toString(), n);
                }
                continue;
            }
            ui.progress("Resolving " + m.model.pom.artifactId + " with the upgrade...");
            Graph after = ctx.resolver.resolve(m.model, o);
            ui.progressDone();
            afterGraphs.put(m.model.pom.artifactId, after);
            String mod = m.model.pom.artifactId;
            Map<String, DepNode> b = byKey(before, reactor), a = byKey(after, reactor);
            for (DepNode n : b.values()) beforeNodes.putIfAbsent(n.gav().toString(), n);
            for (DepNode n : a.values()) afterNodes.putIfAbsent(n.gav().toString(), n);
            for (Map.Entry<String, DepNode> e : b.entrySet()) {
                DepNode x = e.getValue(), y = a.get(e.getKey());
                if (y == null) {
                    changes.add(new TreeChange(mod, x.ga(), "removed", x.version, null, x.scope, x.isDirect(), x.pathString()));
                    continue;
                }
                if (!x.version.equals(y.version)) {
                    String kind = MavenVersion.compare(y.version, x.version) > 0 ? "upgraded" : "downgraded";
                    changes.add(new TreeChange(mod, x.ga(), kind, x.version, y.version, y.scope, y.isDirect(), y.pathString()));
                } else if (!x.scope.equals(y.scope)) {
                    changes.add(new TreeChange(mod, x.ga(), "scope", x.scope, y.scope, y.scope, y.isDirect(), y.pathString()));
                }
            }
            for (Map.Entry<String, DepNode> e : a.entrySet()) {
                if (b.containsKey(e.getKey())) continue;
                DepNode y = e.getValue();
                changes.add(new TreeChange(mod, y.ga(), "added", null, y.version, y.scope, y.isDirect(), y.pathString()));
            }
            Set<String> oldDowngrades = new LinkedHashSet<>();
            for (Graph.Conflict c : before.conflicts) if (c.downgrade()) oldDowngrades.add(c.winner.ga() + ":" + c.winner.version);
            for (Graph.Conflict c : after.conflicts) {
                if (!c.downgrade() || oldDowngrades.contains(c.winner.ga() + ":" + c.winner.version)) continue;
                Map<String, Object> cj = Json.map(c.toJson());
                cj.put("module", mod);
                newConflicts.add(cj);
            }
            Set<String> oldProblems = new LinkedHashSet<>(before.allProblems());
            for (String p : after.allProblems()) if (!oldProblems.contains(p)) newProblems.add(mod + ": " + p);
        }
        for (Upgrade u : upgrades.values()) {
            if (u.how.isEmpty() && policy == null) {
                throw new UsageException(u.ga + " is not a dependency of " + project.rootModule().gav().ga()
                        + (onlyModules.isEmpty() ? "" : " (modules " + String.join(",", onlyModules) + ")"));
            }
        }
        upgrades.values().removeIf(u -> u.how.isEmpty());

        // ---------------------------------------------------------------- vulnerabilities
        Set<Gav> all = new LinkedHashSet<>();
        for (DepNode n : beforeNodes.values()) all.add(n.gav());
        for (DepNode n : afterNodes.values()) all.add(n.gav());
        Map<String, List<Osv.Vuln>> vulns = all.isEmpty() ? Map.of() : ctx.vulnerabilities(all);
        Map<String, Object[]> vb = vulnIndex(beforeNodes, vulns), va = vulnIndex(afterNodes, vulns);
        List<Object[]> fixed = new ArrayList<>(), introduced = new ArrayList<>();
        for (Map.Entry<String, Object[]> e : vb.entrySet()) if (!va.containsKey(e.getKey())) fixed.add(e.getValue());
        for (Map.Entry<String, Object[]> e : va.entrySet()) if (!vb.containsKey(e.getKey())) introduced.add(e.getValue());

        // ---------------------------------------------------------------- per artifact: API, JDK level, license
        Map<String, String[]> changed = new LinkedHashMap<>();   // ga -> {from, to}
        for (TreeChange c : changes) if (c.from != null && c.to != null && !c.kind.equals("scope")) changed.putIfAbsent(c.ga + ":" + c.from + ":" + c.to, new String[] {c.ga, c.from, c.to});
        List<Jar> classes = UpgradeKit.projectClasses(project);
        ApiDiff.Usage usage = ApiDiff.Usage.of(classes);
        List<Object> apiJson = new ArrayList<>();
        List<String[]> apiLines = new ArrayList<>();
        int apiHits = 0, depHits = 0;
        List<Object> jdkJson = new ArrayList<>();
        List<Object> licJson = new ArrayList<>();
        List<String> reasonsBreaking = new ArrayList<>(), reasonsReview = new ArrayList<>();
        int targetMajor = release > 0 ? UpgradeKit.majorFor(release) : 0;
        for (String[] c : changed.values()) {
            String[] ga = c[0].split(":");
            Gav from = new Gav(ga[0], ga[1], c[1]), to = new Gav(ga[0], ga[1], c[2]);
            if (api && !classes.isEmpty()) {
                ui.progress("Comparing the API of " + c[0] + " " + c[1] + " and " + c[2] + "...");
                List<ApiDiff.Impact> imp = UpgradeKit.impacts(ctx, from, to, usage);
                ui.progressDone();
                if (imp != null) {
                    for (ApiDiff.Impact i : imp) {
                        Map<String, Object> j = Json.map(i.toJson());
                        j.put("artifact", c[0]);
                        j.put("from", c[1]);
                        j.put("to", c[2]);
                        j.put("affects", "project");
                        apiJson.add(j);
                        apiLines.add(new String[] {c[0] + " " + c[1] + " " + ui.arrow() + " " + c[2], i.change.level, i.change.kind, i.change.where(), i.change.detail, String.join(", ", i.usedBy)});
                        apiHits++;
                    }
                }
            }
            if (api) {
                // Other dependencies compiled against the version they requested.
                Set<String> done = new LinkedHashSet<>();
                for (Graph g : afterGraphs.values()) {
                    for (DepNode n : g.find(x -> x.ga().equals(c[0]) && x.parent != null && x.parent.selected)) {
                        String requested = n.premanagedVersion != null ? n.premanagedVersion : n.version;
                        if (n.range != null || requested == null || requested.equals(c[2]) || requested.startsWith("[") || requested.startsWith("(")) continue;
                        DepNode p = n.parent;
                        if (!done.add(p.gav() + ">" + requested)) continue;
                        Jar pj = ctx.jar(p.gav());
                        if (pj == null) continue;
                        List<ApiDiff.Impact> imp = UpgradeKit.impacts(ctx, new Gav(ga[0], ga[1], requested), to, ApiDiff.Usage.of(List.of(pj)));
                        if (imp == null) continue;
                        for (ApiDiff.Impact i : imp) {
                            Map<String, Object> j = Json.map(i.toJson());
                            j.put("artifact", c[0]);
                            j.put("from", requested);
                            j.put("to", c[2]);
                            j.put("affects", p.gav().toString());
                            apiJson.add(j);
                            apiLines.add(new String[] {c[0] + " " + requested + " " + ui.arrow() + " " + c[2], i.change.level, i.change.kind, i.change.where(), i.change.detail, p.gav() + " (" + String.join(", ", i.usedBy) + ")"});
                            depHits++;
                        }
                    }
                }
            }
            int mf = UpgradeKit.jarMajor(ctx, from), mt = UpgradeKit.jarMajor(ctx, to);
            if (mf != mt && mt > 0) {
                boolean ok = targetMajor == 0 || mt <= targetMajor;
                jdkJson.add(Json.obj("artifact", c[0], "from", c[1], "to", c[2], "fromMajor", mf, "toMajor", mt,
                        "requiresJava", Integer.parseInt(UpgradeKit.javaOf(mt).replace("1.", "")), "compatible", ok));
                if (!ok) reasonsBreaking.add(c[0] + " " + c[2] + " needs Java " + UpgradeKit.javaOf(mt) + " (class file " + mt + "), the project targets Java " + release);
            }
            List<String> lf = UpgradeKit.licenses(ctx, from), lt = UpgradeKit.licenses(ctx, to);
            if (!lf.equals(lt)) {
                Licenses.Category cf = Licenses.bestOf(lf), ct = Licenses.bestOf(lt);
                boolean worse = Licenses.rank(ct) > Licenses.rank(cf);
                licJson.add(Json.obj("artifact", c[0], "from", c[1], "to", c[2], "fromLicenses", lf, "toLicenses", lt,
                        "fromCategory", cf.label, "toCategory", ct.label, "moreRestrictive", worse));
                reasonsReview.add("license of " + c[0] + " changes " + UpgradeKit.licenseText(lf) + " " + ui.arrow() + " " + UpgradeKit.licenseText(lt) + " (" + ct.label + ")");
            }
        }
        // Newly added artifacts: JDK level and license category.
        Set<String> addedSeen = new LinkedHashSet<>();
        for (TreeChange c : changes) {
            if (!c.kind.equals("added") || !addedSeen.add(c.ga + ":" + c.to)) continue;
            String[] ga = c.ga.split(":");
            Gav g = new Gav(ga[0], ga[1], c.to);
            int mt = UpgradeKit.jarMajor(ctx, g);
            if (targetMajor > 0 && mt > targetMajor) {
                jdkJson.add(Json.obj("artifact", c.ga, "to", c.to, "toMajor", mt, "requiresJava", mt - 44, "compatible", false));
                reasonsBreaking.add("new dependency " + g + " needs Java " + UpgradeKit.javaOf(mt) + ", the project targets Java " + release);
            }
            List<String> lt = UpgradeKit.licenses(ctx, g);
            Licenses.Category ct = Licenses.bestOf(lt);
            if (Licenses.rank(ct) >= Licenses.rank(Licenses.Category.STRONG_COPYLEFT) && ct != Licenses.Category.UNKNOWN) {
                licJson.add(Json.obj("artifact", c.ga, "to", c.to, "toLicenses", lt, "toCategory", ct.label, "added", true, "moreRestrictive", true));
                reasonsReview.add("new dependency " + g + " is " + UpgradeKit.licenseText(lt) + " (" + ct.label + ")");
            }
        }
        // Removed artifacts the project's own code still uses.
        for (TreeChange c : changes) {
            if (!c.kind.equals("removed") || classes.isEmpty()) continue;
            String[] ga = c.ga.split(":");
            Jar j = ctx.jar(new Gav(ga[0], ga[1], c.from));
            if (j == null) continue;
            Set<String> users = new LinkedHashSet<>();
            for (in.slashmark.maven.bytecode.ClassFile cf : j.classes()) {
                if (usage.types.containsKey(cf.name)) users.addAll(usage.types.get(cf.name));
                if (usage.extended.containsKey(cf.name)) users.addAll(usage.extended.get(cf.name));
            }
            if (!users.isEmpty()) reasonsBreaking.add(c.module + ": " + c.ga + " leaves the classpath but " + String.join(", ", users) + " use it (declare it directly)");
        }

        // ---------------------------------------------------------------- verdict
        if (apiHits > 0) reasonsBreaking.add(0, Ui.plural(apiHits, "API break") + " hit the project's code");
        if (depHits > 0) reasonsBreaking.add(Ui.plural(depHits, "API break") + " hit other dependencies compiled against the old version");
        for (String p : newProblems) reasonsBreaking.add("resolution problem: " + p);
        if (!introduced.isEmpty()) reasonsReview.add(0, Ui.plural(introduced.size(), "vulnerability", "vulnerabilities") + " introduced");
        for (Upgrade u : upgrades.values()) {
            for (String f : u.from) {
                if (MavenVersion.compare(u.to, f) < 0) reasonsReview.add(u.ga + " goes down from " + f + " to " + u.to);
                else if (MavenVersion.of(f).major() != MavenVersion.of(u.to).major() && apiHits == 0)
                    reasonsReview.add(u.ga + " " + f + " " + ui.arrow() + " " + u.to + " is a major version jump (no API break detected in your code; check behaviour changes)");
            }
        }
        for (TreeChange c : changes) {
            if (c.kind.equals("downgraded") && !upgrades.containsKey(c.ga)) reasonsReview.add(c.module + ": " + c.ga + " is downgraded " + c.from + " " + ui.arrow() + " " + c.to);
        }
        if (!newConflicts.isEmpty()) reasonsReview.add(Ui.plural(newConflicts.size(), "new silent downgrade") + " in mediation");
        String verdict = !reasonsBreaking.isEmpty() ? "BREAKING" : !reasonsReview.isEmpty() ? "REVIEW" : "SAFE";
        if (upgrades.isEmpty()) verdict = "SAFE";

        // ---------------------------------------------------------------- output
        if (ui.json) {
            List<Object> ups = new ArrayList<>();
            for (Upgrade u : upgrades.values()) {
                String f = u.from.isEmpty() ? null : u.from.iterator().next();
                ups.add(Json.obj("artifact", u.ga, "from", f, "to", u.to, "jump", f == null ? null : MavenVersion.of(f).jumpTo(MavenVersion.of(u.to)),
                        "apply", u.how));
            }
            List<Object> ch = new ArrayList<>();
            for (TreeChange c : changes) ch.add(c.toJson());
            Map<String, Object> doc = new LinkedHashMap<>();
            doc.put("project", project.rootModule().gav().toString());
            doc.put("policy", policy);
            doc.put("release", release > 0 ? release : null);
            doc.put("upgrades", ups);
            doc.put("treeChanges", ch);
            doc.put("newConflicts", newConflicts);
            doc.put("problems", newProblems);
            doc.put("vulnerabilities", Json.obj("fixed", vulnJson(fixed), "introduced", vulnJson(introduced),
                    "before", vb.size(), "after", va.size()));
            doc.put("apiBreaks", apiJson);
            doc.put("jdk", jdkJson);
            doc.put("licenses", licJson);
            doc.put("verdict", verdict);
            doc.put("reasons", concat(reasonsBreaking, reasonsReview));
            ui.emitJson(doc);
            return verdict.equals("SAFE") ? Exit.OK : Exit.ISSUES;
        }

        ui.title(title() + " " + ui.dot() + " " + project.rootModule().gav() + (release > 0 ? ui.dim("  (Java " + release + ")") : ""));
        if (upgrades.isEmpty()) {
            ui.good("Nothing to upgrade: every direct dependency is already at the newest " + (policy == null ? "" : policy + " ") + "release.");
            return Exit.OK;
        }
        ui.section("Upgrades");
        Ui.Table t = new Ui.Table("Artifact", "From", "To", "Jump", "Applied as");
        for (Upgrade u : upgrades.values()) {
            String f = String.join(", ", u.from);
            String jump = u.from.isEmpty() ? "" : MavenVersion.of(u.from.iterator().next()).jumpTo(MavenVersion.of(u.to));
            t.row(u.ga, f, ui.bold(u.to), jump.equals("major") ? ui.yellow(jump) : jump, u.how.get(0) + (u.how.size() > 1 ? " (+" + (u.how.size() - 1) + ")" : ""));
        }
        ui.table(t);

        ui.section("Dependency tree changes");
        if (changes.isEmpty()) ui.line(ui.dim("no changes"));
        String lastMod = null;
        for (TreeChange c : changes) {
            if (!c.module.equals(lastMod)) {
                lastMod = c.module;
                ui.line(ui.bold(c.module));
            }
            String where = c.direct ? "direct" : "transitive";
            switch (c.kind) {
                case "upgraded": ui.line("  " + ui.green(ui.unicode() ? "↑" : "^") + " " + c.ga + " " + c.from + " " + ui.arrow() + " " + ui.bold(c.to) + ui.dim("  " + where + ", " + c.scope)); break;
                case "downgraded": ui.line("  " + ui.yellow(ui.unicode() ? "↓" : "v") + " " + c.ga + " " + c.from + " " + ui.arrow() + " " + ui.bold(c.to) + ui.dim("  " + where + ", " + c.scope)); break;
                case "added": ui.line("  " + ui.cyan("+") + " " + c.ga + ":" + c.to + ui.dim("  " + c.scope + ", via " + c.path)); break;
                case "removed": ui.line("  " + ui.red("-") + " " + c.ga + ":" + c.from + ui.dim("  no longer needed")); break;
                default: ui.line("  " + ui.yellow("~") + " " + c.ga + " scope " + c.from + " " + ui.arrow() + " " + c.to);
            }
        }
        for (Object o : newConflicts) ui.warn("new silent downgrade: " + Json.str(o, "artifact") + " " + Json.str(o, "selected") + " wins over " + Json.str(o, "highestRequested") + " (" + Json.str(o, "module") + ")");
        for (String p : newProblems) ui.fail(p);

        ui.section("Vulnerabilities");
        if (fixed.isEmpty() && introduced.isEmpty()) ui.line(ui.dim("no change (" + Ui.plural(va.size(), "known vulnerability", "known vulnerabilities") + " before and after)"));
        for (Object[] f : fixed) {
            Osv.Vuln v = (Osv.Vuln) f[0];
            ui.good("fixed " + v.displayId() + " " + ui.severity(v.severity) + " in " + f[1] + ui.dim("  " + v.summary));
        }
        for (Object[] f : introduced) {
            Osv.Vuln v = (Osv.Vuln) f[0];
            ui.fail("introduces " + v.displayId() + " " + ui.severity(v.severity) + " in " + f[1] + ui.dim("  " + v.summary));
        }
        if (!fixed.isEmpty() || !introduced.isEmpty()) ui.note("  " + vb.size() + " " + ui.arrow() + " " + va.size() + " known vulnerabilities");

        ui.section("API compatibility");
        if (!api) ui.line(ui.dim("skipped (--no-api)"));
        else if (classes.isEmpty()) ui.line(ui.dim("no compiled classes (target/classes) to check; build the project first"));
        else if (apiLines.isEmpty()) ui.good("no binary or source break hits your code (" + Ui.plural(usage.classCount, "class", "classes") + " checked)");
        else {
            String last = null;
            for (String[] l : apiLines) {
                if (!l[0].equals(last)) {
                    last = l[0];
                    ui.line(ui.bold(l[0]));
                }
                ui.line("  " + (l[1].equals("binary") ? ui.red("binary") : ui.yellow("source")) + " " + l[2] + ": " + l[3] + ui.dim(" - " + l[4]));
                ui.line("      " + ui.dim("used by ") + l[5]);
            }
        }

        if (!jdkJson.isEmpty()) {
            ui.section("Java class-file level");
            for (Object o : jdkJson) {
                boolean ok = Json.bool(o, true, "compatible");
                String line = Json.str(o, "artifact") + " " + (Json.str(o, "from") == null ? "" : "Java " + UpgradeKit.javaOf((int) Json.num(o, 0, "fromMajor")) + " " + ui.arrow() + " ")
                        + "Java " + UpgradeKit.javaOf((int) Json.num(o, 0, "toMajor")) + " (class file " + Json.num(o, 0, "toMajor") + ")";
                if (ok) ui.line(line);
                else ui.fail(line + ": the project targets Java " + release);
            }
        }
        if (!licJson.isEmpty()) {
            ui.section("Licenses");
            for (Object o : licJson) {
                String line = Json.str(o, "artifact") + " " + (Json.get(o, "fromLicenses") == null ? "(new) " : String.join(" OR ", strs(Json.list(o, "fromLicenses"))) + " " + ui.arrow() + " ")
                        + String.join(" OR ", strs(Json.list(o, "toLicenses"))) + ui.dim("  " + Json.str(o, "toCategory"));
                if (Json.bool(o, false, "moreRestrictive")) ui.warn(line);
                else ui.line(line);
            }
        }

        ui.section("How to apply");
        for (Upgrade u : upgrades.values()) for (String h : u.how) ui.line(h);

        ui.println();
        String head = "Verdict: " + (verdict.equals("SAFE") ? ui.green(verdict) : verdict.equals("REVIEW") ? ui.yellow(verdict) : ui.red(verdict));
        ui.println(ui.bold(head));
        for (String r : reasonsBreaking) ui.line(ui.red(ui.unicode() ? "✖" : "X") + " " + r);
        for (String r : reasonsReview) ui.line(ui.warnMark() + " " + r);
        if (verdict.equals("SAFE")) ui.line(ui.dim("no API breaks, no new vulnerabilities, same licenses and Java level"));
        return verdict.equals("SAFE") ? Exit.OK : Exit.ISSUES;
    }

    static boolean matchesModule(Project.Module m, List<String> names) {
        for (String n : names) if (m.relPath.equals(n) || m.model.pom.artifactId.equals(n) || m.gav().ga().equals(n)) return true;
        return false;
    }

    private static String rel(Project.Module m) { return (m.relPath.equals(".") ? "" : m.relPath + "/") + "pom.xml"; }

    /** Newest version allowed by the policy that is newer than current; null when there is none. */
    static String newestByPolicy(List<String> versions, String current, String policy) {
        MavenVersion cur = MavenVersion.of(current);
        String best = null;
        for (String v : versions) {
            MavenVersion mv = MavenVersion.of(v);
            if (mv.compareTo(cur) <= 0) continue;
            if (policy.equals("minor") && mv.major() != cur.major()) continue;
            if (policy.equals("patch") && (mv.major() != cur.major() || mv.minor() != cur.minor())) continue;
            if (best == null || mv.compareTo(MavenVersion.of(best)) > 0) best = v;
        }
        return best;
    }

    /** Selected nodes keyed by g:a[:classifier], reactor modules excluded. */
    private static Map<String, DepNode> byKey(Graph g, Set<String> reactor) {
        Map<String, DepNode> m = new LinkedHashMap<>();
        for (DepNode n : g.resolved()) {
            if (reactor.contains(n.gav().toString())) continue;
            m.putIfAbsent(n.ga() + (n.classifier == null ? "" : ":" + n.classifier), n);
        }
        return m;
    }

    /** advisory@ga -> {vuln, gav, scope}. */
    private static Map<String, Object[]> vulnIndex(Map<String, DepNode> nodes, Map<String, List<Osv.Vuln>> vulns) {
        Map<String, Object[]> m = new LinkedHashMap<>();
        for (DepNode n : nodes.values()) {
            List<Osv.Vuln> vs = vulns.get(n.gav().toString());
            if (vs == null) continue;
            for (Osv.Vuln v : vs) m.putIfAbsent(v.id + "@" + n.ga(), new Object[] {v, n.gav().toString(), n.scope});
        }
        return m;
    }

    private static List<Object> vulnJson(List<Object[]> l) {
        List<Object> out = new ArrayList<>();
        for (Object[] f : l) {
            Osv.Vuln v = (Osv.Vuln) f[0];
            out.add(Json.obj("id", v.id, "displayId", v.displayId(), "severity", v.severity, "cvss", v.score >= 0 ? v.score : null,
                    "artifact", f[1], "scope", f[2], "summary", v.summary));
        }
        return out;
    }

    private static List<String> concat(List<String> a, List<String> b) {
        List<String> out = new ArrayList<>(a);
        out.addAll(b);
        return out;
    }

    private static List<String> strs(List<Object> l) {
        List<String> out = new ArrayList<>();
        for (Object o : l) out.add(String.valueOf(o));
        return out;
    }
}
