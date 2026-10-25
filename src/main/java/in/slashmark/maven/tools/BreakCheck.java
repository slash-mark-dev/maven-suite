package in.slashmark.maven.tools;

import in.slashmark.maven.bytecode.ApiDiff;
import in.slashmark.maven.bytecode.Jar;
import in.slashmark.maven.cli.Args;
import in.slashmark.maven.cli.Command;
import in.slashmark.maven.cli.Ctx;
import in.slashmark.maven.cli.Exit;
import in.slashmark.maven.cli.Project;
import in.slashmark.maven.cli.Ui;
import in.slashmark.maven.cli.UsageException;
import in.slashmark.maven.model.Gav;
import in.slashmark.maven.model.MavenVersion;
import in.slashmark.maven.resolve.DepNode;
import in.slashmark.maven.resolve.Graph;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Breaking Change Forecaster: API breaks of an upgrade that actually hit your code. */
public final class BreakCheck extends Command {
    @Override public String name() { return "breakcheck"; }
    @Override public String title() { return "Breaking Change Forecaster"; }
    @Override public String group() { return "Release intelligence"; }
    @Override public String summary() { return "API breaks of an upgrade that actually hit your code"; }

    @Override
    public String help() {
        return String.join("\n",
                "Usage: sm-maven breakcheck <group:artifact[:version]> [options]",
                "",
                summary() + ".",
                "It compares the public binary API of the version your project resolves today with",
                "the target version (default: newest release),",
                "following the JLS binary-compatibility rules (removed/changed methods and fields, classes",
                "made final or abstract, new abstract methods, removed supertypes...), then intersects the",
                "changes with what your compiled classes (target/classes) actually call, extend or implement.",
                "Only breaks that hit your code are reported, each with the class that uses the API. It also",
                "flags a target compiled for a newer Java than your project. Exit code 1 when something breaks.",
                "Compile the project first (mvn compile) so target/classes exists.",
                "",
                "Options:",
                "  --from <version>       Compare from this version instead of the resolved one (needed without a project)",
                "  --java <release>       Java release the project runs on (default: from target/classes or the POM)",
                "  --deps                 Also check the other dependencies that call the library (their JARs)",
                "  --all                  Also list the breaking changes your code does not use",
                "",
                "Examples:",
                "  sm-maven breakcheck com.acme:acme-core:2.0.0",
                "  sm-maven breakcheck com.google.guava:guava --deps",
                "  sm-maven breakcheck com.acme:acme-core --from 1.0.0 --json");
    }

    @Override
    public Set<String> flags() { return Set.of("deps", "all"); }

    /** Code that may call the library. */
    private static final class Consumer {
        final String label;
        final String kind;   // "module" or "dependency"
        final Jar jar;

        Consumer(String label, String kind, Jar jar) {
            this.label = label;
            this.kind = kind;
            this.jar = jar;
        }
    }

    /** One comparison from a resolved version to the target. */
    private static final class Comparison {
        String from;
        final List<String> modules = new ArrayList<>();
        final List<Consumer> consumers = new ArrayList<>();
        final List<String> notCompiled = new ArrayList<>();
        int projectMajor;
        String projectMajorSource;
        List<ApiDiff.Change> changes;
        int oldMajor;
        /** change key -> users (labelled). */
        final Map<String, Set<String>> hits = new LinkedHashMap<>();
        final Map<String, ApiDiff.Change> byKey = new LinkedHashMap<>();
        Set<String> classVersionUsers = new LinkedHashSet<>();
        int consumerClasses;
    }

    @Override
    public int run(Ctx ctx, Args args) throws Exception {
        String p = args.pos(0);
        if (p == null) throw new UsageException("which dependency? e.g. sm-maven breakcheck com.acme:acme-core:2.0.0");
        if (args.positionals().size() > 1) throw new UsageException("breakcheck takes one coordinate, got " + args.positionals());
        Gav want = ReleaseSupport.parseGav(p);
        String fromOpt = args.get("from");
        if ("true".equals(fromOpt)) throw new UsageException("--from expects a version");
        int javaOpt = args.getInt("java", 0);
        if (args.has("java") && (javaOpt < 1 || javaOpt > 99)) throw new UsageException("--java expects a release number like 11 or 17");
        boolean withDeps = args.flag("deps");
        boolean showAll = args.flag("all");

        Gav to = ctx.resolveLatest(want);
        if (ctx.repos.pom(to) == null) throw new UsageException(to + " was not found on " + ctx.repos.remotes().get(0).url);
        Jar newJar = ctx.jar(to);
        if (newJar == null) throw new UsageException(to + " has no JAR to compare (packaging pom?)");
        String ga = to.ga();

        // Which modules use the library, at which version.
        Map<String, Comparison> byFrom = new LinkedHashMap<>();
        if (ctx.hasProject()) {
            Ctx.Target t = ctx.target(args, 1);
            for (Project.Module m : t.project.codeModules()) {
                Graph g = m.graph();
                if (g == null) continue;
                DepNode n = g.selected(to.groupId, to.artifactId);
                if (n == null && fromOpt == null) continue;
                String from = fromOpt != null ? fromOpt : n.version;
                Comparison c = byFrom.computeIfAbsent(from, k -> new Comparison());
                c.from = from;
                addModule(ctx, c, m, g, ga, withDeps, n != null);
            }
            if (byFrom.isEmpty()) {
                throw new UsageException("the project does not depend on " + ga + " (use --from <version> to compare anyway)");
            }
        } else {
            if (fromOpt == null) throw new UsageException("no pom.xml here: pass -f <project> or --from <version> to compare " + ga);
            Comparison c = new Comparison();
            c.from = fromOpt;
            byFrom.put(fromOpt, c);
        }

        Ui ui = ctx.ui;
        ApiDiff.Api newApi = ApiDiff.Api.of(newJar);
        int newMajor = newJar.maxClassMajor();
        int totalBreaks = 0;
        boolean anyCompiled = false;
        for (Comparison c : byFrom.values()) {
            Gav fromGav = to.withVersion(c.from);
            Jar oldJar = ctx.jar(fromGav);
            if (oldJar == null) throw new UsageException(fromGav + " was not found on " + ctx.repos.remotes().get(0).url);
            ApiDiff.Api oldApi = ApiDiff.Api.of(oldJar);
            c.oldMajor = oldJar.maxClassMajor();
            c.changes = ApiDiff.diff(oldApi, newApi);
            for (Consumer con : c.consumers) {
                ApiDiff.Usage u = ApiDiff.Usage.of(List.of(con.jar));
                if (con.kind.equals("module")) {
                    anyCompiled = true;
                    c.consumerClasses += u.classCount;
                }
                for (ApiDiff.Impact im : ApiDiff.impacts(c.changes, oldApi, u)) {
                    String k = key(im.change);
                    c.byKey.put(k, im.change);
                    Set<String> users = c.hits.computeIfAbsent(k, x -> new LinkedHashSet<>());
                    for (String cls : im.usedBy) users.add(con.kind.equals("module") ? cls : con.label + " (" + cls + ")");
                }
                // Code that touches any type of the library must run on the library's class-file version.
                for (String type : newApi.types.keySet()) {
                    if (!u.usesType(type)) continue;
                    Set<String> s = new LinkedHashSet<>();
                    if (u.types.get(type) != null) s.addAll(u.types.get(type));
                    if (u.extended.get(type) != null) s.addAll(u.extended.get(type));
                    for (String cls : s) c.classVersionUsers.add(con.kind.equals("module") ? cls : con.label + " (" + cls + ")");
                }
            }
            if (javaOpt > 0) {
                c.projectMajor = javaOpt + 44;
                c.projectMajorSource = "--java";
            }
            if (c.projectMajor > 0 && newMajor > c.projectMajor && !c.classVersionUsers.isEmpty()) totalBreaks++;
            else c.classVersionUsers.clear();
            totalBreaks += c.hits.size();
        }
        // Nothing compiled to intersect with: every breaking change is a potential break.
        boolean potentialOnly = !anyCompiled;
        int potential = 0;
        if (potentialOnly) for (Comparison c : byFrom.values()) for (ApiDiff.Change ch : c.changes) if (!"info".equals(ch.level)) potential++;
        int exit = totalBreaks > 0 || (potentialOnly && potential > 0) ? Exit.ISSUES : Exit.OK;

        if (ui.json) {
            List<Object> comps = new ArrayList<>();
            for (Comparison c : byFrom.values()) comps.add(toJson(c, to, newMajor, showAll || potentialOnly));
            ui.emitJson(ReleaseSupport.o("tool", name(), "artifact", ga, "to", to.version,
                    "toJava", newMajor > 0 ? newMajor - 44 : null, "toClassMajor", newMajor > 0 ? newMajor : null,
                    "compiled", anyCompiled, "breaks", totalBreaks, "potential", potentialOnly ? potential : null,
                    "safe", exit == Exit.OK, "comparisons", comps));
            return exit;
        }
        for (Comparison c : byFrom.values()) print(ui, c, to, newMajor, showAll, potentialOnly);
        ui.println();
        if (potentialOnly) {
            ui.warn("No compiled classes found (run mvn compile): " + Ui.plural(potential, "breaking change") + " in the library may affect you");
        } else if (totalBreaks > 0) {
            ui.fail(Ui.plural(totalBreaks, "breaking change hits", "breaking changes hit") + " your code: upgrading " + ga + " to " + to.version + " needs code changes");
        } else {
            ui.good("Safe: none of the API changes in " + ga + " " + to.version + " touch the code that uses it");
        }
        return exit;
    }

    private static void addModule(Ctx ctx, Comparison c, Project.Module m, Graph g, String ga, boolean withDeps, boolean uses) throws Exception {
        c.modules.add(m.model.pom.artifactId);
        java.nio.file.Path dir = m.classesDir();
        if (dir != null) {
            Jar j = Jar.read(dir);
            c.consumers.add(new Consumer(m.model.pom.artifactId, "module", j));
            if (c.projectMajor == 0 || j.maxClassMajor() < c.projectMajor) {
                int mj = j.maxClassMajor();
                if (mj > 0) {
                    c.projectMajor = mj;
                    c.projectMajorSource = m.model.pom.artifactId + "/target/classes";
                }
            }
        } else {
            c.notCompiled.add(m.model.pom.artifactId);
        }
        if (c.projectMajor == 0) {
            Map<String, String> props = m.model.pom.properties;
            for (String k : new String[] {"maven.compiler.release", "maven.compiler.target", "maven.compiler.source", "java.version"}) {
                String v = props.get(k);
                if (v == null) continue;
                v = v.trim();
                if (v.startsWith("1.")) v = v.substring(2);
                try {
                    c.projectMajor = Integer.parseInt(v) + 44;
                    c.projectMajorSource = k;
                    break;
                } catch (NumberFormatException ignored) {
                }
            }
        }
        if (!withDeps || !uses) return;
        // Other dependencies of this module that depend on the library call it too.
        for (DepNode n : g.resolved()) {
            if (n.ga().equals(ga) || ctx.models.reactorGavs().contains(n.gav().toString())) continue;
            boolean callsIt = false;
            for (DepNode k : n.kids()) if (k.ga().equals(ga)) callsIt = true;
            if (!callsIt) continue;
            Jar j = ctx.jar(n.gav());
            if (j != null) c.consumers.add(new Consumer(n.gav().toString(), "dependency", j));
        }
    }

    private static String key(ApiDiff.Change ch) { return ch.kind + "|" + ch.type + "|" + ch.member; }

    private static Map<String, Object> changeJson(ApiDiff.Change ch, Set<String> users) {
        return ReleaseSupport.o("level", ch.level, "kind", ch.kind, "type", ch.typeName(), "member", ch.member, "detail", ch.detail,
                "usedBy", users == null ? List.of() : new ArrayList<>(users));
    }

    private static Map<String, Object> toJson(Comparison c, Gav to, int newMajor, boolean listUnused) {
        List<Object> impacts = new ArrayList<>();
        for (Map.Entry<String, Set<String>> e : c.hits.entrySet()) impacts.add(changeJson(c.byKey.get(e.getKey()), e.getValue()));
        if (!c.classVersionUsers.isEmpty()) {
            impacts.add(ReleaseSupport.o("level", "binary", "kind", "class-version", "type", null, "member", null,
                    "detail", "compiled for Java " + (newMajor - 44) + " (class file " + newMajor + "); the project targets Java " + (c.projectMajor - 44)
                            + " (" + c.projectMajor + ")",
                    "usedBy", new ArrayList<>(c.classVersionUsers)));
        }
        int breaking = 0, compatible = 0;
        List<Object> unused = new ArrayList<>();
        for (ApiDiff.Change ch : c.changes) {
            if ("info".equals(ch.level)) compatible++;
            else {
                breaking++;
                if (!c.hits.containsKey(key(ch))) unused.add(changeJson(ch, null));
            }
        }
        List<Object> consumers = new ArrayList<>();
        for (Consumer con : c.consumers) consumers.add(ReleaseSupport.o("name", con.label, "kind", con.kind));
        return ReleaseSupport.o("from", c.from, "to", to.version, "jump", MavenVersion.of(c.from).jumpTo(MavenVersion.of(to.version)),
                "modules", c.modules, "consumers", consumers, "notCompiled", c.notCompiled, "consumerClasses", c.consumerClasses,
                "fromJava", c.oldMajor > 0 ? c.oldMajor - 44 : null,
                "projectJava", c.projectMajor > 0 ? c.projectMajor - 44 : null, "projectJavaSource", c.projectMajorSource,
                "apiChanges", ReleaseSupport.o("breaking", breaking, "compatible", compatible),
                "impacts", impacts, "unusedBreaking", listUnused ? unused : null);
    }

    private static String kindLabel(String kind) { return kind.replace('-', ' ').toUpperCase(Locale.ROOT); }

    private static void print(Ui ui, Comparison c, Gav to, int newMajor, boolean showAll, boolean potentialOnly) {
        String jump = MavenVersion.of(c.from).jumpTo(MavenVersion.of(to.version));
        ui.title("Breaking Change Forecast  " + to.ga() + " " + c.from + " " + ui.arrow() + " " + to.version + "  " + ui.dim("(" + jump + ")"));
        int breaking = 0, compatible = 0;
        for (ApiDiff.Change ch : c.changes) if ("info".equals(ch.level)) compatible++; else breaking++;
        if (MavenVersion.compare(c.from, to.version) == 0) ui.note("  already on " + to.version + ": nothing to compare");
        ui.note("  API diff: " + Ui.plural(breaking, "breaking change") + ", " + Ui.plural(compatible, "compatible addition")
                + (c.modules.isEmpty() ? "" : "; used from " + String.join(", ", c.modules) + " (" + Ui.plural(c.consumerClasses, "class", "classes") + ")"));
        for (String m : c.notCompiled) ui.warn(m + " has no target/classes: compile it so its usage can be checked");
        int n = 0;
        for (Map.Entry<String, Set<String>> e : c.hits.entrySet()) {
            ApiDiff.Change ch = c.byKey.get(e.getKey());
            if (n++ == 0) ui.println();
            ui.println(ui.bad() + " " + ui.bold(kindLabel(ch.kind)) + "  " + ch.where());
            ui.line("  " + ch.detail + ui.dim(" [" + ch.level + "]"));
            for (String u : e.getValue()) ui.line("  " + ui.arrow() + " used by " + ui.cyan(u));
        }
        if (!c.classVersionUsers.isEmpty()) {
            if (n++ == 0) ui.println();
            ui.println(ui.bad() + " " + ui.bold("JAVA VERSION") + "  " + to + " is compiled for Java " + (newMajor - 44) + " (class file " + newMajor + ")");
            ui.line("  the project targets Java " + (c.projectMajor - 44) + " (class file " + c.projectMajor + ", from " + c.projectMajorSource
                    + "): UnsupportedClassVersionError at runtime");
            int k = 0;
            for (String u : c.classVersionUsers) {
                if (k++ == 5) { ui.line("  " + ui.dim("... and " + (c.classVersionUsers.size() - 5) + " more")); break; }
                ui.line("  " + ui.arrow() + " loaded by " + ui.cyan(u));
            }
        }
        List<ApiDiff.Change> unused = new ArrayList<>();
        for (ApiDiff.Change ch : c.changes) if (!"info".equals(ch.level) && !c.hits.containsKey(key(ch))) unused.add(ch);
        if (!unused.isEmpty() && (showAll || potentialOnly)) {
            ui.section(potentialOnly ? "Breaking changes in the library (usage unknown)" : "Breaking changes your code does not touch");
            for (ApiDiff.Change ch : unused) ui.line(ui.dot() + " " + ch.where() + ": " + ch.detail + ui.dim(" [" + ch.kind + "]"));
        } else if (!unused.isEmpty()) {
            ui.note("  " + Ui.plural(unused.size(), "other breaking change") + " in the library do not touch your code (--all to list)");
        }
    }
}
