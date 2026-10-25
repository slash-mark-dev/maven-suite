package in.slashmark.maven.tools;

import in.slashmark.maven.cli.Args;
import in.slashmark.maven.cli.Ctx;
import in.slashmark.maven.cli.Project;
import in.slashmark.maven.cli.UsageException;
import in.slashmark.maven.data.Osv;
import in.slashmark.maven.model.Gav;
import in.slashmark.maven.resolve.DepNode;
import in.slashmark.maven.resolve.Graph;
import in.slashmark.maven.util.HttpException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/** Helpers shared by the live dependency analysis tools (graph, blast, drift, resolve, classpath). */
final class DepSupport {
    private DepSupport() {}

    static final Set<String> SCOPES = Set.of("compile", "provided", "runtime", "test", "system", "import");

    /** One resolved module (or the published artifact) of a target. */
    static final class Unit {
        final String label;
        final String relPath;
        final Graph graph;
        final Project.Module module;

        Unit(String label, String relPath, Graph graph, Project.Module module) {
            this.label = label;
            this.relPath = relPath;
            this.graph = graph;
            this.module = module;
        }

        String ga() { return graph.root.gav().ga(); }

        String name() { return graph.root.pom.artifactId; }
    }

    /** The resolved units of a target, optionally narrowed to one module (--module). */
    static List<Unit> units(Ctx.Target t, String moduleFilter) {
        List<Unit> out = new ArrayList<>();
        if (t.project != null) {
            for (Project.Module m : t.project.codeModules()) {
                if (m.graph() == null) continue;
                out.add(new Unit(m.gav().toString(), m.relPath, m.graph(), m));
            }
        } else {
            for (Graph g : t.graphs) out.add(new Unit(g.root.gav().toString(), null, g, null));
        }
        if (moduleFilter != null) {
            List<Unit> f = new ArrayList<>();
            for (Unit u : out) {
                if (u.name().equals(moduleFilter) || u.ga().equals(moduleFilter) || moduleFilter.equals(u.relPath) || u.label.equals(moduleFilter)) f.add(u);
            }
            if (f.isEmpty()) {
                List<String> names = new ArrayList<>();
                for (Unit u : out) names.add(u.name());
                throw new UsageException("no module '" + moduleFilter + "' (modules: " + String.join(", ", names) + ")");
            }
            return f;
        }
        return out;
    }

    /** --scope values (comma separated or repeated), validated; null when not given. */
    static Set<String> scopes(Args args) {
        List<String> l = args.getAll("scope");
        if (l.isEmpty()) return null;
        Set<String> s = new LinkedHashSet<>();
        for (String x : l) {
            String v = x.toLowerCase(Locale.ROOT);
            if (!SCOPES.contains(v)) throw new UsageException("unknown scope '" + x + "' (use compile, provided, runtime, test, system)");
            s.add(v);
        }
        return s;
    }

    /** Patterns like "g:a", "g:*", "*jackson*" or a bare artifactId/groupId, matched against groupId:artifactId. */
    static final class Matcher {
        private final List<Pattern> patterns = new ArrayList<>();
        private final List<String> raw;

        Matcher(List<String> raw) {
            this.raw = raw;
            for (String r : raw) {
                String p = r.trim();
                // g:a:v filters ignore the version part for matching groupId:artifactId
                String[] parts = p.split(":");
                if (parts.length > 2) p = parts[0] + ":" + parts[1];
                if (!p.contains(":")) p = "*" + p + "*";
                StringBuilder re = new StringBuilder();
                for (char c : p.toCharArray()) {
                    if (c == '*') re.append(".*");
                    else re.append(Pattern.quote(String.valueOf(c)));
                }
                patterns.add(Pattern.compile(re.toString(), Pattern.CASE_INSENSITIVE));
            }
        }

        boolean isEmpty() { return patterns.isEmpty(); }

        List<String> raw() { return raw; }

        boolean matches(String ga) {
            if (patterns.isEmpty()) return true;
            for (Pattern p : patterns) if (p.matcher(ga).matches()) return true;
            return false;
        }

        boolean matches(DepNode n) {
            return matches(n.ga()) || (n.relocatedFrom != null && matches(gaOf(n.relocatedFrom)));
        }
    }

    static String gaOf(String gav) {
        String[] p = gav.split(":");
        return p.length >= 2 ? p[0] + ":" + p[1] : gav;
    }

    /** The preferred public identifier of an advisory: its CVE alias when there is one. */
    static String vulnId(Osv.Vuln v) {
        for (String a : v.aliases) if (a.startsWith("CVE-")) return a;
        return v.id;
    }

    /** True for an omitted sibling candidate of a version range (not a real conflict, just the range's choices). */
    static boolean rangeSibling(DepNode n) {
        return !n.selected && n.winner != null && n.range != null && n.range.equals(n.winner.range) && n.parent == n.winner.parent;
    }

    /** Selected artifacts of a set of graphs (each g:a:v once), for vulnerability lookups. */
    static List<Gav> selectedGavs(List<Unit> units) {
        Set<Gav> s = new LinkedHashSet<>();
        for (Unit u : units) for (DepNode n : u.graph.resolved()) if (n.version != null) s.add(n.gav());
        return new ArrayList<>(s);
    }

    /** Verifies that g:a:v exists on the configured repositories (usage error otherwise). */
    static void requireExists(Ctx ctx, Gav g) throws HttpException {
        List<String> vs = ctx.versions(g.groupId, g.artifactId, false);
        if (vs.isEmpty()) throw new UsageException(g.ga() + " was not found on " + ctx.repos.remotes().get(0).url);
        if (g.version != null && !vs.contains(g.version)) {
            throw new UsageException(g + " does not exist (latest: " + vs.get(vs.size() - 1) + ")");
        }
    }

    /** A dependencyManagement snippet pinning the given g:a:v coordinates. */
    static String managementSnippet(List<Gav> pins) {
        StringBuilder b = new StringBuilder();
        b.append("<dependencyManagement>\n  <dependencies>\n");
        for (Gav g : pins) {
            b.append("    <dependency>\n");
            b.append("      <groupId>").append(g.groupId).append("</groupId>\n");
            b.append("      <artifactId>").append(g.artifactId).append("</artifactId>\n");
            b.append("      <version>").append(g.version).append("</version>\n");
            b.append("    </dependency>\n");
        }
        b.append("  </dependencies>\n</dependencyManagement>");
        return b.toString();
    }

    /** Writes text to a file (creating folders), for --output. */
    static void write(String path, String text) throws IOException {
        java.nio.file.Path p = java.nio.file.Paths.get(path);
        if (p.toAbsolutePath().getParent() != null) java.nio.file.Files.createDirectories(p.toAbsolutePath().getParent());
        java.nio.file.Files.writeString(p, text, java.nio.charset.StandardCharsets.UTF_8);
    }
}
