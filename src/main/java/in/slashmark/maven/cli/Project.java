package in.slashmark.maven.cli;

import in.slashmark.maven.model.Gav;
import in.slashmark.maven.model.ModelBuilder;
import in.slashmark.maven.resolve.DepNode;
import in.slashmark.maven.resolve.Graph;
import in.slashmark.maven.resolve.Resolver;
import in.slashmark.maven.util.HttpException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The Maven project being analysed: the root pom.xml plus every module of a multi-module build,
 * each with its effective model and (on demand) its resolved dependency graph.
 */
public final class Project {
    public static final class Module {
        public final Path pom;
        public final ModelBuilder.Model model;
        /** Path relative to the project root, "." for the root module. */
        public final String relPath;
        Graph graph;

        Module(Path pom, ModelBuilder.Model model, String relPath) {
            this.pom = pom;
            this.model = model;
            this.relPath = relPath;
        }

        public Gav gav() { return model.gav(); }

        public Path dir() { return pom.getParent(); }

        public String packaging() { return model.pom.packaging == null ? "jar" : model.pom.packaging; }

        /** target/classes when it exists (compiled output for bytecode analysis). */
        public Path classesDir() {
            Path p = dir().resolve("target").resolve("classes");
            return Files.isDirectory(p) ? p : null;
        }

        public Path testClassesDir() {
            Path p = dir().resolve("target").resolve("test-classes");
            return Files.isDirectory(p) ? p : null;
        }

        public Graph graph() { return graph; }

        @Override
        public String toString() { return gav() + " (" + relPath + ")"; }
    }

    public final Path root;
    public final List<Module> modules = new ArrayList<>();
    public final List<String> problems = new ArrayList<>();
    private final ModelBuilder models;
    private boolean resolved;

    private Project(Path root, ModelBuilder models) {
        this.root = root;
        this.models = models;
    }

    /** Locates pom.xml (a file, or a folder containing one) and loads it with all modules. */
    public static Project load(Path pathOrDir, ModelBuilder models) throws IOException, HttpException {
        Path pom = pathOrDir;
        if (Files.isDirectory(pom)) pom = pom.resolve("pom.xml");
        if (!Files.isRegularFile(pom)) {
            throw new UsageException("no pom.xml found at " + pathOrDir.toAbsolutePath().normalize()
                    + " (run inside a Maven project, pass -f <path/to/pom.xml>, or give coordinates like group:artifact:version)");
        }
        pom = pom.toAbsolutePath().normalize();
        Project p = new Project(pom.getParent(), models);
        p.loadModule(pom, ".", new LinkedHashSet<>());
        // Register every module first so inter-module dependencies resolve from disk.
        for (Module m : p.modules) models.addReactor(m.gav(), m.pom);
        for (Module m : p.modules) models.repos().addFrom(m.model.pom);
        return p;
    }

    private void loadModule(Path pom, String rel, Set<Path> seen) throws IOException, HttpException {
        if (!seen.add(pom)) return;
        ModelBuilder.Model m;
        try {
            m = models.buildFile(pom);
        } catch (IllegalArgumentException e) {
            if (modules.isEmpty()) throw new UsageException(pom + ": " + e.getMessage());
            problems.add(rel + ": " + e.getMessage());
            return;
        }
        Module mod = new Module(pom, m, rel);
        modules.add(mod);
        for (String p : m.problems) problems.add((rel.equals(".") ? "" : rel + ": ") + p);
        for (String moduleRef : m.pom.modules) {
            Path child = pom.getParent().resolve(moduleRef).normalize();
            if (Files.isDirectory(child)) child = child.resolve("pom.xml");
            if (!Files.isRegularFile(child)) {
                problems.add("module '" + moduleRef + "' listed in " + rel + "/pom.xml has no pom.xml");
                continue;
            }
            String childRel = root.relativize(child.getParent()).toString().replace('\\', '/');
            loadModule(child, childRel.isEmpty() ? "." : childRel, seen);
        }
    }

    public Module rootModule() { return modules.get(0); }

    public boolean multiModule() { return modules.size() > 1; }

    /** Modules that produce artifacts with dependencies worth analysing (skips pure aggregator POMs without deps). */
    public List<Module> codeModules() {
        List<Module> out = new ArrayList<>();
        for (Module m : modules) {
            if ("pom".equals(m.packaging()) && m.model.pom.dependencies.isEmpty()) continue;
            out.add(m);
        }
        if (out.isEmpty()) out.add(rootModule());
        return out;
    }

    public Module module(String nameOrPath) {
        for (Module m : modules) {
            if (m.relPath.equals(nameOrPath) || m.model.pom.artifactId.equals(nameOrPath) || m.gav().ga().equals(nameOrPath)) return m;
        }
        return null;
    }

    /** Resolves every code module's dependency graph (once). */
    public void resolveAll(Resolver resolver, Resolver.Options opt, Ui ui) throws HttpException {
        if (resolved) return;
        List<Module> todo = codeModules();
        int i = 0;
        for (Module m : todo) {
            ui.progress("Resolving " + m.model.pom.artifactId + " (" + (++i) + "/" + todo.size() + ")...");
            m.graph = resolver.resolve(m.model, opt);
        }
        ui.progressDone();
        resolved = true;
    }

    /** Selected dependency nodes across modules, de-duplicated by g:a:v (first module wins), reactor modules excluded. */
    public List<DepNode> allResolved(Set<String> scopes) {
        Map<String, DepNode> out = new LinkedHashMap<>();
        Set<String> reactor = models.reactorGavs();
        for (Module m : codeModules()) {
            if (m.graph == null) continue;
            for (DepNode n : m.graph.resolved(scopes)) {
                if (reactor.contains(n.gav().toString())) continue;
                out.putIfAbsent(n.gav().toString(), n);
            }
        }
        return new ArrayList<>(out.values());
    }

    /** Which modules use a given g:a:v. */
    public List<Module> modulesUsing(String gav) {
        List<Module> out = new ArrayList<>();
        for (Module m : codeModules()) {
            if (m.graph == null) continue;
            for (DepNode n : m.graph.resolved()) if (n.gav().toString().equals(gav)) { out.add(m); break; }
        }
        return out;
    }
}
