package in.slashmark.maven.cli;

import in.slashmark.maven.bytecode.Jar;
import in.slashmark.maven.data.CentralSearch;
import in.slashmark.maven.data.DepsDev;
import in.slashmark.maven.data.Epss;
import in.slashmark.maven.data.GitHub;
import in.slashmark.maven.data.Kev;
import in.slashmark.maven.data.Osv;
import in.slashmark.maven.model.Gav;
import in.slashmark.maven.model.MavenVersion;
import in.slashmark.maven.model.ModelBuilder;
import in.slashmark.maven.repo.Metadata;
import in.slashmark.maven.repo.Repos;
import in.slashmark.maven.repo.Settings;
import in.slashmark.maven.resolve.DepNode;
import in.slashmark.maven.resolve.Graph;
import in.slashmark.maven.resolve.Resolver;
import in.slashmark.maven.util.Env;
import in.slashmark.maven.util.Http;
import in.slashmark.maven.util.HttpException;
import in.slashmark.maven.watch.Alerts;
import in.slashmark.maven.watch.State;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/** Everything a tool needs: output, configuration, clients for every live data source, and the project. */
public final class Ctx {
    public final Env env;
    public final Ui ui;
    public final Http http;
    public final Settings settings;
    public final Repos repos;
    public final ModelBuilder models;
    public final Resolver resolver;
    public final Osv osv;
    public final Kev kev;
    public final Epss epss;
    public final DepsDev depsDev;
    public final CentralSearch search;
    public final GitHub github;
    private final Args globals;
    private Project project;
    private Alerts alerts;
    private final Map<String, Jar> jarCache = new ConcurrentHashMap<>();

    public Ctx(Env env, Ui ui, Args globals) throws IOException {
        this.env = env;
        this.ui = ui;
        this.globals = globals;
        this.http = new Http(env.cacheDir());
        http.setCacheEnabled(!globals.flag("no-cache"));
        http.setVerbose(globals.flag("verbose"));
        Path settingsFile = globals.get("settings") != null ? Paths.get(globals.get("settings")) : env.userSettings();
        Settings s;
        try {
            s = Settings.load(settingsFile, System.getenv());
        } catch (IllegalArgumentException e) {
            throw new UsageException(settingsFile + ": " + e.getMessage());
        }
        this.settings = s;
        Path local = s.localRepository != null ? Paths.get(s.localRepository) : env.localRepo();
        this.repos = new Repos(http, env.central(), local, s);
        if (globals.flag("no-local")) repos.setUseLocal(false);
        String jdk = globals.get("jdk", System.getProperty("java.specification.version", "17"));
        this.models = new ModelBuilder(repos, globals.defines(), globals.getAll("profiles"), jdk);
        this.resolver = new Resolver(models);
        this.osv = new Osv(http, env.osv());
        this.kev = new Kev(http, env.kev());
        this.epss = new Epss(http, env.epss());
        this.depsDev = new DepsDev(http, env.depsDev());
        this.search = new CentralSearch(http, env.search());
        this.github = new GitHub(http, env.github(), env.githubToken());
    }

    public Args globals() { return globals; }

    public Path configDir() { return env.configDir(); }

    /**
     * Real-time mode for watch loops: repository metadata, advisory queries and search results are
     * fetched fresh every cycle (immutable artifacts stay cached).
     */
    public void live(long ttl) {
        repos.setMetadataTtl(ttl);
        osv.setTtl(ttl);
        search.setTtl(ttl);
    }

    public Alerts alerts() throws IOException {
        if (alerts == null) alerts = new Alerts(configDir(), http, env);
        return alerts;
    }

    public State state(String tool, String scope) { return State.of(configDir(), tool, scope); }

    // ---------------------------------------------------------------- project / targets

    /** The project from -f/--file or the current folder; throws a usage error when there is none. */
    public Project project() throws IOException, HttpException {
        if (project == null) {
            String f = globals.get("file");
            project = Project.load(Paths.get(f == null ? "." : f), models);
        }
        return project;
    }

    public boolean hasProject() {
        String f = globals.get("file");
        Path p = Paths.get(f == null ? "." : f);
        if (java.nio.file.Files.isDirectory(p)) p = p.resolve("pom.xml");
        return java.nio.file.Files.isRegularFile(p);
    }

    /** What a tool analyses: the local project's modules, or a published artifact given as coordinates. */
    public static final class Target {
        public final String label;
        public final Project project;
        public final List<Graph> graphs = new ArrayList<>();
        /** Set when the target is a published artifact rather than a local project. */
        public final Gav artifact;

        Target(String label, Project project, Gav artifact) {
            this.label = label;
            this.project = project;
            this.artifact = artifact;
        }

        /** Selected dependencies across all graphs, each g:a:v once (reactor modules excluded). */
        public List<DepNode> dependencies(Set<String> scopes) {
            if (project != null) return project.allResolved(scopes);
            Map<String, DepNode> m = new LinkedHashMap<>();
            for (Graph g : graphs) for (DepNode n : g.resolved(scopes)) m.putIfAbsent(n.gav().toString(), n);
            return new ArrayList<>(m.values());
        }

        public List<String> problems() {
            Set<String> s = new LinkedHashSet<>();
            if (project != null) s.addAll(project.problems);
            for (Graph g : graphs) s.addAll(g.allProblems());
            return new ArrayList<>(s);
        }
    }

    /**
     * Resolves the target: if the first positional looks like coordinates (g:a:v) that artifact is the
     * root; otherwise the project. Test-scoped dependencies are included unless --no-test.
     */
    public Target target(Args args, int posIndex) throws IOException, HttpException {
        String p = args.pos(posIndex);
        Resolver.Options opt = new Resolver.Options();
        opt.includeTest = !args.flag("no-test");
        if (p != null && Gav.looksLikeGav(p)) {
            Gav g = resolveLatest(Gav.parse(p));
            ui.progress("Resolving " + g + "...");
            ModelBuilder.Model m = models.buildRemote(g);
            if (m == null) throw new UsageException(g + " was not found on " + repos.remotes().get(0).url);
            Target t = new Target(g.toString(), null, g);
            t.graphs.add(resolver.resolve(m, opt));
            ui.progressDone();
            return t;
        }
        Project pr = project();
        pr.resolveAll(resolver, opt, ui);
        Target t = new Target(pr.rootModule().gav().toString(), pr, null);
        for (Project.Module m : pr.codeModules()) if (m.graph() != null) t.graphs.add(m.graph());
        return t;
    }

    /** Fills in the newest release when coordinates have no version (g:a). */
    public Gav resolveLatest(Gav g) throws HttpException {
        if (g.version != null && !g.version.equalsIgnoreCase("latest") && !g.version.equalsIgnoreCase("release")) return g;
        Metadata md = repos.metadata(g.groupId, g.artifactId);
        if (md == null) throw new UsageException(g.ga() + " was not found on " + repos.remotes().get(0).url);
        String v = md.newest(!"latest".equalsIgnoreCase(g.version));
        if (v == null) throw new UsageException(g.ga() + " has no published versions");
        return g.withVersion(v);
    }

    // ---------------------------------------------------------------- shared analyses

    /**
     * Known vulnerabilities for each coordinate (key "g:a:v"), from OSV, most severe first. Withdrawn
     * advisories are dropped.
     */
    public Map<String, List<Osv.Vuln>> vulnerabilities(Collection<Gav> gavs) throws HttpException {
        List<Gav> list = new ArrayList<>(new LinkedHashSet<>(gavs));
        List<String[]> q = new ArrayList<>();
        for (Gav g : list) q.add(new String[] {g.ga(), g.version});
        ui.progress("Checking " + list.size() + " artifacts against OSV...");
        List<List<String>> ids = osv.queryBatch(q);
        Set<String> all = new LinkedHashSet<>();
        for (List<String> l : ids) all.addAll(l);
        Map<String, Osv.Vuln> details = osv.getAll(all);
        Map<String, List<Osv.Vuln>> out = new LinkedHashMap<>();
        for (int i = 0; i < list.size(); i++) {
            List<Osv.Vuln> vs = new ArrayList<>();
            for (String id : ids.get(i)) {
                Osv.Vuln v = details.get(id);
                if (v == null || v.withdrawn) continue;
                vs.add(v);
            }
            vs.sort((a, b) -> {
                int c = Integer.compare(in.slashmark.maven.data.Cvss.rank(b.severity), in.slashmark.maven.data.Cvss.rank(a.severity));
                return c != 0 ? c : Double.compare(b.score, a.score);
            });
            out.put(list.get(i).toString(), vs);
        }
        ui.progressDone();
        return out;
    }

    /** Downloads and opens an artifact's JAR (cached per run). Null when it has no JAR. */
    public Jar jar(Gav gav) throws HttpException, IOException {
        String k = gav.toString();
        Jar j = jarCache.get(k);
        if (j != null) return j;
        Repos.Fetched f = repos.fetch(gav, null, "jar");
        if (f == null) return null;
        j = Jar.read(gav.artifactId + "-" + gav.version + ".jar", f.data);
        jarCache.put(k, j);
        return j;
    }

    /** Releases of g:a, ascending, optionally without pre-releases. */
    public List<String> versions(String groupId, String artifactId, boolean stableOnly) throws HttpException {
        Metadata md = repos.metadata(groupId, artifactId);
        List<String> out = new ArrayList<>();
        if (md == null) return out;
        for (String v : md.sortedVersions()) {
            MavenVersion mv = MavenVersion.of(v);
            if (mv.isSnapshot()) continue;
            if (stableOnly && mv.isPreRelease()) continue;
            out.add(v);
        }
        return out;
    }
}
