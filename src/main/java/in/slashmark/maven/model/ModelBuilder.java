package in.slashmark.maven.model;

import in.slashmark.maven.repo.Repos;
import in.slashmark.maven.util.HttpException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Builds effective POMs the way Maven does for dependency purposes: parent inheritance (local
 * relativePath or repository), profile activation, property interpolation, BOM imports and
 * dependency management injection. Build plugins are merged by groupId:artifactId.
 */
public final class ModelBuilder {
    public static final class Model {
        public final Pom pom;
        /** Parent chain, nearest first. */
        public final List<Gav> parents = new ArrayList<>();
        /** Managed dependencies by key (groupId:artifactId:type[:classifier]), as applied to transitive dependencies. */
        public final Map<String, Dependency> managed = new LinkedHashMap<>();
        /** The effective dependencyManagement list in Maven's order (may contain duplicate keys). */
        public final List<Dependency> managedList = new ArrayList<>();
        /** BOMs imported (directly or transitively). */
        public final List<Gav> importedBoms = new ArrayList<>();
        public final List<String> problems = new ArrayList<>();
        public final List<String> activeProfiles = new ArrayList<>();

        Model(Pom p) { pom = p; }

        public Gav gav() { return pom.gav(); }

        public Dependency managedFor(String groupId, String artifactId) {
            for (Dependency d : managed.values()) if (d.groupId.equals(groupId) && d.artifactId.equals(artifactId)) return d;
            return null;
        }
    }

    private final Repos repos;
    private final Map<String, String> sysProps;
    private final Set<String> explicitProfiles;
    private final Set<String> disabledProfiles;
    private final String jdk;
    private final Map<String, Model> remoteCache = new ConcurrentHashMap<>();
    /** Modules of the local build: their POMs are read from disk instead of a repository. */
    private final Map<String, Path> reactor = new ConcurrentHashMap<>();

    public ModelBuilder(Repos repos, Map<String, String> sysProps, Collection<String> profiles, String jdk) {
        this.repos = repos;
        this.sysProps = sysProps == null ? Map.of() : sysProps;
        this.explicitProfiles = new LinkedHashSet<>();
        this.disabledProfiles = new LinkedHashSet<>();
        if (profiles != null) {
            for (String p : profiles) {
                for (String q : p.split(",")) {
                    q = q.trim();
                    if (q.isEmpty()) continue;
                    if (q.startsWith("!") || q.startsWith("-")) disabledProfiles.add(q.substring(1));
                    else explicitProfiles.add(q.startsWith("+") ? q.substring(1) : q);
                }
            }
        }
        this.jdk = jdk == null ? System.getProperty("java.specification.version", "17") : jdk;
    }

    public Repos repos() { return repos; }

    /** Registers a module of the local multi-module build. */
    public void addReactor(Gav gav, Path pomFile) { reactor.put(gav.toString(), pomFile); }

    public boolean inReactor(Gav gav) { return reactor.containsKey(gav.toString()); }

    public java.util.Set<String> reactorGavs() { return reactor.keySet(); }

    /** Effective model of a pom.xml on disk. */
    public Model buildFile(Path pomFile) throws IOException, HttpException {
        Pom raw = Pom.parse(Files.readAllBytes(pomFile), pomFile.toString());
        raw.file = pomFile.toAbsolutePath().normalize();
        return build(raw, new HashSet<>());
    }

    /** Effective model of a published artifact; returns null when the POM cannot be found. */
    public Model buildRemote(Gav gav) throws HttpException {
        String k = gav.toString();
        Model c = remoteCache.get(k);
        if (c != null) return c;
        Path local = reactor.get(k);
        if (local != null) {
            try {
                Model m = buildFile(local);
                remoteCache.put(k, m);
                return m;
            } catch (IOException e) {
                throw new HttpException(local.toString(), 0, e.getMessage());
            }
        }
        byte[] data = repos.pom(gav);
        if (data == null) return null;
        Pom raw;
        try {
            raw = Pom.parse(data, gav.toString());
        } catch (IllegalArgumentException e) {
            Pom stub = new Pom();
            stub.groupId = gav.groupId;
            stub.artifactId = gav.artifactId;
            stub.version = gav.version;
            Model m = new Model(stub);
            m.problems.add("unreadable POM for " + gav + ": " + e.getMessage());
            remoteCache.put(k, m);
            return m;
        }
        Model m;
        try {
            m = build(raw, new HashSet<>());
        } catch (IOException e) {
            throw new HttpException(gav.toString(), 0, e.getMessage());
        }
        remoteCache.put(k, m);
        return m;
    }

    private Model build(Pom raw, Set<String> seen) throws IOException, HttpException {
        // 1. Lineage, child first.
        List<Pom> lineage = new ArrayList<>();
        List<String> problems = new ArrayList<>();
        List<Gav> parents = new ArrayList<>();
        Pom cur = raw;
        lineage.add(cur);
        Set<String> chain = new HashSet<>();
        while (cur.parent != null) {
            Pom.Parent pa = cur.parent;
            String pv = pa.version;
            if (pv != null && pv.contains("${")) pv = interpolate(pv, mergedProps(lineage), null, problems);
            Gav pg = new Gav(pa.groupId, pa.artifactId, pv);
            if (!chain.add(pg.toString())) {
                problems.add("parent cycle at " + pg);
                break;
            }
            Pom parentPom = null;
            if (cur.file != null && pa.relativePath != null && !pa.relativePath.isEmpty()) {
                Path rp = cur.file.getParent().resolve(pa.relativePath).normalize();
                if (Files.isDirectory(rp)) rp = rp.resolve("pom.xml");
                if (Files.isRegularFile(rp)) {
                    try {
                        Pom cand = Pom.parse(Files.readAllBytes(rp), rp.toString());
                        if (pa.artifactId != null && pa.artifactId.equals(cand.artifactId)
                                && (pa.groupId == null || pa.groupId.equals(cand.effectiveGroupId()))) {
                            cand.file = rp.toAbsolutePath().normalize();
                            parentPom = cand;
                            if (cand.effectiveVersion() != null && pv != null && !cand.effectiveVersion().contains("${") && !cand.effectiveVersion().equals(pv)) {
                                problems.add("parent " + pg.ga() + " at " + pa.relativePath + " has version " + cand.effectiveVersion() + ", not " + pv);
                            }
                        }
                    } catch (IllegalArgumentException e) {
                        problems.add("cannot parse parent " + rp + ": " + e.getMessage());
                    }
                }
            }
            if (parentPom == null && pg.version != null && !pg.version.contains("${")) {
                byte[] data = repos.pom(pg);
                if (data != null) {
                    try {
                        parentPom = Pom.parse(data, pg.toString());
                    } catch (IllegalArgumentException e) {
                        problems.add("cannot parse parent " + pg + ": " + e.getMessage());
                    }
                }
            }
            if (parentPom == null) {
                problems.add("parent " + pg + " not found");
                break;
            }
            parents.add(pg);
            lineage.add(parentPom);
            cur = parentPom;
        }

        // 2. Activate profiles per POM and merge from the root ancestor down to the child.
        Pom eff = new Pom();
        eff.source = raw.source;
        eff.file = raw.file;
        eff.lines.putAll(raw.lines);
        List<String> active = new ArrayList<>();
        for (int i = lineage.size() - 1; i >= 0; i--) {
            Pom p = lineage.get(i);
            Pom withProfiles = applyProfiles(p, active, i == 0);
            inherit(eff, withProfiles, i == 0);
        }
        eff.artifactId = raw.artifactId;
        eff.packaging = raw.packaging;
        eff.relocation = raw.relocation;
        eff.groupId = raw.groupId != null ? raw.groupId : raw.parent != null ? raw.parent.groupId : null;
        eff.version = raw.version != null ? raw.version : raw.parent != null ? raw.parent.version : null;
        eff.name = raw.name;
        eff.description = raw.description != null ? raw.description : eff.description;
        eff.parent = raw.parent;
        eff.modules.clear();
        eff.modules.addAll(raw.modules);
        for (Pom.Profile pr : raw.profiles) if (active.contains(pr.id)) eff.modules.addAll(pr.modules);

        // 3. Interpolation.
        Map<String, String> props = new LinkedHashMap<>(eff.properties);
        Map<String, String> ctx = projectContext(eff, raw);
        eff.groupId = interpolate(eff.groupId, props, ctx, problems);
        eff.version = interpolate(eff.version, props, ctx, problems);
        ctx = projectContext(eff, raw);
        for (Map.Entry<String, String> e : eff.properties.entrySet()) e.setValue(interpolate(e.getValue(), props, ctx, null));
        props = new LinkedHashMap<>(eff.properties);
        for (Dependency d : eff.dependencies) interpolate(d, props, ctx, problems);
        for (Dependency d : eff.dependencyManagement) interpolate(d, props, ctx, problems);
        for (Pom.Plugin pl : eff.plugins) interpolate(pl, props, ctx, problems);
        for (Pom.Plugin pl : eff.pluginManagement) interpolate(pl, props, ctx, problems);
        for (Pom.Extension x : eff.extensions) x.version = interpolate(x.version, props, ctx, null);
        for (Pom.Repository r : eff.repositories) r.url = interpolate(r.url, props, ctx, null);
        for (Pom.License l : eff.licenses) l.name = interpolate(l.name, props, ctx, null);
        eff.url = interpolate(eff.url, props, ctx, null);
        eff.scmUrl = interpolate(eff.scmUrl, props, ctx, null);
        eff.scmConnection = interpolate(eff.scmConnection, props, ctx, null);
        eff.name = interpolate(eff.name, props, ctx, null);
        eff.description = interpolate(eff.description, props, ctx, null);

        Model model = new Model(eff);
        model.parents.addAll(parents);
        model.problems.addAll(problems);
        model.activeProfiles.addAll(active);

        // 4. Dependency management incl. imported BOMs, following Maven's DefaultDependencyManagementImporter:
        //    when anything is imported, declared entries are collapsed by key (last declaration wins, first
        //    position kept) and imported entries are appended only for keys not declared (first BOM wins).
        //    Without imports, duplicate declarations stay in the list.
        String self = eff.gav().toString();
        Set<String> seenHere = new HashSet<>(seen);
        seenHere.add(self);
        List<Dependency> declared = new ArrayList<>();
        List<Model> imports = new ArrayList<>();
        for (Dependency d : eff.dependencyManagement) {
            if (!("import".equals(d.scope) && "pom".equals(d.type))) {
                declared.add(d);
                continue;
            }
            Gav bom = d.gav();
            if (bom.version == null || bom.version.contains("${")) {
                model.problems.add("cannot import BOM " + d.ga() + ": version " + d.version + " unresolved");
                continue;
            }
            if (seenHere.contains(bom.toString())) {
                model.problems.add("BOM import cycle at " + bom);
                continue;
            }
            Model bm = importBom(bom, seenHere);
            if (bm == null) {
                model.problems.add("BOM " + bom + " not found");
                continue;
            }
            model.importedBoms.add(bom);
            for (Gav g : bm.importedBoms) if (!model.importedBoms.contains(g)) model.importedBoms.add(g);
            imports.add(bm);
        }
        if (imports.isEmpty()) {
            model.managedList.addAll(declared);
        } else {
            Map<String, Dependency> byKey = new LinkedHashMap<>();
            for (Dependency d : declared) byKey.put(d.key(), d);
            for (Model bm : imports) {
                for (Dependency d : bm.managedList) byKey.putIfAbsent(d.key(), d.copy());
            }
            model.managedList.addAll(byKey.values());
        }
        // The view used for transitive management: per key, the first non-empty value of each attribute
        // (maven-resolver's AbstractDependencyManager).
        for (Dependency d : model.managedList) {
            Dependency m = model.managed.get(d.key());
            if (m == null) {
                model.managed.put(d.key(), d.copy());
                continue;
            }
            if (m.version == null) m.version = d.version;
            if (m.scope == null) m.scope = d.scope;
            if (m.optional == null) m.optional = d.optional;
            if (m.systemPath == null) m.systemPath = d.systemPath;
            for (String[] x : d.exclusions) m.exclusions.add(x.clone());
        }

        // 5. Inject management into the POM's own dependencies, as Maven's DefaultDependencyManagementInjector does:
        //    every managed entry is merged in declaration order and only fills attributes that are still empty
        //    (so with duplicate entries the first one wins), exclusions are copied only when the dependency
        //    has none, and <optional> is never injected.
        Map<String, Dependency> own = new HashMap<>();
        for (Dependency d : eff.dependencies) own.put(d.key(), d);
        for (Dependency m : model.managedList) {
            Dependency d = own.get(m.key());
            if (d == null) continue;
            if (d.version == null) d.version = m.version;
            if (d.scope == null) d.scope = m.scope;
            if (d.systemPath == null) d.systemPath = m.systemPath;
            if (d.exclusions.isEmpty() && !m.exclusions.isEmpty()) for (String[] x : m.exclusions) d.exclusions.add(x.clone());
        }
        for (Dependency d : eff.dependencies) {
            if (d.version == null && !"system".equals(d.scope)) model.problems.add("dependency " + d.ga() + " has no version (not managed)");
        }
        // Plugin versions from pluginManagement.
        for (Pom.Plugin pl : eff.plugins) {
            if (pl.version != null) continue;
            for (Pom.Plugin pm : eff.pluginManagement) if (pm.ga().equals(pl.ga())) pl.version = pm.version;
        }
        return model;
    }

    private Model importBom(Gav bom, Set<String> seen) throws HttpException {
        String k = bom.toString();
        Model c = remoteCache.get(k);
        if (c != null) return c;
        byte[] data = repos.pom(bom);
        if (data == null) return null;
        try {
            Pom raw = Pom.parse(data, bom.toString());
            Model m = build(raw, seen);
            remoteCache.put(k, m);
            return m;
        } catch (IOException | IllegalArgumentException e) {
            return null;
        }
    }

    // ---------------------------------------------------------------- inheritance

    private static Map<String, String> mergedProps(List<Pom> lineage) {
        Map<String, String> m = new LinkedHashMap<>();
        for (int i = lineage.size() - 1; i >= 0; i--) m.putAll(lineage.get(i).properties);
        return m;
    }

    private static void inherit(Pom eff, Pom p, boolean isChild) {
        eff.properties.putAll(p.properties);
        mergeDeps(eff.dependencyManagement, p.dependencyManagement, false);
        mergeDeps(eff.dependencies, p.dependencies);
        if (!p.licenses.isEmpty()) {
            eff.licenses.clear();
            eff.licenses.addAll(p.licenses);
        }
        if (!p.developers.isEmpty()) {
            eff.developers.clear();
            eff.developers.addAll(p.developers);
        }
        String prevArtifact = eff.artifactId;
        if (p.url != null) eff.url = p.url;
        else if (eff.url != null && isChild && p.artifactId != null) eff.url = appendPath(eff.url, p.artifactId);
        if (p.scmUrl != null) eff.scmUrl = p.scmUrl;
        else if (eff.scmUrl != null && isChild && p.artifactId != null) eff.scmUrl = appendPath(eff.scmUrl, p.artifactId);
        if (p.scmConnection != null) eff.scmConnection = p.scmConnection;
        if (p.scmDeveloperConnection != null) eff.scmDeveloperConnection = p.scmDeveloperConnection;
        if (p.scmTag != null) eff.scmTag = p.scmTag;
        if (p.organizationName != null) eff.organizationName = p.organizationName;
        if (p.organizationUrl != null) eff.organizationUrl = p.organizationUrl;
        if (p.issueUrl != null) eff.issueUrl = p.issueUrl;
        if (p.ciUrl != null) eff.ciUrl = p.ciUrl;
        if (p.description != null) eff.description = p.description;
        if (p.inceptionYear != null) eff.inceptionYear = p.inceptionYear;
        if (p.distributionRelease != null) eff.distributionRelease = p.distributionRelease;
        if (p.distributionSnapshot != null) eff.distributionSnapshot = p.distributionSnapshot;
        if (p.prerequisitesMaven != null) eff.prerequisitesMaven = p.prerequisitesMaven;
        for (Pom.Repository r : p.repositories) {
            eff.repositories.removeIf(x -> x.id != null && x.id.equals(r.id));
            eff.repositories.add(r);
        }
        for (Pom.Repository r : p.pluginRepositories) {
            eff.pluginRepositories.removeIf(x -> x.id != null && x.id.equals(r.id));
            eff.pluginRepositories.add(r);
        }
        mergePlugins(eff.pluginManagement, p.pluginManagement, true);
        mergePlugins(eff.plugins, p.plugins, isChild);
        eff.extensions.addAll(p.extensions);
        eff.artifactId = p.artifactId != null ? p.artifactId : prevArtifact;
        if (p.groupId != null) eff.groupId = p.groupId;
        if (p.version != null) eff.version = p.version;
    }

    private static String appendPath(String base, String child) {
        if (base.endsWith("/")) return base + child;
        return base + "/" + child;
    }

    /**
     * Merges a more specific list (child, or an active profile) over an inherited one. As in Maven, the
     * dominant entries come first in declaration order, followed by inherited entries they don't override.
     */
    private static void mergeDeps(List<Dependency> into, List<Dependency> dominant) { mergeDeps(into, dominant, true); }

    /**
     * collapseAlways=false is for dependencyManagement: Maven keeps duplicate declarations there unless
     * an inherited list has to be merged in.
     */
    private static void mergeDeps(List<Dependency> into, List<Dependency> dominant, boolean collapseAlways) {
        if (dominant.isEmpty()) return;
        if (!collapseAlways && into.isEmpty()) {
            for (Dependency d : dominant) into.add(d.copy());
            return;
        }
        // Duplicate declarations in one POM: the last one wins but keeps the first one's position (as Maven does).
        Map<String, Dependency> byKey = new LinkedHashMap<>();
        for (Dependency d : dominant) byKey.put(d.key(), d.copy());
        List<Dependency> merged = new ArrayList<>(byKey.values());
        for (Dependency d : into) if (!byKey.containsKey(d.key())) merged.add(d);
        into.clear();
        into.addAll(merged);
    }

    private static void mergePlugins(List<Pom.Plugin> into, List<Pom.Plugin> from, boolean keepNonInherited) {
        for (Pom.Plugin p : from) {
            // <inherited>false</inherited> plugins apply only to the POM that declares them.
            if (!keepNonInherited && !p.inherited) continue;
            boolean replaced = false;
            for (int i = 0; i < into.size(); i++) {
                Pom.Plugin q = into.get(i);
                if (q.ga().equals(p.ga())) {
                    if (p.version == null) p.version = q.version;
                    for (Map.Entry<String, String> e : q.configuration.entrySet()) p.configuration.putIfAbsent(e.getKey(), e.getValue());
                    for (String g : q.goals) if (!p.goals.contains(g)) p.goals.add(g);
                    into.set(i, p);
                    replaced = true;
                    break;
                }
            }
            if (!replaced) into.add(p);
        }
    }

    // ---------------------------------------------------------------- profiles

    private Pom applyProfiles(Pom p, List<String> activeOut, boolean isChild) {
        List<Pom.Profile> on = new ArrayList<>();
        boolean anyNonDefault = false;
        for (Pom.Profile pr : p.profiles) {
            if (pr.id != null && disabledProfiles.contains(pr.id)) continue;
            if ((pr.id != null && explicitProfiles.contains(pr.id)) || triggered(pr, p)) {
                on.add(pr);
                anyNonDefault = true;
            }
        }
        if (!anyNonDefault) {
            for (Pom.Profile pr : p.profiles) {
                if (pr.activeByDefault && (pr.id == null || !disabledProfiles.contains(pr.id))) on.add(pr);
            }
        }
        if (on.isEmpty()) return p;
        Pom copy = shallowCopy(p);
        for (Pom.Profile pr : on) {
            if (pr.id != null && !activeOut.contains(pr.id)) activeOut.add(pr.id);
            copy.properties.putAll(pr.properties);
            mergeDeps(copy.dependencies, pr.dependencies);
            mergeDeps(copy.dependencyManagement, pr.dependencyManagement, false);
            copy.repositories.addAll(pr.repositories);
            mergePlugins(copy.plugins, pr.plugins, true);
            mergePlugins(copy.pluginManagement, pr.pluginManagement, true);
        }
        return copy;
    }

    private static Pom shallowCopy(Pom p) {
        Pom c = new Pom();
        c.groupId = p.groupId;
        c.artifactId = p.artifactId;
        c.version = p.version;
        c.packaging = p.packaging;
        c.name = p.name;
        c.description = p.description;
        c.url = p.url;
        c.parent = p.parent;
        c.properties.putAll(p.properties);
        for (Dependency d : p.dependencies) c.dependencies.add(d.copy());
        for (Dependency d : p.dependencyManagement) c.dependencyManagement.add(d.copy());
        c.modules.addAll(p.modules);
        c.licenses.addAll(p.licenses);
        c.developers.addAll(p.developers);
        c.scmUrl = p.scmUrl;
        c.scmConnection = p.scmConnection;
        c.scmDeveloperConnection = p.scmDeveloperConnection;
        c.scmTag = p.scmTag;
        c.organizationName = p.organizationName;
        c.organizationUrl = p.organizationUrl;
        c.issueUrl = p.issueUrl;
        c.ciUrl = p.ciUrl;
        c.relocation = p.relocation;
        c.repositories.addAll(p.repositories);
        c.pluginRepositories.addAll(p.pluginRepositories);
        c.distributionRelease = p.distributionRelease;
        c.distributionSnapshot = p.distributionSnapshot;
        c.plugins.addAll(p.plugins);
        c.pluginManagement.addAll(p.pluginManagement);
        c.extensions.addAll(p.extensions);
        c.prerequisitesMaven = p.prerequisitesMaven;
        c.inceptionYear = p.inceptionYear;
        c.source = p.source;
        c.file = p.file;
        return c;
    }

    private boolean triggered(Pom.Profile pr, Pom p) {
        boolean any = false;
        if (pr.activationJdk != null) {
            any = true;
            if (!jdkMatches(pr.activationJdk.trim(), jdk)) return false;
        }
        if (pr.activationProperty != null) {
            any = true;
            String name = pr.activationProperty;
            boolean neg = name.startsWith("!");
            if (neg) name = name.substring(1);
            String val = sysProps.get(name);
            if (pr.activationPropertyValue == null) {
                if (neg == (val != null)) return false;
            } else {
                String want = pr.activationPropertyValue;
                boolean vneg = want.startsWith("!");
                if (vneg) want = want.substring(1);
                boolean eq = want.equals(val);
                if (vneg == eq) return false;
            }
        }
        if (pr.activationFileExists != null || pr.activationFileMissing != null) {
            any = true;
            Path base = p.file == null ? null : p.file.getParent();
            if (base == null) return false;
            if (pr.activationFileExists != null && !Files.exists(base.resolve(pr.activationFileExists.replace("${basedir}", base.toString()).replace("${project.basedir}", base.toString())))) return false;
            if (pr.activationFileMissing != null && Files.exists(base.resolve(pr.activationFileMissing.replace("${basedir}", base.toString()).replace("${project.basedir}", base.toString())))) return false;
        }
        if (pr.activationOs != null) {
            any = true;
            String os = System.getProperty("os.name", "").toLowerCase();
            String want = pr.activationOs.toLowerCase();
            boolean neg = want.startsWith("!");
            if (neg) want = want.substring(1);
            boolean match = os.contains(want) || ("unix".equals(want) && !os.contains("win")) || ("mac".equals(want) && os.contains("mac"));
            if (match == neg) return false;
        }
        return any;
    }

    static boolean jdkMatches(String spec, String jdk) {
        boolean neg = spec.startsWith("!");
        if (neg) spec = spec.substring(1);
        boolean r;
        if (spec.startsWith("[") || spec.startsWith("(")) {
            try {
                r = VersionRange.parse(spec).contains(jdk);
            } catch (IllegalArgumentException e) {
                r = false;
            }
        } else {
            r = jdk.equals(spec) || jdk.startsWith(spec + ".") || ("1." + jdk).startsWith(spec);
        }
        return neg != r;
    }

    // ---------------------------------------------------------------- interpolation

    private static final Pattern EXPR = Pattern.compile("\\$\\{([^}]+)}");

    private Map<String, String> projectContext(Pom eff, Pom raw) {
        Map<String, String> c = new LinkedHashMap<>();
        for (String pre : new String[] {"project.", "pom.", ""}) {
            if (eff.groupId != null) c.put(pre + "groupId", eff.groupId);
            if (eff.artifactId != null) c.put(pre + "artifactId", eff.artifactId);
            if (eff.version != null) c.put(pre + "version", eff.version);
            if (eff.packaging != null) c.put(pre + "packaging", eff.packaging);
            if (eff.name != null) c.put(pre + "name", eff.name);
            if (eff.url != null) c.put(pre + "url", eff.url);
            if (raw.parent != null) {
                if (raw.parent.version != null) c.put(pre + "parent.version", raw.parent.version);
                if (raw.parent.groupId != null) c.put(pre + "parent.groupId", raw.parent.groupId);
                if (raw.parent.artifactId != null) c.put(pre + "parent.artifactId", raw.parent.artifactId);
            }
        }
        if (raw.file != null) {
            String b = raw.file.getParent().toString();
            c.put("basedir", b);
            c.put("project.basedir", b);
            c.put("project.build.directory", b + "/target");
        }
        c.put("java.version", jdk);
        c.put("java.specification.version", jdk);
        return c;
    }

    String interpolate(String s, Map<String, String> props, Map<String, String> ctx, List<String> problems) {
        if (s == null || !s.contains("${")) return s;
        String cur = s;
        for (int round = 0; round < 12 && cur.contains("${"); round++) {
            Matcher m = EXPR.matcher(cur);
            StringBuilder b = new StringBuilder();
            boolean changed = false;
            while (m.find()) {
                String key = m.group(1);
                String v = sysProps.get(key);
                if (v == null && ctx != null) {
                    // Model values (project.version, ...) take precedence over same-named properties, as in Maven.
                    if (key.startsWith("project.") || key.startsWith("pom.")) v = ctx.get(key);
                }
                if (v == null) v = props.get(key);
                if (v == null && ctx != null) v = ctx.get(key);
                if (v == null && key.startsWith("env.")) v = System.getenv(key.substring(4));
                if (v == null && key.startsWith("settings.")) v = null;
                if (v != null && !v.equals(m.group(0))) {
                    changed = true;
                    m.appendReplacement(b, Matcher.quoteReplacement(v));
                } else {
                    m.appendReplacement(b, Matcher.quoteReplacement(m.group(0)));
                }
            }
            m.appendTail(b);
            cur = b.toString();
            if (!changed) break;
        }
        if (problems != null && cur.contains("${")) {
            Matcher m = EXPR.matcher(cur);
            if (m.find()) {
                String msg = "unresolved expression " + m.group(0) + " in '" + s + "'";
                if (!problems.contains(msg)) problems.add(msg);
            }
        }
        return cur;
    }

    private void interpolate(Dependency d, Map<String, String> props, Map<String, String> ctx, List<String> problems) {
        d.groupId = interpolate(d.groupId, props, ctx, problems);
        d.artifactId = interpolate(d.artifactId, props, ctx, problems);
        d.version = interpolate(d.version, props, ctx, problems);
        d.type = interpolate(d.type, props, ctx, null);
        d.classifier = interpolate(d.classifier, props, ctx, null);
        d.scope = interpolate(d.scope, props, ctx, null);
        d.optional = interpolate(d.optional, props, ctx, null);
        d.systemPath = interpolate(d.systemPath, props, ctx, null);
        for (String[] x : d.exclusions) {
            x[0] = interpolate(x[0], props, ctx, null);
            x[1] = interpolate(x[1], props, ctx, null);
        }
    }

    private void interpolate(Pom.Plugin pl, Map<String, String> props, Map<String, String> ctx, List<String> problems) {
        pl.groupId = interpolate(pl.groupId, props, ctx, null);
        pl.artifactId = interpolate(pl.artifactId, props, ctx, null);
        pl.version = interpolate(pl.version, props, ctx, null);
        for (Map.Entry<String, String> e : pl.configuration.entrySet()) e.setValue(interpolate(e.getValue(), props, ctx, null));
        for (Dependency d : pl.dependencies) interpolate(d, props, ctx, null);
    }
}
