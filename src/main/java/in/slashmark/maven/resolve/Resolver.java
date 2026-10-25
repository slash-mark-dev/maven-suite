package in.slashmark.maven.resolve;

import in.slashmark.maven.model.Dependency;
import in.slashmark.maven.model.Gav;
import in.slashmark.maven.model.MavenVersion;
import in.slashmark.maven.model.ModelBuilder;
import in.slashmark.maven.model.VersionRange;
import in.slashmark.maven.repo.Metadata;
import in.slashmark.maven.util.Http;
import in.slashmark.maven.util.HttpException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Maven 3 dependency resolution: depth-first collection with root dependency management applied to
 * transitive dependencies (ClassicDependencyManager), test/provided/optional pruning below direct
 * dependencies, accumulated exclusions, relocations, then conflict mediation with Maven's rules:
 * nearest wins, first declaration breaks ties, direct scope wins otherwise the widest derived scope,
 * and optional only if every occurrence is optional.
 */
public final class Resolver {
    private final ModelBuilder models;
    private final Map<String, ModelBuilder.Model> modelCache = new ConcurrentHashMap<>();
    private final Map<String, String> missing = new ConcurrentHashMap<>();
    private int maxNodes = 250_000;
    private int counter;

    public Resolver(ModelBuilder models) { this.models = models; }

    public ModelBuilder models() { return models; }

    public void setMaxNodes(int n) { maxNodes = n; }

    /** Options for one resolution. */
    public static final class Options {
        /** Extra managed versions that override everything (g:a -> version), used to simulate pins/upgrades. */
        public final Map<String, String> pins = new LinkedHashMap<>();
        /** Replace direct dependency versions (g:a -> version) as if pom.xml said so. */
        public final Map<String, String> directOverrides = new LinkedHashMap<>();
        /** Extra direct dependencies to add (simulating "what if I add X"). */
        public final List<Dependency> extraDirect = new ArrayList<>();
        /** Include test-scoped direct dependencies (and their trees). */
        public boolean includeTest = true;
        /** Prefetch POMs in parallel before collecting (much faster on cold caches). */
        public boolean prefetch = true;
    }

    // ------------------------------------------------------------------------------------------------

    public Graph resolve(ModelBuilder.Model root, Options opt) throws HttpException {
        if (opt == null) opt = new Options();
        counter = 0;
        Graph g = new Graph(root);
        Map<String, Dependency> managed = new LinkedHashMap<>();
        for (Dependency d : root.managed.values()) managed.put(mgmtKey(d.groupId, d.artifactId, d.type, d.classifier), d);
        for (Map.Entry<String, String> pin : opt.pins.entrySet()) {
            String[] ga = pin.getKey().split(":");
            Dependency d = new Dependency();
            d.groupId = ga[0];
            d.artifactId = ga[1];
            d.version = pin.getValue();
            String key = mgmtKey(d.groupId, d.artifactId, "jar", null);
            Dependency existing = managed.get(key);
            if (existing != null) {
                Dependency c = existing.copy();
                c.version = pin.getValue();
                managed.put(key, c);
            } else managed.put(key, d);
        }

        List<Dependency> direct = new ArrayList<>();
        for (Dependency d : root.pom.dependencies) {
            Dependency c = d.copy();
            String ov = opt.directOverrides.get(c.ga());
            if (ov != null) c.version = ov;
            else if (opt.pins.containsKey(c.ga())) c.version = opt.pins.get(c.ga());
            direct.add(c);
        }
        for (Dependency d : opt.extraDirect) direct.add(d.copy());

        if (opt.prefetch) prefetch(direct, managed);

        pool = new HashMap<>();
        for (Dependency d : direct) {
            if (!opt.includeTest && "test".equals(d.scopeOrDefault())) continue;
            if (d.version == null && !"system".equals(d.scopeOrDefault())) {
                g.problems.add(d.ga() + " has no version");
                continue;
            }
            process(d.copy(), null, managed, g, new ArrayList<>(), null, false, Set.of(), d.line);
        }
        mediate(g);
        return g;
    }

    /** Key used by dependency management (type is normalised to its extension/classifier like Maven). */
    static String mgmtKey(String g, String a, String type, String classifier) {
        String t = type == null ? "jar" : type;
        String cl = classifier;
        if ("test-jar".equals(t)) { t = "jar"; if (cl == null) cl = "tests"; }
        if ("bundle".equals(t) || "maven-plugin".equals(t) || "ejb".equals(t) || "ejb-client".equals(t) || "java-source".equals(t) || "javadoc".equals(t)) t = "jar";
        return g + ":" + a + ":" + t + (cl == null || cl.isEmpty() ? "" : ":" + cl);
    }

    /** Children lists already built, by Maven's pool key (artifact + accumulated exclusions). */
    private Map<String, DepNode> pool = new HashMap<>();

    /**
     * Processes one dependency edge like maven-resolver's depth-first collector: management (below the
     * direct level), version ranges (one node per matching version), relocations (processed again under
     * the new coordinates), cycle detection against the current path (versionless) and child-list reuse
     * for an artifact already expanded with the same exclusions.
     *
     * @param parentExcl exclusions accumulated above this edge (excluding the dependency's own)
     */
    private void process(Dependency c, DepNode parent, Map<String, Dependency> managed, Graph g, List<String> relocations,
                         String premanagedFrom, boolean disableVersionManagement, Set<String> parentExcl, int line) {
        if (counter > maxNodes) {
            if (!g.truncated) g.problems.add("dependency graph larger than " + maxNodes + " nodes; truncated");
            g.truncated = true;
            return;
        }
        int depth = parent == null ? 1 : parent.depth + 1;
        String pre = null, preScope = null;
        boolean mScope = false, mOptional = false;
        if (depth >= 2) {
            // Classic dependency management: the root's management applies to every transitive dependency.
            Dependency mg = managed.get(mgmtKey(c.groupId, c.artifactId, c.type, c.classifier));
            if (mg != null) {
                if (!disableVersionManagement && mg.version != null && !mg.version.equals(c.version)) { pre = c.version; c.version = mg.version; }
                if (mg.scope != null && !"import".equals(mg.scope) && !"system".equals(mg.scope)) {
                    if (!mg.scope.equals(c.scopeOrDefault())) preScope = c.scopeOrDefault();
                    c.scope = mg.scope;
                    mScope = true;
                }
                if (mg.optional != null) { c.optional = mg.optional; mOptional = true; }
                for (String[] x : mg.exclusions) c.exclusions.add(x.clone());
            }
        }
        if (premanagedFrom != null && pre == null) pre = premanagedFrom;
        if (c.version == null) {
            if (parent != null) parent.problems.add(c.ga() + " (needed by " + parent.ga() + ") has no version");
            return;
        }
        Set<String> excl = new LinkedHashSet<>(parentExcl);
        for (String[] x : c.exclusions) excl.add(x[0] + ":" + x[1]);
        List<String> versions = new ArrayList<>();
        String range = null;
        List<String> rangeProblems = new ArrayList<>();
        if (c.version.startsWith("[") || c.version.startsWith("(")) {
            range = c.version;
            versions = rangeVersions(c.groupId, c.artifactId, range, rangeProblems);
        } else versions.add(c.version);
        if (versions.isEmpty()) {
            DepNode n = newNode(c, null, depth, parent, excl, pre, preScope, mScope, mOptional, range, relocations, line, g);
            n.problems.addAll(rangeProblems);
            g.problems.addAll(rangeProblems);
            return;
        }
        for (String v : versions) {
            DepNode n;
            if ("system".equals(c.scopeOrDefault())) {
                newNode(c, v, depth, parent, excl, pre, preScope, mScope, mOptional, range, relocations, line, g);
                continue;
            }
            List<String> problems = new ArrayList<>();
            ModelBuilder.Model m = model(new Gav(c.groupId, c.artifactId, v), problems);
            if (m != null && m.pom.relocation != null && relocations.size() < 3) {
                var r = m.pom.relocation;
                Gav to = new Gav(r.groupId != null ? r.groupId : c.groupId, r.artifactId != null ? r.artifactId : c.artifactId,
                        r.version != null ? r.version : v);
                if (!to.equals(new Gav(c.groupId, c.artifactId, v))) {
                    String from = c.groupId + ":" + c.artifactId + ":" + v;
                    g.relocations.put(from, to.toString());
                    Dependency rc = c.copy();
                    rc.groupId = to.groupId;
                    rc.artifactId = to.artifactId;
                    rc.version = to.version;
                    List<String> rel = new ArrayList<>(relocations);
                    rel.add(from);
                    boolean sameGa = c.groupId.equals(to.groupId) && c.artifactId.equals(to.artifactId);
                    // The relocated artifact is selected again (exclusions apply to its new coordinates).
                    if (parent != null && excludedBy(parentExcl, rc.groupId, rc.artifactId)) return;
                    process(rc, parent, managed, g, rel, pre, sameGa, parentExcl, line);
                    return;
                }
            }
            n = newNode(c, v, depth, parent, excl, pre, preScope, mScope, mOptional, range, relocations, line, g);
            n.problems.addAll(problems);
            if (m == null) continue;
            // Cycle: the same artifact (any version) is already on the path; Maven reuses that node's children.
            DepNode cyc = null;
            for (DepNode a = parent; a != null; a = a.parent) {
                if (a.conflictId().equals(n.conflictId())) { cyc = a; break; }
            }
            if (cyc != null) {
                n.cycle = true;
                n.cycleTarget = cyc.cycleTarget != null ? cyc.cycleTarget : cyc;
                n.listId = n.cycleTarget.listId;
                continue;
            }
            String key = poolKey(n);
            DepNode pooled = pool.get(key);
            if (pooled != null) {
                n.listId = pooled.listId;
                copyChildren(pooled, n);
                continue;
            }
            n.listId = n;
            pool.put(key, n);
            expandChildren(n, m, managed, g);
        }
    }

    private DepNode newNode(Dependency c, String v, int depth, DepNode parent, Set<String> excl, String pre, String preScope,
                            boolean mScope, boolean mOptional, String range, List<String> relocations, int line, Graph g) {
        DepNode n = new DepNode(c.groupId, c.artifactId, v, c.type, c.classifier, c.scopeOrDefault(), c.isOptional(), depth, parent, excl, counter++);
        n.premanagedVersion = pre;
        n.premanagedScope = preScope;
        n.managedScope = mScope;
        n.managedOptional = mOptional;
        n.range = range;
        if (!relocations.isEmpty()) {
            n.relocatedFrom = relocations.get(0);
            n.relocatedTo = n.gav();
            g.relocatedNodes.add(n);
        }
        if (parent == null) {
            n.declaredLine = line;
            g.direct.add(n);
        } else parent.children.add(n);
        n.listId = n;
        return n;
    }

    private void expandChildren(DepNode node, ModelBuilder.Model m, Map<String, Dependency> managed, Graph g) {
        for (Dependency c0 : m.pom.dependencies) {
            String sc = c0.scopeOrDefault();
            if ("test".equals(sc) || "provided".equals(sc)) continue;
            if (c0.isOptional()) continue;
            if (excluded(node, c0.groupId, c0.artifactId)) continue;
            process(c0.copy(), node, managed, g, new ArrayList<>(), null, false, node.exclusions, 0);
        }
    }

    /** Re-creates a pooled child list under another parent (Maven shares the very same node objects). */
    private void copyChildren(DepNode from, DepNode to) {
        for (DepNode c : from.children) {
            DepNode k = new DepNode(c.groupId, c.artifactId, c.version, c.type, c.classifier, c.declaredScope, c.declaredOptional,
                    to.depth + 1, to, c.exclusions, counter++);
            k.premanagedVersion = c.premanagedVersion;
            k.premanagedScope = c.premanagedScope;
            k.managedScope = c.managedScope;
            k.managedOptional = c.managedOptional;
            k.range = c.range;
            k.relocatedFrom = c.relocatedFrom;
            k.relocatedTo = c.relocatedTo;
            k.cycle = c.cycle;
            k.cycleTarget = c.cycleTarget;
            k.listId = c.listId;
            k.problems.addAll(c.problems);
            k.copyOf = c.copyOf != null ? c.copyOf : c;
            to.children.add(k);
            if (counter > maxNodes) return;
            if (!c.cycle) copyChildren(c, k);
        }
    }

    private static boolean excludedBy(Set<String> exclusions, String g, String a) {
        for (String e : exclusions) {
            int i = e.indexOf(':');
            String eg = e.substring(0, i), ea = e.substring(i + 1);
            if (("*".equals(eg) || eg.equals(g)) && ("*".equals(ea) || ea.equals(a))) return true;
        }
        return false;
    }

    private static boolean excluded(DepNode node, String g, String a) {
        for (String e : node.exclusions) {
            int i = e.indexOf(':');
            String eg = e.substring(0, i), ea = e.substring(i + 1);
            if (("*".equals(eg) || eg.equals(g)) && ("*".equals(ea) || ea.equals(a))) return true;
        }
        return false;
    }

    private ModelBuilder.Model model(Gav gav, List<String> problems) {
        String k = gav.toString();
        ModelBuilder.Model m = modelCache.get(k);
        if (m != null) return m;
        if (missing.containsKey(k)) {
            problems.add(missing.get(k));
            return null;
        }
        try {
            m = models.buildRemote(gav);
            if (m == null) {
                String msg = "POM not found for " + gav;
                missing.put(k, msg);
                problems.add(msg);
                return null;
            }
            modelCache.put(k, m);
            return m;
        } catch (HttpException e) {
            String msg = "could not fetch POM for " + gav + ": " + e.getMessage();
            missing.put(k, msg);
            problems.add(msg);
            return null;
        }
    }

    private List<String> rangeVersions(String g, String a, String spec, List<String> problems) {
        List<String> out = new ArrayList<>();
        try {
            VersionRange r = VersionRange.parse(spec);
            Metadata md = models.repos().metadata(g, a);
            if (md == null) {
                problems.add("no versions found for " + g + ":" + a + " to satisfy " + spec);
                return out;
            }
            for (String v : md.sortedVersions()) if (!MavenVersion.of(v).isSnapshot() && r.contains(v)) out.add(v);
            if (out.isEmpty()) problems.add("no version of " + g + ":" + a + " matches " + spec);
        } catch (IllegalArgumentException e) {
            problems.add("invalid version range " + spec + " for " + g + ":" + a);
        } catch (HttpException e) {
            problems.add("could not list versions of " + g + ":" + a + ": " + e.getMessage());
        }
        return out;
    }

    /** Warms the POM cache level by level in parallel, using an approximation of the real walk. */
    private void prefetch(List<Dependency> direct, Map<String, Dependency> managed) {
        Http http = models.repos().http();
        Set<String> seen = new HashSet<>();
        List<Gav> level = new ArrayList<>();
        for (Dependency d : direct) {
            if (d.version == null || d.version.startsWith("[") || d.version.startsWith("(")) continue;
            Gav gv = new Gav(d.groupId, d.artifactId, d.version);
            if (seen.add(gv.toString())) level.add(gv);
        }
        int rounds = 0;
        while (!level.isEmpty() && rounds++ < 40 && seen.size() < 20_000) {
            List<ModelBuilder.Model> ms = http.parallelOrNull(level, gv -> {
                ModelBuilder.Model m = models.buildRemote(gv);
                if (m != null) modelCache.put(gv.toString(), m);
                return m;
            });
            List<Gav> next = new ArrayList<>();
            for (ModelBuilder.Model m : ms) {
                if (m == null) continue;
                for (Dependency c : m.pom.dependencies) {
                    String sc = c.scopeOrDefault();
                    if ("test".equals(sc) || "provided".equals(sc) || "system".equals(sc) || c.isOptional()) continue;
                    String v = c.version;
                    Dependency mg = managed.get(mgmtKey(c.groupId, c.artifactId, c.type, c.classifier));
                    if (mg != null && mg.version != null) v = mg.version;
                    if (v == null || v.startsWith("[") || v.startsWith("(") || v.contains("${")) continue;
                    Gav gv = new Gav(c.groupId, c.artifactId, v);
                    if (seen.add(gv.toString())) next.add(gv);
                }
            }
            level = next;
        }
    }

    // ------------------------------------------------------------------------------------------------
    // Conflict mediation (port of maven-resolver's ConflictResolver with Nearest/JavaScope/SimpleOptionality)

    // ------------------------------------------------------------------------------------------------
    // Maven node identity. Maven's collector shares one child list per (artifact, exclusions) and a cycle
    // node shares its ancestor's list, so several of our tree nodes can stand for one Maven node object.
    // A node object is identified by the list that holds it plus its index in that list.

    private Map<DepNode, Integer> listNumbers;

    private String objKey(DepNode n) {
        if (n.parent == null) return "r#" + n.indexInParent;
        Integer ln = listNumbers.computeIfAbsent(n.parent.listId, k -> listNumbers.size() + 1);
        return ln + "#" + n.indexInParent;
    }

    private static void indexTree(List<DepNode> nodes) {
        for (int i = 0; i < nodes.size(); i++) {
            DepNode n = nodes.get(i);
            n.indexInParent = i;
            indexTree(n.children);
        }
    }

    /** One conflict item (ConflictResolver.ConflictItem). */
    private static final class Item {
        final DepNode node;
        final DepNode parentList; // null for direct dependencies
        int depth;
        final Set<String> scopes = new LinkedHashSet<>();
        int optionalities; // 1 = seen non-optional, 2 = seen optional

        Item(DepNode node, DepNode parentList) { this.node = node; this.parentList = parentList; }
    }

    /** ConflictResolver.NodeInfo: what has been derived for one child list during one gathering. */
    private static final class NodeInfo {
        int minDepth;
        final Set<String> scopes = new LinkedHashSet<>();
        int optionalities;
        final List<Item> children = new ArrayList<>();

        NodeInfo(int depth, String scope, boolean optional) {
            minDepth = depth;
            scopes.add(scope);
            optionalities = optional ? 2 : 1;
        }

        int update(int depth, String scope, boolean optional) {
            if (depth < minDepth) minDepth = depth;
            int changes = scopes.add(scope) ? 1 : 0;
            int bit = optional ? 2 : 1;
            if ((optionalities & bit) == 0) {
                optionalities |= bit;
                changes |= 2;
            }
            return changes;
        }
    }

    /** ConflictResolver.State for one conflict id. */
    private final class State {
        final String current;
        final Set<String> potential;
        final Map<String, String> winnerKey;       // cid -> objKey of the winner
        final Map<String, String> resolvedScope;   // objKey -> scope
        final Map<String, Boolean> resolvedOptional;
        final List<Item> items = new ArrayList<>();
        final Map<DepNode, NodeInfo> infos = new HashMap<>();
        final Set<DepNode> stack = new HashSet<>();
        final List<DepNode> parentNodes = new ArrayList<>();
        final List<String> parentScopes = new ArrayList<>();
        final List<Boolean> parentOptionals = new ArrayList<>();
        final List<NodeInfo> parentInfos = new ArrayList<>();

        State(String current, Set<String> potential, Map<String, String> winnerKey, Map<String, String> resolvedScope,
              Map<String, Boolean> resolvedOptional) {
            this.current = current;
            this.potential = potential;
            this.winnerKey = winnerKey;
            this.resolvedScope = resolvedScope;
            this.resolvedOptional = resolvedOptional;
            // The project node: no dependency, its list is the list of direct dependencies (minDepth 0).
            NodeInfo rootInfo = new NodeInfo(0, "", false);
            infos.put(ROOT_LIST, rootInfo);
            parentInfos.add(rootInfo);
            parentNodes.add(null);
            parentScopes.add("");
            parentOptionals.add(false);
        }

        boolean resolved(String cid) { return winnerKey.containsKey(cid); }

        String scopeOf(DepNode n) {
            String k = objKey(n);
            String s = resolvedScope.get(k);
            return s != null ? s : n.declaredScope;
        }

        boolean optionalOf(DepNode n) {
            Boolean o = resolvedOptional.get(objKey(n));
            return o != null ? o : n.declaredOptional;
        }

        String deriveScope(DepNode n, String cid) {
            if (n.managedScope || (cid != null && resolved(cid))) return scopeOf(n);
            int depth = parentNodes.size();
            String parentScope = depth > 0 ? parentScopes.get(depth - 1) : null;
            return derive(parentScope, scopeOf(n));
        }

        boolean deriveOptional(DepNode n, String cid) {
            boolean optional = optionalOf(n);
            if (optional || n.managedOptional || (cid != null && resolved(cid))) return optional;
            int depth = parentNodes.size();
            return depth > 1 && parentOptionals.get(depth - 1);
        }

        boolean loser(DepNode n, String cid) {
            String w = winnerKey.get(cid);
            return w != null && !w.equals(objKey(n));
        }

        boolean push(DepNode n, String cid) {
            if (!potential.contains(cid)) return false;
            DepNode list = n.listId;
            if (!stack.add(list)) return false;
            int depth = parentNodes.size();
            String scope = deriveScope(n, cid);
            boolean optional = deriveOptional(n, cid);
            NodeInfo info = infos.get(list);
            if (info == null) {
                info = new NodeInfo(depth, scope, optional);
                infos.put(list, info);
                parentInfos.add(info);
                parentNodes.add(n);
                parentScopes.add(scope);
                parentOptionals.add(optional);
                return true;
            }
            int changes = info.update(depth, scope, optional);
            if (changes == 0) {
                stack.remove(list);
                return false;
            }
            parentInfos.add(null);
            parentNodes.add(n);
            parentScopes.add(scope);
            parentOptionals.add(optional);
            if ((changes & 1) != 0) for (int i = info.children.size() - 1; i >= 0; i--) {
                Item it = info.children.get(i);
                it.scopes.add(deriveScope(it.node, null));
            }
            if ((changes & 2) != 0) for (int i = info.children.size() - 1; i >= 0; i--) {
                Item it = info.children.get(i);
                it.optionalities |= deriveOptional(it.node, null) ? 2 : 1;
            }
            return true;
        }

        void pop() {
            int last = parentInfos.size() - 1;
            parentInfos.remove(last);
            DepNode n = parentNodes.remove(last);
            parentScopes.remove(last);
            parentOptionals.remove(last);
            if (n != null) stack.remove(n.listId);
        }

        void add(DepNode n) {
            NodeInfo info = parentInfos.get(parentInfos.size() - 1);
            if (info == null) return; // revisiting a list: its items already exist
            DepNode parent = parentNodes.get(parentNodes.size() - 1);
            Item it = new Item(n, parent == null ? ROOT_LIST : parent.listId);
            it.scopes.add(deriveScope(n, null));
            it.optionalities = deriveOptional(n, null) ? 2 : 1;
            info.children.add(it);
            items.add(it);
        }

        void finish() {
            for (Item it : items) {
                NodeInfo info = infos.get(it.parentList);
                it.depth = info == null ? it.node.depth : info.minDepth + 1;
            }
        }

        /** ConflictResolver.gatherConflictItems; returns false for a leftover loser (removed by Maven). */
        boolean gather(DepNode n) {
            String cid = n.conflictId();
            if (current.equals(cid)) {
                add(n);
            } else if (loser(n, cid)) {
                return false;
            } else if (push(n, cid)) {
                for (DepNode c : n.kids()) gather(c);
                pop();
            }
            return true;
        }
    }

    private static final DepNode ROOT_LIST = new DepNode("", "", null, "jar", null, "", false, 0, null, Set.of(), -1);

    private void mediate(Graph g) {
        listNumbers = new HashMap<>();
        indexTree(g.direct);
        List<DepNode> all = new ArrayList<>();
        walkAll(g.direct, all);
        Map<String, Set<String>> cyclicPredecessors = new HashMap<>();
        List<String> order = topo(g.direct, cyclicPredecessors);
        if (System.getProperty("sm.debug.topo") != null) System.err.println("topo: " + order);

        Set<String> potential = new HashSet<>();
        Map<String, String> winnerKey = new HashMap<>();
        Map<String, String> resolvedScope = new HashMap<>();
        Map<String, Boolean> resolvedOptional = new HashMap<>();
        Map<String, Item> winners = new HashMap<>();
        for (String cid : order) {
            Set<String> pred = cyclicPredecessors.get(cid);
            if (pred != null) potential.addAll(pred);
            State st = new State(cid, potential, winnerKey, resolvedScope, resolvedOptional);
            for (DepNode d : g.direct) st.gather(d);
            st.finish();
            potential.add(cid);
            if (st.items.isEmpty()) {
                // Nothing reachable yet: Maven marks the id resolved without a winner and never removes its nodes.
                winnerKey.put(cid, null);
                continue;
            }
            Item win = selectVersion(st.items, g);
            DepNode w = win.node;
            // Scope (JavaScopeSelector).
            String scope;
            if ("system".equals(st.scopeOf(w))) scope = "system";
            else {
                scope = null;
                Set<String> scopes = new LinkedHashSet<>();
                for (Item it : st.items) {
                    if (it.depth <= 1) { scope = st.scopeOf(it.node); break; }
                    scopes.addAll(it.scopes);
                }
                if (scope == null) scope = chooseScope(scopes);
            }
            // Optionality (SimpleOptionalitySelector).
            boolean optional = true;
            for (Item it : st.items) {
                if (it.depth <= 1) { optional = st.optionalOf(it.node); break; }
                if ((it.optionalities & 1) != 0) optional = false;
            }
            String wk = objKey(w);
            winnerKey.put(cid, wk);
            resolvedScope.put(wk, scope);
            resolvedOptional.put(wk, optional);
            winners.put(cid, win);
            List<DepNode> nodes = new ArrayList<>();
            Set<String> versions = new LinkedHashSet<>();
            for (Item it : st.items) {
                // Sibling candidates of one version range are not a conflict, just the range's choices.
                if (it.node != w && it.node.range != null && it.parentList == win.parentList && it.node.range.equals(w.range)) continue;
                nodes.add(it.node);
                if (it.node.version != null) versions.add(MavenVersion.of(it.node.version).canonical());
            }
            if (versions.size() > 1) g.conflicts.add(new Graph.Conflict(cid, w, nodes));
            g.selectedByCid.put(cid, w);
        }
        // Project the decisions onto our tree: walk from the roots through winners.
        for (DepNode n : all) {
            String cid = n.conflictId();
            String wk = winnerKey.get(cid);
            Item win = winners.get(cid);
            if (wk == null && winnerKey.containsKey(cid)) {
                // Resolved without a winner: the node stays with its own scope and optionality.
                n.selected = n.version != null;
            } else if (wk != null && wk.equals(objKey(n))) {
                n.selected = true;
                n.scope = resolvedScope.get(wk);
                n.optional = resolvedOptional.get(wk);
            } else if (win != null) {
                n.winner = win.node;
                n.omitted = n.cycle && n.version != null && n.version.equals(win.node.version) ? "cycle"
                        : MavenVersion.compare(n.version == null ? "" : n.version, win.node.version == null ? "" : win.node.version) == 0 ? "duplicate" : "conflict";
            }
        }
        markReachable(g.direct, all);
        for (DepNode n : all) if (!n.selected && n.omitted == null) n.omitted = "unreachable";
    }

    /**
     * A selected node is only kept when it can be reached from the project through selected nodes, following
     * Maven's graph (a cycle node leads into the children of the node it repeats).
     */
    private static void markReachable(List<DepNode> roots, List<DepNode> all) {
        Set<DepNode> reached = java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<>());
        java.util.ArrayDeque<DepNode> q = new java.util.ArrayDeque<>();
        for (DepNode d : roots) if (d.selected && reached.add(d)) q.add(d);
        while (!q.isEmpty()) {
            DepNode n = q.poll();
            for (DepNode c : n.kids()) if (c.selected && reached.add(c)) q.add(c);
        }
        for (DepNode n : all) {
            if (n.selected && !reached.contains(n)) {
                n.selected = false;
                n.omitted = "unreachable";
            }
        }
    }

    /**
     * maven-resolver's NearestVersionSelector: version ranges are hard constraints every candidate must
     * satisfy (with backtracking when a later range rules out the current winner); among acceptable
     * candidates the nearest wins, siblings prefer the higher version, and the first one found breaks ties.
     */
    private static Item selectVersion(List<Item> items, Graph g) {
        List<VersionRange> constraints = new ArrayList<>();
        Set<String> seenSpecs = new HashSet<>();
        List<Item> candidates = new ArrayList<>();
        Item winner = null;
        for (Item it : items) {
            DepNode n = it.node;
            if (n.version == null) continue;
            boolean backtrack = false;
            if (n.range != null && seenSpecs.add(n.range)) {
                try {
                    VersionRange vr = VersionRange.parse(n.range);
                    constraints.add(vr);
                    if (winner != null && !vr.contains(winner.node.version)) backtrack = true;
                } catch (IllegalArgumentException ignored) {}
            }
            if (acceptable(constraints, n.version)) {
                candidates.add(it);
                if (backtrack) winner = backtrack(candidates, constraints);
                else if (winner == null || nearer(it, winner)) winner = it;
            } else if (backtrack) {
                winner = backtrack(candidates, constraints);
            }
        }
        if (winner == null) {
            for (Item it : items) if (it.node.version != null && (winner == null || it.depth < winner.depth)) winner = it;
            if (winner == null) winner = items.get(0);
            g.problems.add("version conflict cannot be solved for " + winner.node.ga() + ": ranges " + seenSpecs + " exclude every candidate");
        }
        return winner;
    }

    private static Item backtrack(List<Item> candidates, List<VersionRange> constraints) {
        Item winner = null;
        for (java.util.Iterator<Item> i = candidates.iterator(); i.hasNext(); ) {
            Item c = i.next();
            if (!acceptable(constraints, c.node.version)) i.remove();
            else if (winner == null || nearer(c, winner)) winner = c;
        }
        return winner;
    }

    private static boolean acceptable(List<VersionRange> constraints, String version) {
        for (VersionRange r : constraints) if (!r.contains(version)) return false;
        return true;
    }

    private static boolean nearer(Item a, Item b) {
        if (a.parentList == b.parentList) return MavenVersion.compare(a.node.version, b.node.version) > 0;
        return a.depth < b.depth;
    }

    private static void walkAll(List<DepNode> nodes, List<DepNode> out) {
        for (DepNode n : nodes) {
            out.add(n);
            walkAll(n.children, out);
        }
    }

    /**
     * Orders conflict ids parents-first, porting maven-resolver's ConflictMarker numbering and
     * ConflictIdSorter over Maven's node objects (shared child lists visited once): Kahn's algorithm with
     * a FIFO queue, children in HashSet order of their numbers, cycles broken at the id with the smallest
     * depth then the smallest in-degree. Also reports the ids of each detected cycle.
     */
    private List<String> topo(List<DepNode> roots, Map<String, Set<String>> cyclicPredecessors) {
        Map<String, Integer> num = new LinkedHashMap<>();
        numberIds(roots, num, new HashSet<>());
        List<String> names = new ArrayList<>(num.keySet());
        int size = names.size();
        int[] minDepth = new int[size];
        int[] indeg = new int[size];
        List<Set<Integer>> children = new ArrayList<>();
        for (int i = 0; i < size; i++) children.add(new HashSet<>());
        boolean[] created = new boolean[size];
        List<Integer> discovery = new ArrayList<>();
        buildDag(roots, -1, 0, num, minDepth, indeg, children, created, new HashSet<>(), discovery);
        List<String> out = new ArrayList<>();
        java.util.ArrayDeque<Integer> q = new java.util.ArrayDeque<>();
        for (int id : discovery) if (indeg[id] <= 0) q.add(id);
        int sorted = drain(q, out, names, children, indeg, 0);
        boolean cycle = sorted < size;
        while (sorted < size) {
            int nearest = -1;
            for (int id : discovery) {
                if (indeg[id] <= 0) continue;
                if (nearest < 0 || minDepth[id] < minDepth[nearest] || (minDepth[id] == minDepth[nearest] && indeg[id] < indeg[nearest])) nearest = id;
            }
            if (nearest < 0) break;
            indeg[nearest] = 0;
            q.add(nearest);
            sorted = drain(q, out, names, children, indeg, sorted);
        }
        if (cycle) {
            Map<Integer, Integer> stack = new LinkedHashMap<>();
            Set<Integer> seen = new HashSet<>();
            Set<Set<Integer>> cycles = new HashSet<>();
            for (int id : discovery) findCycles(id, children, seen, stack, cycles);
            for (Set<Integer> c : cycles) {
                for (int id : c) {
                    Set<String> pred = cyclicPredecessors.computeIfAbsent(names.get(id), k -> new HashSet<>());
                    for (int o : c) pred.add(names.get(o));
                }
            }
        }
        return out;
    }

    /** ConflictMarker: number conflict ids in depth-first discovery order over node objects. */
    private void numberIds(List<DepNode> nodes, Map<String, Integer> num, Set<String> visited) {
        for (DepNode n : nodes) {
            if (!visited.add(objKey(n))) continue;
            num.putIfAbsent(n.conflictId(), num.size());
            numberIds(n.kids(), num, visited);
        }
    }

    private void buildDag(List<DepNode> kids, int parentId, int depth, Map<String, Integer> num, int[] minDepth, int[] indeg,
                          List<Set<Integer>> children, boolean[] created, Set<String> visited, List<Integer> discovery) {
        int d = depth + 1;
        for (DepNode c : kids) {
            int cid = num.get(c.conflictId());
            if (!created[cid]) {
                created[cid] = true;
                minDepth[cid] = d;
                discovery.add(cid);
            } else pullup(cid, d, minDepth, children);
            if (parentId >= 0 && children.get(parentId).add(cid)) indeg[cid]++;
            if (visited.add(objKey(c))) buildDag(c.kids(), cid, d, num, minDepth, indeg, children, created, visited, discovery);
        }
    }

    private static int drain(java.util.ArrayDeque<Integer> q, List<String> out, List<String> names, List<Set<Integer>> children,
                             int[] indeg, int sorted) {
        while (!q.isEmpty()) {
            int k = q.poll();
            out.add(names.get(k));
            sorted++;
            for (int c : children.get(k)) {
                indeg[c]--;
                if (indeg[c] == 0) q.add(c);
            }
        }
        return sorted;
    }

    private static void findCycles(int id, List<Set<Integer>> children, Set<Integer> seen, Map<Integer, Integer> stack, Set<Set<Integer>> cycles) {
        Integer depth = stack.put(id, stack.size());
        if (depth != null) {
            stack.put(id, depth);
            Set<Integer> c = new HashSet<>();
            for (Map.Entry<Integer, Integer> e : stack.entrySet()) if (e.getValue() >= depth) c.add(e.getKey());
            cycles.add(c);
        } else {
            if (seen.add(id)) for (int ch : children.get(id)) findCycles(ch, children, seen, stack, cycles);
            stack.remove(id);
        }
    }

    /** Identity of a node's child list in Maven's collector: artifact plus accumulated exclusions. */
    private static String poolKey(DepNode n) {
        List<String> ex = new ArrayList<>(n.exclusions);
        Collections.sort(ex);
        return n.groupId + ":" + n.artifactId + ":" + n.version + ":" + n.type + ":" + n.classifier + "|" + ex;
    }

    private static void pullup(int id, int depth, int[] minDepth, List<Set<Integer>> children) {
        if (depth < minDepth[id]) {
            minDepth[id] = depth;
            for (int c : children.get(id)) pullup(c, depth + 1, minDepth, children);
        }
    }

    /** Maven's JavaScopeDeriver. */
    static String derive(String parentScope, String childScope) {
        if ("system".equals(childScope) || "test".equals(childScope)) return childScope;
        if (parentScope == null || parentScope.isEmpty() || "compile".equals(parentScope)) return childScope;
        if ("test".equals(parentScope) || "runtime".equals(parentScope)) return parentScope;
        if ("system".equals(parentScope) || "provided".equals(parentScope)) return "provided";
        return "runtime";
    }

    /** Maven's JavaScopeSelector for non-direct conflicts: widest wins. */
    static String chooseScope(Set<String> scopes) {
        Set<String> s = new LinkedHashSet<>(scopes);
        if (s.size() > 1) s.remove("system");
        if (s.size() == 1) return s.iterator().next();
        if (s.contains("compile")) return "compile";
        if (s.contains("runtime")) return "runtime";
        if (s.contains("provided")) return "provided";
        if (s.contains("test")) return "test";
        return s.isEmpty() ? "compile" : s.iterator().next();
    }
}
