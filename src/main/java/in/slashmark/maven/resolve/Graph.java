package in.slashmark.maven.resolve;

import in.slashmark.maven.model.MavenVersion;
import in.slashmark.maven.model.ModelBuilder;
import in.slashmark.maven.util.Json;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

/** Result of a resolution: the collected tree plus mediation decisions. */
public final class Graph {
    public final ModelBuilder.Model root;
    public final List<DepNode> direct = new ArrayList<>();
    public final List<String> problems = new ArrayList<>();
    public final Map<String, String> relocations = new LinkedHashMap<>();
    public final List<DepNode> relocatedNodes = new ArrayList<>();
    public final Map<String, DepNode> selectedByCid = new LinkedHashMap<>();
    public final List<Conflict> conflicts = new ArrayList<>();
    public boolean truncated;

    Graph(ModelBuilder.Model root) { this.root = root; }

    /** A groupId:artifactId requested in more than one version. */
    public static final class Conflict {
        public final String conflictId;
        public final DepNode winner;
        public final List<DepNode> items;

        Conflict(String cid, DepNode winner, List<DepNode> items) {
            this.conflictId = cid;
            this.winner = winner;
            this.items = items;
        }

        /** Highest version requested anywhere. */
        public String highest() {
            String h = winner.version;
            for (DepNode n : items) if (n.version != null && MavenVersion.compare(n.version, h) > 0) h = n.version;
            return h;
        }

        /** True when mediation picked a version older than another requested one (a silent downgrade). */
        public boolean downgrade() { return MavenVersion.compare(highest(), winner.version) > 0; }

        /** True when the downgrade crosses a major version. */
        public boolean majorGap() { return MavenVersion.of(highest()).major() != MavenVersion.of(winner.version).major(); }

        public Object toJson() {
            List<Object> reqs = new ArrayList<>();
            for (DepNode n : items) {
                reqs.add(Json.obj("version", n.version, "path", n.pathString(), "depth", n.depth, "selected", n == winner,
                        "premanaged", n.premanagedVersion));
            }
            return Json.obj("artifact", winner.ga(), "selected", winner.version, "highestRequested", highest(),
                    "downgrade", downgrade(), "majorGap", majorGap(), "requests", reqs);
        }
    }

    /** Selected (winning) nodes in breadth-first order, each artifact once. */
    public List<DepNode> resolved() {
        List<DepNode> out = new ArrayList<>();
        Deque<DepNode> q = new ArrayDeque<>(direct);
        java.util.Set<DepNode> seen = new java.util.HashSet<>();
        java.util.Set<String> cids = new java.util.HashSet<>();
        while (!q.isEmpty()) {
            DepNode n = q.poll();
            if (!n.selected || !seen.add(n)) continue;
            if (cids.add(n.conflictId())) out.add(n);
            q.addAll(n.kids());
        }
        return out;
    }

    /** Selected nodes in depth-first order (each artifact once, first parent wins), like mvn dependency:list. */
    public List<DepNode> resolvedDepthFirst() {
        List<DepNode> out = new ArrayList<>();
        dfs(direct, out, new java.util.HashSet<>(), new java.util.HashSet<>());
        return out;
    }

    private static void dfs(List<DepNode> nodes, List<DepNode> out, java.util.Set<DepNode> onPath, java.util.Set<String> cids) {
        for (DepNode n : nodes) {
            if (!n.selected || !onPath.add(n)) continue;
            if (cids.add(n.conflictId())) out.add(n);
            dfs(n.kids(), out, onPath, cids);
            onPath.remove(n);
        }
    }

    /** Selected nodes whose scope is in the given set (e.g. compile+runtime for what ships). */
    public List<DepNode> resolved(Set<String> scopes) {
        List<DepNode> out = new ArrayList<>();
        for (DepNode n : resolved()) if (scopes == null || scopes.contains(n.scope)) out.add(n);
        return out;
    }

    /** Every occurrence (selected or not) matching the predicate, in depth-first order. */
    public List<DepNode> find(Predicate<DepNode> p) {
        List<DepNode> out = new ArrayList<>();
        walk(direct, p, out);
        return out;
    }

    private static void walk(List<DepNode> nodes, Predicate<DepNode> p, List<DepNode> out) {
        for (DepNode n : nodes) {
            if (p.test(n)) out.add(n);
            walk(n.children, p, out);
        }
    }

    public DepNode selected(String groupId, String artifactId) {
        for (DepNode n : resolved()) if (n.groupId.equals(groupId) && n.artifactId.equals(artifactId)) return n;
        return null;
    }

    /** Collected problems from nodes plus graph-level problems, de-duplicated. */
    public List<String> allProblems() {
        java.util.LinkedHashSet<String> s = new java.util.LinkedHashSet<>(root.problems);
        s.addAll(problems);
        for (DepNode n : find(x -> !x.problems.isEmpty())) s.addAll(n.problems);
        return new ArrayList<>(s);
    }

    // ---------------------------------------------------------------- rendering

    /**
     * Text tree like "mvn dependency:tree". verbose=true also shows omitted nodes with the reason,
     * as "mvn dependency:tree -Dverbose" does.
     */
    public String tree(boolean verbose, boolean ascii) {
        StringBuilder b = new StringBuilder();
        b.append(root.gav()).append(root.pom.packaging == null ? "" : ":" + root.pom.packaging).append('\n');
        render(direct, "", verbose, ascii, b);
        return b.toString();
    }

    private void render(List<DepNode> nodes, String indent, boolean verbose, boolean ascii, StringBuilder b) {
        List<DepNode> shown = new ArrayList<>();
        for (DepNode n : nodes) if (n.selected || (verbose && n.omitted != null && !"unreachable".equals(n.omitted))) shown.add(n);
        for (int i = 0; i < shown.size(); i++) {
            DepNode n = shown.get(i);
            boolean last = i == shown.size() - 1;
            String branch = ascii ? (last ? "\\- " : "+- ") : (last ? "└─ " : "├─ ");
            b.append(indent).append(branch).append(label(n));
            b.append('\n');
            if (n.selected && n.cycleTarget == null) render(n.children, indent + (last ? "   " : (ascii ? "|  " : "│  ")), verbose, ascii, b);
        }
    }

    public static String label(DepNode n) {
        StringBuilder b = new StringBuilder();
        if (!n.selected) b.append('(');
        b.append(n.groupId).append(':').append(n.artifactId).append(':');
        if (!"jar".equals(n.type)) b.append(n.type).append(':');
        if (n.classifier != null) b.append(n.classifier).append(':');
        b.append(n.version).append(':').append(n.scope);
        if (n.optional) b.append(" (optional)");
        List<String> notes = new ArrayList<>();
        if (n.premanagedVersion != null) notes.add("version managed from " + n.premanagedVersion);
        if (n.premanagedScope != null) notes.add("scope managed from " + n.premanagedScope);
        if (n.range != null) notes.add("range " + n.range);
        if (n.relocatedFrom != null) notes.add("relocated from " + n.relocatedFrom);
        if (!n.selected && n.omitted != null) {
            if ("conflict".equals(n.omitted)) notes.add("omitted for conflict with " + n.winner.version);
            else if ("duplicate".equals(n.omitted)) notes.add("omitted for duplicate");
            else if ("cycle".equals(n.omitted)) notes.add("omitted for cycle");
        }
        if (!notes.isEmpty()) b.append(" - ").append(String.join("; ", notes));
        if (!n.selected) b.append(')');
        return b.toString();
    }

    public Object nodeJson(DepNode n, boolean withChildren) {
        Map<String, Object> m = Json.obj("groupId", n.groupId, "artifactId", n.artifactId, "version", n.version,
                "type", "jar".equals(n.type) ? null : n.type, "classifier", n.classifier, "scope", n.scope,
                "optional", n.optional ? Boolean.TRUE : null, "depth", n.depth,
                "managedFrom", n.premanagedVersion, "range", n.range, "relocatedFrom", n.relocatedFrom,
                "omitted", n.selected ? null : n.omitted);
        if (withChildren) {
            List<Object> kids = new ArrayList<>();
            if (n.selected) for (DepNode c : n.children) if (c.selected) kids.add(nodeJson(c, true));
            if (!kids.isEmpty()) m.put("dependencies", kids);
        }
        return m;
    }

    public Object toJson() {
        List<Object> kids = new ArrayList<>();
        for (DepNode d : direct) if (d.selected) kids.add(nodeJson(d, true));
        return Json.obj("project", root.gav().toString(), "dependencies", kids);
    }
}
