package in.slashmark.maven.resolve;

import in.slashmark.maven.model.Gav;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** One node of the collected ("dirty") dependency graph, before and after mediation. */
public final class DepNode {
    public String groupId, artifactId;
    public String version;
    public final String type, classifier;
    /** Scope as declared on this edge (after dependency management). */
    public final String declaredScope;
    /** Scope after Maven's scope derivation and selection (set during mediation). */
    public String scope;
    public boolean optional;
    /** Optional flag as declared on this edge. */
    public final boolean declaredOptional;
    /** Whether root dependency management set this node's scope / optionality. */
    public boolean managedScope, managedOptional;
    public final int depth;
    public final DepNode parent;
    public final List<DepNode> children = new ArrayList<>();
    /** Accumulated exclusions on the path (groupId:artifactId, may contain *). */
    final Set<String> exclusions;
    /** Version requested before dependency management replaced it (null when not managed). */
    public String premanagedVersion;
    public String premanagedScope;
    /** The raw version spec when it was a range, e.g. [1.0,2.0). */
    public String range;
    /** Set when this artifact was relocated: the coordinates that were requested. */
    public String relocatedFrom;
    /** Set when this artifact was relocated: where Maven actually took it from. */
    public Gav relocatedTo;
    /** Line of the declaring &lt;dependency&gt; in the project pom.xml (direct dependencies only). */
    public int declaredLine;
    /** Declaration order in a depth-first walk; used for Maven's "first declaration wins" tie-break. */
    final int order;
    /** True when the same groupId:artifactId already appears on the path. */
    public boolean cycle;
    /** For cycle nodes: the ancestor whose children Maven's collector reuses for this node. */
    public DepNode cycleTarget;
    /** Identity of this node's child list (Maven shares one list per artifact + exclusions). */
    DepNode listId;
    /** For nodes copied from a shared child list: the node in the first expansion. */
    DepNode copyOf;
    /** Position in the parent's child list. */
    int indexInParent;
    /** Problems specific to this node (missing POM, unresolvable range...). */
    public final List<String> problems = new ArrayList<>();

    // ---- mediation results
    /** True if this node is the selected one for its conflict id and reachable. */
    public boolean selected;
    /** For nodes that lost mediation: the node that won. */
    public DepNode winner;
    /** "conflict" (other version won), "duplicate" (same version elsewhere), "cycle", or null when selected. */
    public String omitted;

    /**
     * A selected depth-0 node standing for a published artifact that is itself being analysed
     * (graphs only contain its dependencies, so tools that check "the artifact and everything it pulls in" add this).
     */
    public static DepNode artifactRoot(String g, String a, String v, String type) {
        DepNode n = new DepNode(g, a, v, type, null, "compile", false, 0, null, new java.util.HashSet<>(), 0);
        n.selected = true;
        return n;
    }

    DepNode(String g, String a, String v, String type, String classifier, String scope, boolean optional,
            int depth, DepNode parent, Set<String> exclusions, int order) {
        this.groupId = g;
        this.artifactId = a;
        this.version = v;
        this.type = type == null ? "jar" : type;
        this.classifier = classifier == null || classifier.isEmpty() ? null : classifier;
        this.declaredScope = scope == null || scope.isEmpty() ? "compile" : scope;
        this.scope = this.declaredScope;
        this.optional = optional;
        this.declaredOptional = optional;
        this.depth = depth;
        this.parent = parent;
        this.exclusions = exclusions;
        this.order = order;
    }

    public String ga() { return groupId + ":" + artifactId; }

    /** Children as Maven sees them: a cycle node shares its ancestor's children. */
    public List<DepNode> kids() { return cycleTarget != null ? cycleTarget.children : children; }

    public Gav gav() { return new Gav(groupId, artifactId, version); }

    /** Maven's conflict key: groupId:artifactId:extension:classifier. */
    public String conflictId() {
        return groupId + ":" + artifactId + ":" + extension(type) + (classifier == null ? "" : ":" + classifier);
    }

    static String extension(String type) {
        if (type == null) return "jar";
        switch (type) {
            case "pom": return "pom";
            case "war": return "war";
            case "ear": return "ear";
            case "rar": return "rar";
            case "zip": return "zip";
            default: return "jar";
        }
    }

    public String classifierOrType() {
        if (classifier != null) return classifier;
        return "test-jar".equals(type) ? "tests" : null;
    }

    /** Path from the root's direct dependency down to this node: [direct, ..., this]. */
    public List<DepNode> path() {
        List<DepNode> p = new ArrayList<>();
        for (DepNode n = this; n != null; n = n.parent) p.add(0, n);
        return p;
    }

    public String pathString() {
        StringBuilder b = new StringBuilder();
        for (DepNode n : path()) {
            if (b.length() > 0) b.append(" -> ");
            b.append(n.ga()).append(':').append(n.version);
        }
        return b.toString();
    }

    public boolean isDirect() { return depth == 1; }

    @Override
    public String toString() { return ga() + ":" + version + " (" + scope + (optional ? ", optional" : "") + ")"; }
}
