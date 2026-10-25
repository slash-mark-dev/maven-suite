package in.slashmark.maven.model;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** A &lt;dependency&gt; element (raw or interpolated). Mutable while a model is being built. */
public final class Dependency {
    public String groupId;
    public String artifactId;
    public String version;
    public String type = "jar";
    public String classifier;
    public String scope;
    public String optional;
    public String systemPath;
    public List<String[]> exclusions = new ArrayList<>();
    /** 1-based line in the declaring pom.xml, when known. */
    public int line;

    public Dependency copy() {
        Dependency d = new Dependency();
        d.groupId = groupId;
        d.artifactId = artifactId;
        d.version = version;
        d.type = type;
        d.classifier = classifier;
        d.scope = scope;
        d.optional = optional;
        d.systemPath = systemPath;
        d.exclusions = new ArrayList<>();
        for (String[] e : exclusions) d.exclusions.add(new String[] {e[0], e[1]});
        d.line = line;
        return d;
    }

    /** Management key: groupId:artifactId:type[:classifier]. */
    public String key() {
        return groupId + ":" + artifactId + ":" + (type == null ? "jar" : type) + (classifier == null || classifier.isEmpty() ? "" : ":" + classifier);
    }

    public String ga() { return groupId + ":" + artifactId; }

    public String scopeOrDefault() { return scope == null || scope.isEmpty() ? "compile" : scope.toLowerCase(Locale.ROOT); }

    public boolean isOptional() { return "true".equalsIgnoreCase(optional == null ? "" : optional.trim()); }

    public boolean excludes(String g, String a) {
        for (String[] e : exclusions) {
            boolean gm = "*".equals(e[0]) || e[0].equals(g);
            boolean am = "*".equals(e[1]) || e[1].equals(a);
            if (gm && am) return true;
        }
        return false;
    }

    public Gav gav() { return new Gav(groupId, artifactId, version); }

    @Override
    public String toString() {
        return groupId + ":" + artifactId + (version == null ? "" : ":" + version)
                + (scope == null ? "" : " (" + scope + ")") + (isOptional() ? " optional" : "");
    }
}
