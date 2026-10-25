package in.slashmark.maven.model;

import java.util.Objects;

/** Maven coordinates groupId:artifactId[:version]. Also parses g:a:type:classifier:version forms. */
public final class Gav implements Comparable<Gav> {
    public final String groupId;
    public final String artifactId;
    public final String version;

    public Gav(String groupId, String artifactId, String version) {
        this.groupId = groupId;
        this.artifactId = artifactId;
        this.version = version == null || version.isEmpty() ? null : version;
    }

    /**
     * Accepts g:a, g:a:v, g:a:packaging:v and g:a:packaging:classifier:v (the last element is the
     * version when there are 3+ parts). Also accepts "g:a@v" for convenience.
     */
    public static Gav parse(String s) {
        if (s == null) throw new IllegalArgumentException("missing coordinates");
        String t = s.trim();
        String ver = null;
        int at = t.indexOf('@');
        if (at > 0) {
            ver = t.substring(at + 1);
            t = t.substring(0, at);
        }
        String[] p = t.split(":");
        if (p.length < 2 || p[0].isEmpty() || p[1].isEmpty()) {
            throw new IllegalArgumentException("expected groupId:artifactId[:version], got '" + s + "'");
        }
        if (ver == null && p.length >= 3) ver = p[p.length - 1];
        for (String part : new String[] {p[0], p[1]}) {
            if (!part.matches("[A-Za-z0-9_.\\-]+")) throw new IllegalArgumentException("invalid coordinate part '" + part + "' in '" + s + "'");
        }
        return new Gav(p[0], p[1], ver);
    }

    public static boolean looksLikeGav(String s) {
        return s != null && s.matches("[A-Za-z0-9_.\\-]+:[A-Za-z0-9_.\\-]+(?::[^:\\s]+){0,3}(?:@\\S+)?");
    }

    /** groupId:artifactId, the identity used for conflict mediation and advisories. */
    public String ga() { return groupId + ":" + artifactId; }

    public Gav withVersion(String v) { return new Gav(groupId, artifactId, v); }

    /** Repository path of the artifact folder: org/foo/bar/1.0 */
    public String path() {
        String base = groupId.replace('.', '/') + "/" + artifactId;
        return version == null ? base : base + "/" + version;
    }

    /** Repository path of a file in this version: org/foo/bar/1.0/bar-1.0[-classifier].ext */
    public String file(String classifier, String ext) {
        return path() + "/" + artifactId + "-" + version + (classifier == null || classifier.isEmpty() ? "" : "-" + classifier) + "." + ext;
    }

    @Override
    public String toString() { return version == null ? ga() : ga() + ":" + version; }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof Gav)) return false;
        Gav g = (Gav) o;
        return groupId.equals(g.groupId) && artifactId.equals(g.artifactId) && Objects.equals(version, g.version);
    }

    @Override
    public int hashCode() { return Objects.hash(groupId, artifactId, version); }

    @Override
    public int compareTo(Gav o) {
        int c = groupId.compareTo(o.groupId);
        if (c != 0) return c;
        c = artifactId.compareTo(o.artifactId);
        if (c != 0) return c;
        if (version == null || o.version == null) return version == null ? (o.version == null ? 0 : -1) : 1;
        return MavenVersion.of(version).compareTo(MavenVersion.of(o.version));
    }
}
