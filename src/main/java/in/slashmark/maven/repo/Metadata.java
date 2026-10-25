package in.slashmark.maven.repo;

import in.slashmark.maven.model.MavenVersion;
import in.slashmark.maven.util.Xml;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.w3c.dom.Element;

/** maven-metadata.xml for an artifact (all versions) or for one SNAPSHOT version. */
public final class Metadata {
    public String groupId, artifactId;
    public String latest, release;
    public final Set<String> versions = new LinkedHashSet<>();
    /** yyyyMMddHHmmss, UTC. */
    public String lastUpdated;
    /** Snapshot builds: "classifier:extension" -> timestamped value, e.g. ":jar" -> 1.0-20240101.120000-3. */
    public final Map<String, String> snapshotValues = new LinkedHashMap<>();
    public String snapshotTimestamp;
    public int snapshotBuild;
    /** Which repositories contributed (repository id list). */
    public final List<String> sources = new ArrayList<>();

    public static Metadata parse(byte[] xml) {
        Element root = Xml.parse(xml);
        Metadata m = new Metadata();
        m.groupId = Xml.text(root, "groupId");
        m.artifactId = Xml.text(root, "artifactId");
        Element v = Xml.child(root, "versioning");
        if (v != null) {
            m.latest = Xml.text(v, "latest");
            m.release = Xml.text(v, "release");
            m.lastUpdated = Xml.text(v, "lastUpdated");
            for (Element e : Xml.children(Xml.child(v, "versions"), "version")) {
                String t = Xml.text(e);
                if (t != null) m.versions.add(t);
            }
            Element sn = Xml.child(v, "snapshot");
            if (sn != null) {
                m.snapshotTimestamp = Xml.text(sn, "timestamp");
                try { m.snapshotBuild = Integer.parseInt(Xml.text(sn, "buildNumber")); } catch (RuntimeException ignored) {}
            }
            for (Element s : Xml.children(Xml.child(v, "snapshotVersions"), "snapshotVersion")) {
                String c = Xml.text(s, "classifier");
                String ext = Xml.text(s, "extension");
                String val = Xml.text(s, "value");
                if (val != null) m.snapshotValues.put((c == null ? "" : c) + ":" + (ext == null ? "jar" : ext), val);
            }
        }
        return m;
    }

    /** Merges another repository's metadata into this one (union of versions, newest timestamps). */
    public void merge(Metadata o) {
        versions.addAll(o.versions);
        if (o.lastUpdated != null && (lastUpdated == null || o.lastUpdated.compareTo(lastUpdated) > 0)) lastUpdated = o.lastUpdated;
        if (o.release != null && (release == null || MavenVersion.compare(o.release, release) > 0)) release = o.release;
        if (o.latest != null && (latest == null || MavenVersion.compare(o.latest, latest) > 0)) latest = o.latest;
        sources.addAll(o.sources);
        if (groupId == null) groupId = o.groupId;
        if (artifactId == null) artifactId = o.artifactId;
    }

    /** Versions sorted ascending by Maven ordering. */
    public List<String> sortedVersions() {
        List<String> l = new ArrayList<>(versions);
        l.sort((a, b) -> MavenVersion.compare(a, b));
        return l;
    }

    /** Newest version, optionally only final releases (no snapshots/pre-releases). */
    public String newest(boolean stableOnly) {
        String best = null;
        for (String v : versions) {
            MavenVersion mv = MavenVersion.of(v);
            if (mv.isSnapshot()) continue;
            if (stableOnly && mv.isPreRelease()) continue;
            if (best == null || mv.compareTo(MavenVersion.of(best)) > 0) best = v;
        }
        if (best == null && stableOnly) return newest(false);
        return best;
    }

    public long lastUpdatedMillis() { return parseTimestamp(lastUpdated); }

    /** Parses yyyyMMddHHmmss (UTC) into epoch millis; 0 when absent/invalid. */
    public static long parseTimestamp(String ts) {
        if (ts == null || ts.length() < 14) return 0;
        try {
            return LocalDateTime.parse(ts.substring(0, 14), DateTimeFormatter.ofPattern("yyyyMMddHHmmss")).toInstant(ZoneOffset.UTC).toEpochMilli();
        } catch (RuntimeException e) {
            return 0;
        }
    }
}
