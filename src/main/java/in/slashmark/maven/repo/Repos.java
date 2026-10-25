package in.slashmark.maven.repo;

import in.slashmark.maven.model.Gav;
import in.slashmark.maven.model.Pom;
import in.slashmark.maven.util.Http;
import in.slashmark.maven.util.HttpException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Artifact access across the local repository (~/.m2), Maven Central and any repositories declared in
 * the project or settings.xml (with settings.xml mirrors and server credentials applied).
 */
public final class Repos {
    public static final class Remote {
        public final String id;
        public final String url;
        public final boolean releases, snapshots;
        /** Original repository ids this entry serves (more than one when a mirror covers several). */
        public final List<String> mirrorOf = new ArrayList<>();
        final Map<String, String> headers = new LinkedHashMap<>();
        public final boolean hasCredentials;

        Remote(String id, String url, boolean releases, boolean snapshots, Settings.Server server) {
            this.id = id;
            String u = url;
            while (u.endsWith("/")) u = u.substring(0, u.length() - 1);
            this.url = u;
            this.releases = releases;
            this.snapshots = snapshots;
            boolean creds = false;
            if (server != null) {
                if (server.username != null && server.password != null && !server.passwordEncrypted() && !server.password.contains("${")) {
                    String token = Base64.getEncoder().encodeToString((server.username + ":" + server.password).getBytes(StandardCharsets.UTF_8));
                    headers.put("Authorization", "Basic " + token);
                    creds = true;
                }
                for (Map.Entry<String, String> h : server.headers.entrySet()) {
                    if (h.getValue() != null && !h.getValue().contains("${")) {
                        headers.put(h.getKey(), h.getValue());
                        creds = true;
                    }
                }
            }
            this.hasCredentials = creds;
        }

        public Map<String, String> headers() { return headers; }

        @Override
        public String toString() { return id + " (" + url + ")"; }
    }

    private final Http http;
    private final Path localRepo;
    private final Settings settings;
    private final List<Remote> remotes = new ArrayList<>();
    private final Map<String, Metadata> metaCache = new ConcurrentHashMap<>();
    private final Map<String, byte[]> pomCache = new ConcurrentHashMap<>();
    private long metadataTtl = Http.DEFAULT_TTL;
    private boolean useLocal = true;

    public Repos(Http http, String centralUrl, Path localRepo, Settings settings) {
        this.http = http;
        this.localRepo = localRepo;
        this.settings = settings == null ? Settings.empty() : settings;
        add("central", centralUrl, true, false);
        for (Settings.ProfileRepo r : this.settings.activeRepositories()) add(r.id, r.url, r.releases, r.snapshots);
    }

    public Http http() { return http; }
    public Settings settings() { return settings; }
    public List<Remote> remotes() { return remotes; }
    public Path localRepo() { return localRepo; }

    /** Real-time tools shorten this; watch loops set it to zero so every cycle sees fresh metadata. */
    public void setMetadataTtl(long ttl) {
        metadataTtl = ttl;
        metaCache.clear();
    }

    public void setUseLocal(boolean v) { useLocal = v; }

    /** Adds a repository (mirrors from settings.xml are applied; duplicates are ignored). */
    public void add(String id, String url, boolean releases, boolean snapshots) {
        if (url == null || url.isBlank()) return;
        if (id == null) id = url;
        Settings.Mirror m = settings.mirrorFor(id, url);
        String effId = m != null ? m.id : id;
        String effUrl = m != null ? m.url : url;
        if (m != null && m.blocked) return;
        for (Remote r : remotes) {
            if (r.id.equals(effId) || r.url.equals(stripSlash(effUrl))) {
                if (!r.mirrorOf.contains(id)) r.mirrorOf.add(id);
                return;
            }
        }
        Remote r = new Remote(effId, effUrl, releases, snapshots, settings.server(effId));
        r.mirrorOf.add(id);
        remotes.add(r);
    }

    public void addFrom(Pom pom) {
        for (Pom.Repository r : pom.repositories) add(r.id, r.url, r.releases, r.snapshots);
    }

    private static String stripSlash(String u) {
        while (u.endsWith("/")) u = u.substring(0, u.length() - 1);
        return u;
    }

    private List<Remote> candidates(boolean snapshot) {
        List<Remote> out = new ArrayList<>();
        for (Remote r : remotes) if (snapshot ? r.snapshots : r.releases) out.add(r);
        return out;
    }

    // ---------------------------------------------------------------- metadata

    /** Versions known for groupId:artifactId across all repositories, or null when no repository has it. */
    public Metadata metadata(String groupId, String artifactId) throws HttpException {
        String key = groupId + ":" + artifactId;
        Metadata cached = metaCache.get(key);
        if (cached != null) return cached;
        Metadata merged = null;
        HttpException last = null;
        String path = groupId.replace('.', '/') + "/" + artifactId + "/maven-metadata.xml";
        for (Remote r : remotes) {
            try {
                Http.Response resp = http.get(r.url + "/" + path, metadataTtl, r.headers);
                if (!resp.ok()) {
                    if (resp.status != 404 && resp.status != 410) last = new HttpException(resp.url, resp.status, "");
                    continue;
                }
                Metadata m = Metadata.parse(resp.body);
                m.sources.add(r.id);
                if (merged == null) merged = m;
                else merged.merge(m);
            } catch (HttpException e) {
                last = e;
            } catch (IllegalArgumentException e) {
                // corrupt metadata on one repository should not hide the others
            }
        }
        if (merged == null && last != null) throw last;
        if (merged != null) metaCache.put(key, merged);
        return merged;
    }

    /** Resolves a timestamped SNAPSHOT file name (e.g. 1.0-20240101.120000-3) for a remote. */
    private String snapshotValue(Remote r, Gav gav, String classifier, String ext) {
        try {
            Http.Response resp = http.get(r.url + "/" + gav.path() + "/maven-metadata.xml", metadataTtl, r.headers);
            if (!resp.ok()) return null;
            Metadata m = Metadata.parse(resp.body);
            String v = m.snapshotValues.get((classifier == null ? "" : classifier) + ":" + ext);
            if (v != null) return v;
            if (m.snapshotTimestamp != null) return gav.version.replace("SNAPSHOT", m.snapshotTimestamp + "-" + m.snapshotBuild);
        } catch (HttpException | IllegalArgumentException ignored) {
        }
        return null;
    }

    // ---------------------------------------------------------------- files

    /** Repository-relative path of a file (does not resolve snapshot timestamps). */
    public static String filePath(Gav gav, String classifier, String ext) { return gav.file(classifier, ext); }

    public String centralUrl(Gav gav, String classifier, String ext) { return remotes.get(0).url + "/" + gav.file(classifier, ext); }

    public static final class Fetched {
        public final byte[] data;
        public final String url;
        public final String repoId;

        Fetched(byte[] d, String u, String r) { data = d; url = u; repoId = r; }
    }

    /** Downloads a file, trying the local repository first for releases. Returns null when no repository has it. */
    public Fetched fetch(Gav gav, String classifier, String ext) throws HttpException {
        if (gav.version == null) throw new IllegalArgumentException(gav.ga() + " has no version");
        boolean snap = gav.version.endsWith("-SNAPSHOT");
        if (useLocal && !snap && localRepo != null) {
            Path p = localRepo.resolve(gav.file(classifier, ext));
            try {
                if (Files.isRegularFile(p) && Files.size(p) > 0) return new Fetched(Files.readAllBytes(p), p.toUri().toString(), "local");
            } catch (IOException ignored) {}
        }
        HttpException last = null;
        for (Remote r : candidates(snap)) {
            String rel = gav.file(classifier, ext);
            if (snap) {
                String sv = snapshotValue(r, gav, classifier, ext);
                if (sv != null) rel = gav.path() + "/" + gav.artifactId + "-" + sv + (classifier == null ? "" : "-" + classifier) + "." + ext;
            }
            String url = r.url + "/" + rel;
            try {
                Http.Response resp = http.get(url, snap ? metadataTtl : Http.FOREVER, r.headers);
                if (resp.ok()) return new Fetched(resp.body, url, r.id);
                if (resp.status != 404 && resp.status != 410) last = new HttpException(url, resp.status, "");
            } catch (HttpException e) {
                last = e;
            }
        }
        if (last != null && last.status != 0 && last.status != 401 && last.status != 403) throw last;
        if (last != null && last.status == 0) throw last;
        return null;
    }

    public byte[] fetchBytes(Gav gav, String classifier, String ext) throws HttpException {
        Fetched f = fetch(gav, classifier, ext);
        return f == null ? null : f.data;
    }

    /** The POM for a version (cached in memory for the run). */
    public byte[] pom(Gav gav) throws HttpException {
        String k = gav.toString();
        byte[] c = pomCache.get(k);
        if (c != null) return c;
        byte[] d = fetchBytes(gav, null, "pom");
        if (d != null) pomCache.put(k, d);
        return d;
    }

    /** Checks presence without downloading (HEAD), on the first repository that answers. */
    public int status(String url, Remote r) {
        try {
            Http.Response resp = http.head(url);
            return resp.status;
        } catch (HttpException e) {
            return 0;
        }
    }
}
