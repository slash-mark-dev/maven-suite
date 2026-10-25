package in.slashmark.maven.data;

import in.slashmark.maven.util.Http;
import in.slashmark.maven.util.HttpException;
import in.slashmark.maven.util.Json;
import java.util.ArrayList;
import java.util.List;

/** Maven Central search (search.maven.org solrsearch): release timestamps, group listings, checksum search. */
public final class CentralSearch {
    private final Http http;
    private final String base;
    private long ttl = Http.DEFAULT_TTL;

    public CentralSearch(Http http, String base) {
        this.http = http;
        this.base = base;
    }

    public void setTtl(long ttl) { this.ttl = ttl; }

    public static final class Doc {
        public String groupId, artifactId, version, packaging, latestVersion;
        public long timestamp;
        public int versionCount;
        public final List<String> extensions = new ArrayList<>();
    }

    public static final class Result {
        public long numFound;
        public final List<Doc> docs = new ArrayList<>();
    }

    private Result query(String q, String core, int rows) throws HttpException {
        String url = base + "/solrsearch/select?q=" + Http.enc(q) + (core == null ? "" : "&core=" + core) + "&rows=" + rows + "&wt=json";
        Object j = http.getJson(url, ttl, null);
        Result r = new Result();
        r.numFound = Json.num(j, 0, "response", "numFound");
        for (Object d : Json.list(j, "response", "docs")) {
            Doc doc = new Doc();
            doc.groupId = Json.str(d, "g");
            doc.artifactId = Json.str(d, "a");
            doc.version = Json.str(d, "v");
            doc.latestVersion = Json.str(d, "latestVersion");
            doc.packaging = Json.str(d, "p");
            doc.timestamp = Json.num(d, 0, "timestamp");
            doc.versionCount = (int) Json.num(d, 0, "versionCount");
            for (Object e : Json.list(d, "ec")) doc.extensions.add(String.valueOf(e));
            r.docs.add(doc);
        }
        return r;
    }

    /** Every version of g:a with its release timestamp, newest first. */
    public Result versions(String groupId, String artifactId, int rows) throws HttpException {
        return query("g:\"" + groupId + "\" AND a:\"" + artifactId + "\"", "gav", rows);
    }

    /** One specific version (empty result when it is not indexed yet). */
    public Result version(String groupId, String artifactId, String version) throws HttpException {
        return query("g:\"" + groupId + "\" AND a:\"" + artifactId + "\" AND v:\"" + version + "\"", "gav", 1);
    }

    /** Artifacts published under a groupId (latest version per artifact). */
    public Result group(String groupId, int rows) throws HttpException {
        return query("g:\"" + groupId + "\"", null, rows);
    }

    /** Artifacts whose name matches (any group). */
    public Result artifact(String artifactId, int rows) throws HttpException {
        return query("a:\"" + artifactId + "\"", null, rows);
    }

    /** Artifacts containing a file with this SHA-1. */
    public Result sha1(String sha1, int rows) throws HttpException {
        return query("1:\"" + sha1 + "\"", null, rows);
    }
}
