package in.slashmark.maven.data;

import in.slashmark.maven.util.Http;
import in.slashmark.maven.util.HttpException;
import in.slashmark.maven.util.Json;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Minimal GitHub REST client (GITHUB_TOKEN raises the rate limit from 60 to 5,000 requests/hour). */
public final class GitHub {
    private final Http http;
    private final String base;
    private final String token;

    public GitHub(Http http, String base, String token) {
        this.http = http;
        this.base = base;
        this.token = token;
    }

    public boolean hasToken() { return token != null; }

    private Map<String, String> headers() {
        Map<String, String> h = new LinkedHashMap<>();
        h.put("Accept", "application/vnd.github+json");
        h.put("X-GitHub-Api-Version", "2022-11-28");
        if (token != null) h.put("Authorization", "Bearer " + token);
        return h;
    }

    private static final Pattern REPO = Pattern.compile("github\\.com[:/]+([A-Za-z0-9_.\\-]+)/([A-Za-z0-9_.\\-]+?)(?:\\.git)?(?:[/#?].*)?$");

    /** "owner/repo" from an SCM or project URL (scm:git:git@github.com:o/r.git, https://github.com/o/r/tree/x ...). */
    public static String repoFromUrl(String url) {
        if (url == null) return null;
        Matcher m = REPO.matcher(url.trim());
        if (!m.find()) return null;
        String owner = m.group(1), repo = m.group(2);
        if (repo.endsWith(".git")) repo = repo.substring(0, repo.length() - 4);
        return owner + "/" + repo;
    }

    public Object get(String path, long ttl) throws HttpException {
        Http.Response r = http.get(base + path, ttl, headers());
        if (r.status == 404) return null;
        if (r.status == 403 || r.status == 429) {
            String rem = r.header("x-ratelimit-remaining");
            if ("0".equals(rem)) throw new HttpException(r.url, r.status, "GitHub rate limit reached" + (token == null ? " (set GITHUB_TOKEN)" : ""));
        }
        if (!r.ok()) throw new HttpException(r.url, r.status, r.text());
        return r.json();
    }

    public static final class Repo {
        public String fullName, defaultBranch, license, description, htmlUrl;
        public boolean archived, disabled, fork;
        public long stars, forks, openIssues, pushedAt, createdAt;
    }

    public Repo repo(String ownerRepo) throws HttpException {
        Object j = get("/repos/" + ownerRepo, Http.DEFAULT_TTL);
        if (j == null) return null;
        Repo r = new Repo();
        r.fullName = Json.str(j, "full_name");
        r.defaultBranch = Json.str(j, "default_branch");
        r.license = Json.str(j, "license", "spdx_id");
        r.description = Json.str(j, "description");
        r.htmlUrl = Json.str(j, "html_url");
        r.archived = Json.bool(j, false, "archived");
        r.disabled = Json.bool(j, false, "disabled");
        r.fork = Json.bool(j, false, "fork");
        r.stars = Json.num(j, 0, "stargazers_count");
        r.forks = Json.num(j, 0, "forks_count");
        r.openIssues = Json.num(j, 0, "open_issues_count");
        r.pushedAt = Osv.parseTime(Json.str(j, "pushed_at"));
        r.createdAt = Osv.parseTime(Json.str(j, "created_at"));
        return r;
    }

    public static final class Release {
        public String tag, name, url, body;
        public long publishedAt;
        public boolean prerelease, draft;
    }

    public List<Release> releases(String ownerRepo, int max) throws HttpException {
        Object j = get("/repos/" + ownerRepo + "/releases?per_page=" + Math.min(100, max), Http.DEFAULT_TTL);
        List<Release> out = new ArrayList<>();
        if (j == null) return out;
        for (Object o : (List<?>) j) {
            Release r = new Release();
            r.tag = Json.str(o, "tag_name");
            r.name = Json.str(o, "name");
            r.url = Json.str(o, "html_url");
            r.body = Json.str(o, "body");
            r.publishedAt = Osv.parseTime(Json.str(o, "published_at"));
            r.prerelease = Json.bool(o, false, "prerelease");
            r.draft = Json.bool(o, false, "draft");
            out.add(r);
        }
        return out;
    }

    /** Commits since a time (up to 300, three pages). Returns commit timestamps and author logins. */
    public List<String[]> commitsSince(String ownerRepo, long sinceMillis) throws HttpException {
        List<String[]> out = new ArrayList<>();
        String since = java.time.Instant.ofEpochMilli(sinceMillis).toString();
        for (int page = 1; page <= 3; page++) {
            Object j = get("/repos/" + ownerRepo + "/commits?per_page=100&page=" + page + "&since=" + since, Http.DEFAULT_TTL);
            if (!(j instanceof List)) break;
            List<?> l = (List<?>) j;
            for (Object c : l) {
                String login = Json.str(c, "author", "login");
                if (login == null) login = Json.str(c, "commit", "author", "name");
                out.add(new String[] {Json.str(c, "commit", "author", "date"), login, Json.str(c, "sha")});
            }
            if (l.size() < 100) break;
        }
        return out;
    }

    /** Repositories of an organisation or user. */
    public List<Repo> orgRepos(String owner, int max) throws HttpException {
        List<Repo> out = new ArrayList<>();
        for (String kind : new String[] {"orgs", "users"}) {
            for (int page = 1; page <= 10 && out.size() < max; page++) {
                Object j = get("/" + kind + "/" + owner + "/repos?per_page=100&type=all&sort=pushed&page=" + page, Http.DEFAULT_TTL);
                if (!(j instanceof List)) break;
                List<?> l = (List<?>) j;
                for (Object o : l) {
                    Repo r = new Repo();
                    r.fullName = Json.str(o, "full_name");
                    r.defaultBranch = Json.str(o, "default_branch");
                    r.archived = Json.bool(o, false, "archived");
                    r.fork = Json.bool(o, false, "fork");
                    r.pushedAt = Osv.parseTime(Json.str(o, "pushed_at"));
                    r.htmlUrl = Json.str(o, "html_url");
                    r.stars = Json.num(o, 0, "stargazers_count");
                    out.add(r);
                }
                if (l.size() < 100) break;
            }
            if (!out.isEmpty()) break;
        }
        return out;
    }

    /** Paths of all files named like the pattern in a repository's default branch. */
    public List<String> findFiles(String ownerRepo, String branch, String fileName) throws HttpException {
        Object j = get("/repos/" + ownerRepo + "/git/trees/" + Http.enc(branch) + "?recursive=1", Http.DEFAULT_TTL);
        List<String> out = new ArrayList<>();
        if (j == null) return out;
        for (Object t : Json.list(j, "tree")) {
            String p = Json.str(t, "path");
            if ("blob".equals(Json.str(t, "type")) && p != null && (p.equals(fileName) || p.endsWith("/" + fileName))) out.add(p);
        }
        return out;
    }

    /** Raw contents of a file (null when missing). */
    public byte[] file(String ownerRepo, String path, String ref) throws HttpException {
        Object j = get("/repos/" + ownerRepo + "/contents/" + path.replace(" ", "%20") + (ref == null ? "" : "?ref=" + Http.enc(ref)), Http.DEFAULT_TTL);
        if (j == null) return null;
        String content = Json.str(j, "content");
        if (content == null) return null;
        return Base64.getMimeDecoder().decode(content.getBytes(StandardCharsets.US_ASCII));
    }
}
