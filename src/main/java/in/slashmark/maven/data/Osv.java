package in.slashmark.maven.data;

import in.slashmark.maven.model.MavenVersion;
import in.slashmark.maven.util.Http;
import in.slashmark.maven.util.HttpException;
import in.slashmark.maven.util.Json;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** OSV.dev client for the Maven ecosystem (advisories from GitHub, NVD-linked aliases, etc.). */
public final class Osv {
    private final Http http;
    private final String base;
    private long ttl = Http.DEFAULT_TTL;
    private final Map<String, Vuln> cache = new java.util.concurrent.ConcurrentHashMap<>();

    public Osv(Http http, String base) {
        this.http = http;
        this.base = base;
    }

    /** Watch loops set this to a short value so new advisories show up within one cycle. */
    public void setTtl(long ttl) { this.ttl = ttl; }

    /** One advisory, with the parts the tools need. */
    public static final class Vuln implements Json.JsonWritable {
        public String id, summary, details;
        public final List<String> aliases = new ArrayList<>();
        public String severity;       // critical/high/medium/low/unknown
        public double score = -1;     // CVSS base score when known
        public String vector;
        public long published, modified;
        public boolean withdrawn;
        public final List<String> cwes = new ArrayList<>();
        public final List<String> references = new ArrayList<>();
        /** Affected Maven packages: "g:a" -> ranges of [introduced, fixed or last_affected] events. */
        public final Map<String, List<Range>> affected = new LinkedHashMap<>();
        /** Explicit affected versions per package (OSV "versions"). */
        public final Map<String, Set<String>> versions = new LinkedHashMap<>();

        public static final class Range {
            public String introduced;  // "0" means all earlier versions
            public String fixed;       // exclusive upper bound
            public String lastAffected;// inclusive upper bound

            public boolean contains(String v) {
                MavenVersion mv = MavenVersion.of(v);
                if (introduced != null && !"0".equals(introduced) && mv.compareTo(MavenVersion.of(introduced)) < 0) return false;
                if (fixed != null && mv.compareTo(MavenVersion.of(fixed)) >= 0) return false;
                if (lastAffected != null && mv.compareTo(MavenVersion.of(lastAffected)) > 0) return false;
                return true;
            }

            @Override
            public String toString() {
                String lo = introduced == null || "0".equals(introduced) ? "" : ">=" + introduced;
                String hi = fixed != null ? "<" + fixed : lastAffected != null ? "<=" + lastAffected : "";
                if (lo.isEmpty() && hi.isEmpty()) return "all versions";
                if (lo.isEmpty()) return hi;
                if (hi.isEmpty()) return lo;
                return lo + ", " + hi;
            }
        }

        /** CVE identifiers among id and aliases. */
        public List<String> cves() {
            List<String> out = new ArrayList<>();
            if (id != null && id.startsWith("CVE-")) out.add(id);
            for (String a : aliases) if (a.startsWith("CVE-") && !out.contains(a)) out.add(a);
            return out;
        }

        /** The most recognisable identifier: the CVE if there is one, else the OSV/GHSA id. */
        public String displayId() {
            List<String> c = cves();
            return c.isEmpty() ? id : c.get(0);
        }

        public boolean affects(String ga, String version) {
            Set<String> vs = versions.get(ga);
            if (vs != null && vs.contains(version)) return true;
            List<Range> rs = affected.get(ga);
            if (rs == null) return false;
            for (Range r : rs) if (r.contains(version)) return true;
            return false;
        }

        /** All "fixed" versions for the package, ascending. */
        public List<String> fixedVersions(String ga) {
            Set<String> s = new LinkedHashSet<>();
            List<Range> rs = affected.get(ga);
            if (rs != null) for (Range r : rs) if (r.fixed != null) s.add(r.fixed);
            List<String> out = new ArrayList<>(s);
            out.sort(MavenVersion::compare);
            return out;
        }

        /** Smallest fixed version above the given version (null when no fix exists). */
        public String fixFor(String ga, String version) {
            MavenVersion mv = MavenVersion.of(version);
            List<Range> rs = affected.get(ga);
            String best = null;
            if (rs != null) {
                for (Range r : rs) {
                    if (r.fixed == null || !r.contains(version)) continue;
                    if (MavenVersion.of(r.fixed).compareTo(mv) > 0 && (best == null || MavenVersion.compare(r.fixed, best) < 0)) best = r.fixed;
                }
            }
            if (best == null) for (String f : fixedVersions(ga)) if (MavenVersion.of(f).compareTo(mv) > 0) { best = f; break; }
            return best;
        }

        public String url() { return "https://osv.dev/vulnerability/" + id; }

        @Override
        public Object toJson() {
            return Json.obj("id", id, "cve", cves().isEmpty() ? null : cves(), "aliases", aliases, "summary", summary,
                    "severity", severity, "cvss", score >= 0 ? score : null, "vector", vector,
                    "published", published > 0 ? Instant.ofEpochMilli(published).toString() : null,
                    "modified", modified > 0 ? Instant.ofEpochMilli(modified).toString() : null,
                    "cwe", cwes.isEmpty() ? null : cwes, "url", url());
        }
    }

    // ---------------------------------------------------------------- API

    /** Advisory ids affecting each g:a:v, in input order (querybatch, 1000 per request, paginated). */
    public List<List<String>> queryBatch(List<String[]> gaVersions) throws HttpException {
        List<List<String>> out = new ArrayList<>();
        for (int i = 0; i < gaVersions.size(); i++) out.add(new ArrayList<>());
        for (int from = 0; from < gaVersions.size(); from += 1000) {
            int to = Math.min(gaVersions.size(), from + 1000);
            List<Integer> idx = new ArrayList<>();
            List<Object> queries = new ArrayList<>();
            List<String> tokens = new ArrayList<>();
            for (int i = from; i < to; i++) {
                idx.add(i);
                tokens.add(null);
            }
            int guard = 0;
            while (!idx.isEmpty() && guard++ < 20) {
                queries.clear();
                for (int k = 0; k < idx.size(); k++) {
                    String[] gv = gaVersions.get(idx.get(k));
                    Map<String, Object> q = Json.obj("package", Json.obj("name", gv[0], "ecosystem", "Maven"), "version", gv[1]);
                    if (tokens.get(k) != null) q.put("page_token", tokens.get(k));
                    queries.add(q);
                }
                Http.Response r = http.post(base + "/v1/querybatch", Json.write(Json.obj("queries", queries), false), ttl);
                if (!r.ok()) throw new HttpException(base + "/v1/querybatch", r.status, r.text());
                List<Object> results = Json.list(r.json(), "results");
                List<Integer> nextIdx = new ArrayList<>();
                List<String> nextTok = new ArrayList<>();
                for (int k = 0; k < idx.size() && k < results.size(); k++) {
                    Object res = results.get(k);
                    for (Object v : Json.list(res, "vulns")) {
                        String id = Json.str(v, "id");
                        if (id != null && !out.get(idx.get(k)).contains(id)) out.get(idx.get(k)).add(id);
                    }
                    String tok = Json.str(res, "next_page_token");
                    if (tok != null && !tok.isEmpty()) {
                        nextIdx.add(idx.get(k));
                        nextTok.add(tok);
                    }
                }
                idx = nextIdx;
                tokens = nextTok;
            }
        }
        return out;
    }

    /** Full advisory record (cached for the run; on disk for an hour). */
    public Vuln get(String id) throws HttpException {
        Vuln c = cache.get(id);
        if (c != null) return c;
        Object j = http.getJson(base + "/v1/vulns/" + Http.enc(id), Math.max(ttl, 60 * 60 * 1000L), null);
        Vuln v = parse(j);
        cache.put(id, v);
        return v;
    }

    /** Fetches several advisories in parallel; ids that fail to load are skipped. */
    public Map<String, Vuln> getAll(Iterable<String> ids) {
        List<String> list = new ArrayList<>();
        for (String id : ids) if (!list.contains(id)) list.add(id);
        Map<String, Vuln> out = new LinkedHashMap<>();
        List<Vuln> vs = http.parallelOrNull(list, this::get);
        for (int i = 0; i < list.size(); i++) if (vs.get(i) != null) out.put(list.get(i), vs.get(i));
        return out;
    }

    /** Advisories for a CVE or GHSA/OSV id; OSV resolves CVE ids to their aliases. */
    public Vuln lookup(String anyId) throws HttpException {
        Http.Response r = http.get(base + "/v1/vulns/" + Http.enc(anyId), ttl, null);
        if (r.ok()) return parse(r.json());
        if (r.status == 404) return null;
        throw new HttpException(r.url, r.status, r.text());
    }

    /** All advisories ever published for a package (any version). */
    public List<String> allForPackage(String ga) throws HttpException {
        Map<String, Object> q = Json.obj("package", Json.obj("name", ga, "ecosystem", "Maven"));
        List<String> out = new ArrayList<>();
        String token = null;
        for (int page = 0; page < 20; page++) {
            if (token != null) q.put("page_token", token);
            Http.Response r = http.post(base + "/v1/query", Json.write(q, false), ttl);
            if (!r.ok()) throw new HttpException(base + "/v1/query", r.status, r.text());
            Object j = r.json();
            for (Object v : Json.list(j, "vulns")) {
                String id = Json.str(v, "id");
                if (id != null && !out.contains(id)) {
                    out.add(id);
                    if (!cache.containsKey(id)) cache.put(id, parse(v));
                }
            }
            token = Json.str(j, "next_page_token");
            if (token == null || token.isEmpty()) break;
        }
        return out;
    }

    public static Vuln parse(Object j) {
        Vuln v = new Vuln();
        v.id = Json.str(j, "id");
        v.summary = Json.str(j, "summary");
        v.details = Json.str(j, "details");
        if (v.summary == null && v.details != null) {
            String d = v.details.strip();
            int nl = d.indexOf('\n');
            v.summary = nl > 0 ? d.substring(0, nl) : d;
            if (v.summary.length() > 160) v.summary = v.summary.substring(0, 157) + "...";
        }
        for (Object a : Json.list(j, "aliases")) v.aliases.add(String.valueOf(a));
        v.published = parseTime(Json.str(j, "published"));
        v.modified = parseTime(Json.str(j, "modified"));
        v.withdrawn = Json.str(j, "withdrawn") != null;
        for (Object s : Json.list(j, "severity")) {
            String type = Json.str(s, "type");
            String score = Json.str(s, "score");
            if (type != null && type.startsWith("CVSS_V3") && score != null) {
                double sc = Cvss.score(score);
                if (sc > v.score) {
                    v.score = sc;
                    v.vector = score;
                }
            } else if (v.vector == null && score != null) {
                v.vector = score;
            }
        }
        String dbSev = Cvss.normalize(Json.str(j, "database_specific", "severity"));
        v.severity = dbSev != null ? dbSev : v.score >= 0 ? Cvss.severity(v.score) : "unknown";
        for (Object c : Json.list(j, "database_specific", "cwe_ids")) v.cwes.add(String.valueOf(c));
        for (Object r : Json.list(j, "references")) {
            String u = Json.str(r, "url");
            if (u != null) v.references.add(u);
        }
        for (Object a : Json.list(j, "affected")) {
            if (!"Maven".equalsIgnoreCase(Json.str(a, "package", "ecosystem"))) continue;
            String ga = Json.str(a, "package", "name");
            if (ga == null) continue;
            if (v.severity.equals("unknown")) {
                String es = Cvss.normalize(Json.str(a, "ecosystem_specific", "severity"));
                if (es != null) v.severity = es;
            }
            List<Vuln.Range> ranges = v.affected.computeIfAbsent(ga, k -> new ArrayList<>());
            for (Object r : Json.list(a, "ranges")) {
                String type = Json.str(r, "type");
                if (type != null && !type.equals("ECOSYSTEM")) continue;
                Vuln.Range cur = null;
                for (Object e : Json.list(r, "events")) {
                    String intro = Json.str(e, "introduced");
                    String fixed = Json.str(e, "fixed");
                    String last = Json.str(e, "last_affected");
                    if (intro != null) {
                        cur = new Vuln.Range();
                        cur.introduced = intro;
                        ranges.add(cur);
                    } else if (fixed != null || last != null) {
                        if (cur == null) {
                            cur = new Vuln.Range();
                            cur.introduced = "0";
                            ranges.add(cur);
                        }
                        cur.fixed = fixed;
                        cur.lastAffected = last;
                        cur = null;
                    }
                }
            }
            Set<String> vs = v.versions.computeIfAbsent(ga, k -> new LinkedHashSet<>());
            for (Object ver : Json.list(a, "versions")) vs.add(String.valueOf(ver));
        }
        return v;
    }

    public static long parseTime(String s) {
        if (s == null) return 0;
        try {
            return Instant.parse(s).toEpochMilli();
        } catch (RuntimeException e) {
            try {
                return java.time.OffsetDateTime.parse(s).toInstant().toEpochMilli();
            } catch (RuntimeException e2) {
                try {
                    return java.time.LocalDate.parse(s.length() >= 10 ? s.substring(0, 10) : s).atStartOfDay(java.time.ZoneOffset.UTC).toInstant().toEpochMilli();
                } catch (RuntimeException e3) {
                    return 0;
                }
            }
        }
    }
}
