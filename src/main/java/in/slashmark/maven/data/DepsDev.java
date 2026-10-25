package in.slashmark.maven.data;

import in.slashmark.maven.util.Http;
import in.slashmark.maven.util.HttpException;
import in.slashmark.maven.util.Json;
import java.util.ArrayList;
import java.util.List;

/** Google's Open Source Insights (deps.dev) API: versions, licenses, dependents, project scorecards. */
public final class DepsDev {
    private final Http http;
    private final String base;

    public DepsDev(Http http, String base) {
        this.http = http;
        this.base = base;
    }

    private static String name(String ga) { return Http.enc(ga); }

    public static final class VersionInfo {
        public String version;
        public long publishedAt;
        public boolean isDefault;
        public final List<String> licenses = new ArrayList<>();
        public final List<String> advisories = new ArrayList<>();
        public String sourceRepo;
        public String projectId;
    }

    /** All versions with publish times (null when deps.dev does not know the package). */
    public List<VersionInfo> versions(String ga) throws HttpException {
        Http.Response r = http.get(base + "/v3/systems/maven/packages/" + name(ga), Http.DEFAULT_TTL, null);
        if (r.status == 404) return null;
        if (!r.ok()) throw new HttpException(r.url, r.status, r.text());
        List<VersionInfo> out = new ArrayList<>();
        for (Object v : Json.list(r.json(), "versions")) {
            VersionInfo vi = new VersionInfo();
            vi.version = Json.str(v, "versionKey", "version");
            vi.publishedAt = Osv.parseTime(Json.str(v, "publishedAt"));
            vi.isDefault = Json.bool(v, false, "isDefault");
            out.add(vi);
        }
        return out;
    }

    public VersionInfo version(String ga, String version) throws HttpException {
        Http.Response r = http.get(base + "/v3/systems/maven/packages/" + name(ga) + "/versions/" + Http.enc(version), Http.DEFAULT_TTL, null);
        if (r.status == 404) return null;
        if (!r.ok()) throw new HttpException(r.url, r.status, r.text());
        Object j = r.json();
        VersionInfo vi = new VersionInfo();
        vi.version = version;
        vi.publishedAt = Osv.parseTime(Json.str(j, "publishedAt"));
        vi.isDefault = Json.bool(j, false, "isDefault");
        for (Object l : Json.list(j, "licenses")) vi.licenses.add(String.valueOf(l));
        for (Object a : Json.list(j, "advisoryKeys")) vi.advisories.add(Json.str(a, "id"));
        for (Object l : Json.list(j, "links")) if ("SOURCE_REPO".equals(Json.str(l, "label"))) vi.sourceRepo = Json.str(l, "url");
        for (Object p : Json.list(j, "relatedProjects")) {
            if ("SOURCE_REPO".equals(Json.str(p, "relationType")) && vi.projectId == null) vi.projectId = Json.str(p, "projectKey", "id");
        }
        return vi;
    }

    public static final class Dependents {
        public long total, direct, indirect;
    }

    /** Number of packages that depend on this version (deps.dev v3alpha). Null when unknown. */
    public Dependents dependents(String ga, String version) throws HttpException {
        Http.Response r = http.get(base + "/v3alpha/systems/maven/packages/" + name(ga) + "/versions/" + Http.enc(version) + ":dependents", Http.DEFAULT_TTL, null);
        if (r.status == 404) return null;
        if (!r.ok()) throw new HttpException(r.url, r.status, r.text());
        Object j = r.json();
        Dependents d = new Dependents();
        d.total = Json.num(j, 0, "dependentCount");
        d.direct = Json.num(j, 0, "directDependentCount");
        d.indirect = Json.num(j, 0, "indirectDependentCount");
        return d;
    }

    public static final class Project {
        public String id, description, license;
        public long stars, forks, openIssues;
        public double scorecard = -1;
        public String scorecardDate;
        public final List<String[]> checks = new ArrayList<>();
    }

    /** Project data incl. the OpenSSF Scorecard, e.g. id "github.com/google/guava". */
    public Project project(String projectId) throws HttpException {
        Http.Response r = http.get(base + "/v3/projects/" + Http.enc(projectId), Http.DEFAULT_TTL, null);
        if (r.status == 404) return null;
        if (!r.ok()) throw new HttpException(r.url, r.status, r.text());
        Object j = r.json();
        Project p = new Project();
        p.id = projectId;
        p.description = Json.str(j, "description");
        p.license = Json.str(j, "license");
        p.stars = Json.num(j, 0, "starsCount");
        p.forks = Json.num(j, 0, "forksCount");
        p.openIssues = Json.num(j, 0, "openIssuesCount");
        Object sc = Json.get(j, "scorecard");
        if (sc != null) {
            p.scorecard = Json.dbl(sc, -1, "overallScore");
            p.scorecardDate = Json.str(sc, "date");
            for (Object c : Json.list(sc, "checks")) p.checks.add(new String[] {Json.str(c, "name"), String.valueOf(Json.num(c, -1, "score")), Json.str(c, "reason")});
        }
        return p;
    }
}
