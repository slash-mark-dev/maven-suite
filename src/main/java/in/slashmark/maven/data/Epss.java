package in.slashmark.maven.data;

import in.slashmark.maven.util.Http;
import in.slashmark.maven.util.HttpException;
import in.slashmark.maven.util.Json;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** FIRST EPSS: probability that a CVE is exploited in the next 30 days (updated daily). */
public final class Epss {
    private final Http http;
    private final String base;

    public Epss(Http http, String base) {
        this.http = http;
        this.base = base;
    }

    public static final class Score {
        public final String cve;
        public final double epss, percentile;
        public final String date;

        Score(String cve, double epss, double percentile, String date) {
            this.cve = cve;
            this.epss = epss;
            this.percentile = percentile;
            this.date = date;
        }

        public Object toJson() { return Json.obj("cve", cve, "epss", epss, "percentile", percentile, "date", date); }
    }

    /** Scores for the given CVE ids (batched; unknown CVEs are simply absent). */
    public Map<String, Score> scores(List<String> cves) throws HttpException {
        Map<String, Score> out = new LinkedHashMap<>();
        List<String> todo = new ArrayList<>();
        for (String c : cves) if (c != null && c.startsWith("CVE-") && !todo.contains(c)) todo.add(c);
        for (int i = 0; i < todo.size(); i += 80) {
            List<String> batch = todo.subList(i, Math.min(todo.size(), i + 80));
            Object j = http.getJson(base + "?cve=" + String.join(",", batch), 6 * 3600 * 1000L, null);
            for (Object d : Json.list(j, "data")) {
                String cve = Json.str(d, "cve");
                if (cve == null) continue;
                out.put(cve, new Score(cve, Json.dbl(d, 0, "epss"), Json.dbl(d, 0, "percentile"), Json.str(d, "date")));
            }
        }
        return out;
    }
}
