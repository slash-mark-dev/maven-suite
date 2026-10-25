package in.slashmark.maven.data;

import in.slashmark.maven.util.Http;
import in.slashmark.maven.util.HttpException;
import in.slashmark.maven.util.Json;
import java.util.LinkedHashMap;
import java.util.Map;

/** CISA Known Exploited Vulnerabilities catalog (vulnerabilities exploited in the wild). */
public final class Kev {
    private final Http http;
    private final String url;
    private Map<String, Entry> entries;
    private String catalogVersion;

    public Kev(Http http, String url) {
        this.http = http;
        this.url = url;
    }

    public static final class Entry {
        public String cve, vendor, product, name, dateAdded, dueDate, requiredAction;
        public boolean ransomware;

        public Object toJson() {
            return Json.obj("cve", cve, "vendor", vendor, "product", product, "name", name, "dateAdded", dateAdded,
                    "dueDate", dueDate, "ransomware", ransomware);
        }
    }

    /** Loads the catalog (cached for 6 hours; it changes a few times a week). */
    public synchronized Map<String, Entry> catalog() throws HttpException {
        if (entries != null) return entries;
        Object j = http.getJson(url, 6 * 3600 * 1000L, null);
        Map<String, Entry> m = new LinkedHashMap<>();
        for (Object o : Json.list(j, "vulnerabilities")) {
            Entry e = new Entry();
            e.cve = Json.str(o, "cveID");
            if (e.cve == null) continue;
            e.vendor = Json.str(o, "vendorProject");
            e.product = Json.str(o, "product");
            e.name = Json.str(o, "vulnerabilityName");
            e.dateAdded = Json.str(o, "dateAdded");
            e.dueDate = Json.str(o, "dueDate");
            e.requiredAction = Json.str(o, "requiredAction");
            e.ransomware = "Known".equalsIgnoreCase(Json.str(o, "knownRansomwareCampaignUse"));
            m.put(e.cve, e);
        }
        catalogVersion = Json.str(j, "catalogVersion");
        entries = m;
        return m;
    }

    public Entry get(String cve) throws HttpException { return catalog().get(cve); }

    public String version() { return catalogVersion; }
}
