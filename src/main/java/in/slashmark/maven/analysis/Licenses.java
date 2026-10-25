package in.slashmark.maven.analysis;

import in.slashmark.maven.model.Pom;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Maps the free-text license names and URLs found in POMs to SPDX identifiers, and classifies them
 * (permissive, weak copyleft, strong copyleft, network copyleft, source-available). Informational, not legal advice.
 */
public final class Licenses {
    private Licenses() {}

    public enum Category {
        PERMISSIVE("permissive"), WEAK_COPYLEFT("weak copyleft"), STRONG_COPYLEFT("strong copyleft"),
        NETWORK_COPYLEFT("network copyleft"), SOURCE_AVAILABLE("source-available / non-OSS"), PUBLIC_DOMAIN("public domain"), UNKNOWN("unknown");

        public final String label;

        Category(String l) { label = l; }
    }

    private static final Map<String, Category> CATEGORY = new LinkedHashMap<>();
    /** Ordered matchers: lower-case fragment of a name or URL -> SPDX id. More specific first. */
    private static final List<String[]> MATCHERS = new ArrayList<>();

    static {
        for (String s : new String[] {"Apache-2.0", "Apache-1.1", "MIT", "MIT-0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Zlib", "BSL-1.0", "UPL-1.0",
                "PostgreSQL", "X11", "Unicode-DFS-2016", "Unicode-3.0", "W3C", "JSON", "Bouncy-Castle", "BlueOak-1.0.0", "Python-2.0", "EDL-1.0", "ICU", "Libpng", "OpenSSL"}) CATEGORY.put(s, Category.PERMISSIVE);
        for (String s : new String[] {"CC0-1.0", "Unlicense", "0BSD", "WTFPL", "Public-Domain"}) CATEGORY.put(s, Category.PUBLIC_DOMAIN);
        for (String s : new String[] {"LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later", "LGPL-2.0-only", "MPL-1.1", "MPL-2.0",
                "EPL-1.0", "EPL-2.0", "CDDL-1.0", "CDDL-1.1", "GPL-2.0-with-classpath-exception", "CPL-1.0", "EUPL-1.1", "EUPL-1.2", "MS-PL", "MS-RL", "OSL-3.0"}) CATEGORY.put(s, Category.WEAK_COPYLEFT);
        for (String s : new String[] {"GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later", "GPL-1.0-or-later", "CC-BY-SA-4.0"}) CATEGORY.put(s, Category.STRONG_COPYLEFT);
        for (String s : new String[] {"AGPL-3.0-only", "AGPL-3.0-or-later", "SSPL-1.0", "OSL-3.0-network"}) CATEGORY.put(s, Category.NETWORK_COPYLEFT);
        for (String s : new String[] {"BUSL-1.1", "Elastic-2.0", "Commons-Clause", "PolyForm-Noncommercial-1.0.0", "PolyForm-Small-Business-1.0.0", "CC-BY-NC-4.0", "Confluent-Community-1.0", "Proprietary"}) CATEGORY.put(s, Category.SOURCE_AVAILABLE);
        CATEGORY.put("SSPL-1.0", Category.NETWORK_COPYLEFT);

        m("classpath exception", "GPL-2.0-with-classpath-exception");
        m("classpath-exception", "GPL-2.0-with-classpath-exception");
        m("cpe", "GPL-2.0-with-classpath-exception");
        m("affero", "AGPL-3.0-only");
        m("agpl", "AGPL-3.0-only");
        m("lesser general public license, version 2.1", "LGPL-2.1-only");
        m("lgpl-2.1", "LGPL-2.1-only");
        m("lgpl 2.1", "LGPL-2.1-only");
        m("lgpl, version 2.1", "LGPL-2.1-only");
        m("lgpl-3", "LGPL-3.0-only");
        m("lesser general public license v3", "LGPL-3.0-only");
        m("lesser general public license, version 3", "LGPL-3.0-only");
        m("lgpl", "LGPL-2.1-or-later");
        m("lesser general public", "LGPL-2.1-or-later");
        m("library general public", "LGPL-2.0-only");
        m("gpl-3", "GPL-3.0-only");
        m("gplv3", "GPL-3.0-only");
        m("gpl v3", "GPL-3.0-only");
        m("general public license v3", "GPL-3.0-only");
        m("general public license, version 3", "GPL-3.0-only");
        m("gnu general public license v3", "GPL-3.0-only");
        m("gpl-2", "GPL-2.0-only");
        m("gplv2", "GPL-2.0-only");
        m("gpl v2", "GPL-2.0-only");
        m("general public license, version 2", "GPL-2.0-only");
        m("general public license v2", "GPL-2.0-only");
        m("gnu general public license", "GPL-2.0-or-later");
        m("server side public license", "SSPL-1.0");
        m("sspl", "SSPL-1.0");
        m("business source license", "BUSL-1.1");
        m("busl", "BUSL-1.1");
        m("bsl11", "BUSL-1.1");
        m("mariadb.com/bsl", "BUSL-1.1");
        m("elastic license 2", "Elastic-2.0");
        m("elastic-2.0", "Elastic-2.0");
        m("commons clause", "Commons-Clause");
        m("polyform noncommercial", "PolyForm-Noncommercial-1.0.0");
        m("confluent community", "Confluent-Community-1.0");
        m("apache license, version 2", "Apache-2.0");
        m("apache license version 2", "Apache-2.0");
        m("apache license 2", "Apache-2.0");
        m("apache-2", "Apache-2.0");
        m("apache 2", "Apache-2.0");
        m("asl 2", "Apache-2.0");
        m("al 2.0", "Apache-2.0");
        m("apache.org/licenses/license-2.0", "Apache-2.0");
        m("the apache software license", "Apache-2.0");
        m("apache license", "Apache-2.0");
        m("apache software license, version 1.1", "Apache-1.1");
        m("eclipse public license - v 2", "EPL-2.0");
        m("eclipse public license v2", "EPL-2.0");
        m("eclipse public license, version 2", "EPL-2.0");
        m("eclipse public license 2", "EPL-2.0");
        m("epl-2", "EPL-2.0");
        m("epl 2", "EPL-2.0");
        m("eclipse.org/legal/epl-2.0", "EPL-2.0");
        m("eclipse distribution license", "EDL-1.0");
        m("edl 1.0", "EDL-1.0");
        m("eclipse public license", "EPL-1.0");
        m("epl-1", "EPL-1.0");
        m("epl 1", "EPL-1.0");
        m("mozilla public license, version 2", "MPL-2.0");
        m("mozilla public license 2", "MPL-2.0");
        m("mpl-2", "MPL-2.0");
        m("mpl 2", "MPL-2.0");
        m("mozilla public license", "MPL-1.1");
        m("common development and distribution license (cddl) v1.1", "CDDL-1.1");
        m("cddl 1.1", "CDDL-1.1");
        m("cddl-1.1", "CDDL-1.1");
        m("cddl+gpl", "CDDL-1.1");
        m("cddl", "CDDL-1.0");
        m("common development and distribution", "CDDL-1.0");
        m("common public license", "CPL-1.0");
        m("european union public licence 1.2", "EUPL-1.2");
        m("eupl-1.2", "EUPL-1.2");
        m("eupl", "EUPL-1.1");
        m("universal permissive license", "UPL-1.0");
        m("upl", "UPL-1.0");
        m("boost software license", "BSL-1.0");
        m("bsd-3", "BSD-3-Clause");
        m("bsd 3", "BSD-3-Clause");
        m("3-clause", "BSD-3-Clause");
        m("new bsd", "BSD-3-Clause");
        m("revised bsd", "BSD-3-Clause");
        m("modified bsd", "BSD-3-Clause");
        m("edl", "EDL-1.0");
        m("bsd-2", "BSD-2-Clause");
        m("bsd 2", "BSD-2-Clause");
        m("2-clause", "BSD-2-Clause");
        m("simplified bsd", "BSD-2-Clause");
        m("freebsd", "BSD-2-Clause");
        m("bsd", "BSD-3-Clause");
        m("mit-0", "MIT-0");
        m("mit license", "MIT");
        m("the mit", "MIT");
        m("opensource.org/licenses/mit", "MIT");
        m("bouncy castle", "Bouncy-Castle");
        m("isc", "ISC");
        m("zlib", "Zlib");
        m("unicode", "Unicode-DFS-2016");
        m("cc0", "CC0-1.0");
        m("creative commons zero", "CC0-1.0");
        m("public domain", "Public-Domain");
        m("unlicense", "Unlicense");
        m("wtfpl", "WTFPL");
        m("json license", "JSON");
        m("postgresql", "PostgreSQL");
        m("go license", "BSD-3-Clause");
        m("python software foundation", "Python-2.0");
        m("w3c", "W3C");
        m("ms-pl", "MS-PL");
        m("microsoft public license", "MS-PL");
    }

    private static void m(String frag, String spdx) { MATCHERS.add(new String[] {frag, spdx}); }

    /** SPDX id for one POM &lt;license&gt; (name and/or url); null when unrecognised. */
    public static String spdx(String name, String url) {
        if (name != null) {
            String direct = exactId(name.trim());
            if (direct != null) return direct;
        }
        String hay = ((name == null ? "" : name) + " | " + (url == null ? "" : url)).toLowerCase(Locale.ROOT);
        if (hay.trim().equals("|")) return null;
        for (String[] mm : MATCHERS) {
            String f = mm[0];
            if (f.length() <= 4) {
                // short fragments must match whole words to avoid false hits ("mit" in "summit")
                if (hay.matches("(?s).*(?:^|[^a-z0-9])" + java.util.regex.Pattern.quote(f) + "(?:[^a-z0-9]|$).*")) return mm[1];
            } else if (hay.contains(f)) return mm[1];
        }
        return null;
    }

    private static String exactId(String s) {
        for (String id : CATEGORY.keySet()) if (id.equalsIgnoreCase(s)) return id;
        switch (s.toUpperCase(Locale.ROOT)) {
            case "GPL-2.0": case "GPL-2.0+": return s.endsWith("+") ? "GPL-2.0-or-later" : "GPL-2.0-only";
            case "GPL-3.0": case "GPL-3.0+": return s.endsWith("+") ? "GPL-3.0-or-later" : "GPL-3.0-only";
            case "LGPL-2.1": case "LGPL-2.1+": return s.endsWith("+") ? "LGPL-2.1-or-later" : "LGPL-2.1-only";
            case "LGPL-3.0": case "LGPL-3.0+": return s.endsWith("+") ? "LGPL-3.0-or-later" : "LGPL-3.0-only";
            case "AGPL-3.0": return "AGPL-3.0-only";
            default: return null;
        }
    }

    /** All SPDX ids for a POM's licenses (unrecognised names are kept as "LicenseRef-<name>"). */
    public static List<String> of(Pom pom) {
        List<String> out = new ArrayList<>();
        for (Pom.License l : pom.licenses) {
            String id = spdx(l.name, l.url);
            if (id == null) id = "LicenseRef-" + (l.name != null ? l.name : l.url != null ? l.url : "unknown").replaceAll("[^A-Za-z0-9.\\-]+", "-");
            if (!out.contains(id)) out.add(id);
        }
        return out;
    }

    public static Category category(String spdx) {
        if (spdx == null) return Category.UNKNOWN;
        Category c = CATEGORY.get(spdx);
        return c == null ? Category.UNKNOWN : c;
    }

    /**
     * Category of a dependency with several licenses: Maven POMs list alternatives (dual licensing), so
     * the most permissive option is the one that applies.
     */
    public static Category bestOf(List<String> spdxIds) {
        if (spdxIds == null || spdxIds.isEmpty()) return Category.UNKNOWN;
        Category best = null;
        for (String id : spdxIds) {
            Category c = category(id);
            if (best == null || rank(c) < rank(best)) best = c;
        }
        return best;
    }

    /** Lower is more permissive. */
    public static int rank(Category c) {
        switch (c) {
            case PUBLIC_DOMAIN: return 0;
            case PERMISSIVE: return 1;
            case WEAK_COPYLEFT: return 2;
            case STRONG_COPYLEFT: return 3;
            case NETWORK_COPYLEFT: return 4;
            case SOURCE_AVAILABLE: return 5;
            default: return 6;
        }
    }

    /** Matches an SPDX id against a user pattern list (exact ids, "GPL-*" prefixes, or category names). */
    public static boolean matches(String spdx, List<String> patterns) {
        if (spdx == null) return false;
        for (String p : patterns) {
            String t = p.trim();
            if (t.isEmpty()) continue;
            if (t.equalsIgnoreCase(spdx)) return true;
            if (t.endsWith("*") && spdx.toLowerCase(Locale.ROOT).startsWith(t.substring(0, t.length() - 1).toLowerCase(Locale.ROOT))) return true;
            Category c = category(spdx);
            if (t.equalsIgnoreCase(c.name()) || t.equalsIgnoreCase(c.label) || t.replace('-', '_').equalsIgnoreCase(c.name())) return true;
        }
        return false;
    }
}
