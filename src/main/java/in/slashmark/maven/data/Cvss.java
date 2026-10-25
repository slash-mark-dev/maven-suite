package in.slashmark.maven.data;

import java.util.HashMap;
import java.util.Map;

/** CVSS v3.0/v3.1 base score calculator (FIRST specification) and severity bands. */
public final class Cvss {
    private Cvss() {}

    /** Base score for a vector like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", or -1 when unparseable. */
    public static double score(String vector) {
        if (vector == null || !vector.startsWith("CVSS:3")) return -1;
        Map<String, String> m = new HashMap<>();
        for (String part : vector.split("/")) {
            int i = part.indexOf(':');
            if (i > 0) m.put(part.substring(0, i), part.substring(i + 1));
        }
        try {
            boolean changed = "C".equals(m.get("S"));
            double av = pick(m.get("AV"), "N", 0.85, "A", 0.62, "L", 0.55, "P", 0.2);
            double ac = pick(m.get("AC"), "L", 0.77, "H", 0.44);
            double pr = changed ? pick(m.get("PR"), "N", 0.85, "L", 0.68, "H", 0.5) : pick(m.get("PR"), "N", 0.85, "L", 0.62, "H", 0.27);
            double ui = pick(m.get("UI"), "N", 0.85, "R", 0.62);
            double c = pick(m.get("C"), "H", 0.56, "L", 0.22, "N", 0);
            double in = pick(m.get("I"), "H", 0.56, "L", 0.22, "N", 0);
            double a = pick(m.get("A"), "H", 0.56, "L", 0.22, "N", 0);
            double iss = 1 - (1 - c) * (1 - in) * (1 - a);
            double impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
            double exploit = 8.22 * av * ac * pr * ui;
            if (impact <= 0) return 0;
            double base = changed ? roundUp(Math.min(1.08 * (impact + exploit), 10)) : roundUp(Math.min(impact + exploit, 10));
            return base;
        } catch (IllegalArgumentException e) {
            return -1;
        }
    }

    private static double pick(String v, Object... kv) {
        for (int i = 0; i + 1 < kv.length; i += 2) if (kv[i].equals(v)) return ((Number) kv[i + 1]).doubleValue();
        throw new IllegalArgumentException("bad metric " + v);
    }

    /** CVSS 3.1 Roundup: smallest number, to one decimal, equal to or higher than its input. */
    static double roundUp(double d) {
        long i = Math.round(d * 100000);
        if (i % 10000 == 0) return i / 100000.0;
        return (Math.floor(i / 10000.0) + 1) / 10.0;
    }

    /** critical / high / medium / low / none per the CVSS qualitative scale. */
    public static String severity(double score) {
        if (score < 0) return "unknown";
        if (score == 0) return "none";
        if (score < 4) return "low";
        if (score < 7) return "medium";
        if (score < 9) return "high";
        return "critical";
    }

    /** Rank for sorting/thresholds: critical 4, high 3, medium 2, low 1, other 0. */
    public static int rank(String severity) {
        if (severity == null) return 0;
        switch (severity.toLowerCase()) {
            case "critical": return 4;
            case "high": return 3;
            case "medium": case "moderate": return 2;
            case "low": return 1;
            default: return 0;
        }
    }

    /** Normalises GHSA/OSV severity words ("MODERATE" becomes "medium"). */
    public static String normalize(String s) {
        if (s == null) return null;
        String t = s.trim().toLowerCase();
        if (t.equals("moderate")) return "medium";
        if (t.equals("critical") || t.equals("high") || t.equals("medium") || t.equals("low")) return t;
        return null;
    }
}
