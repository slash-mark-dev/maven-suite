package in.slashmark.maven.analysis;

import in.slashmark.maven.cli.Ctx;
import in.slashmark.maven.data.Cvss;
import in.slashmark.maven.data.Epss;
import in.slashmark.maven.data.Kev;
import in.slashmark.maven.data.Osv;
import in.slashmark.maven.model.Gav;
import in.slashmark.maven.resolve.DepNode;
import in.slashmark.maven.util.HttpException;
import in.slashmark.maven.util.Json;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Vulnerability findings for resolved dependencies, enriched with live exploit data (CISA KEV and
 * FIRST EPSS) and a priority:
 *   P1 act now   - known exploited (KEV), or EPSS >= 0.5 with high/critical severity
 *   P2 attend    - EPSS >= 0.1, or critical severity
 *   P3 track     - high or medium severity
 *   P4 defer     - low severity, or only reachable through test/provided scope
 */
public final class Risk {
    private Risk() {}

    public static final class Finding implements Json.JsonWritable {
        public final DepNode node;
        public final Gav gav;
        public final Osv.Vuln vuln;
        public Kev.Entry kev;
        public Epss.Score epss;
        public String fix;
        public String priority;   // P1..P4
        public double score;      // 0..100 for sorting

        public Finding(DepNode node, Gav gav, Osv.Vuln vuln) {
            this.node = node;
            this.gav = gav;
            this.vuln = vuln;
        }

        public String priorityLabel() {
            switch (priority) {
                case "P1": return "act now";
                case "P2": return "attend";
                case "P3": return "track";
                default: return "defer";
            }
        }

        /** Stable key for watch state: advisory @ coordinates. */
        public String key() { return vuln.id + "@" + gav; }

        @Override
        public Object toJson() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("artifact", gav.toString());
            if (node != null) {
                m.put("scope", node.scope);
                m.put("direct", node.depth == 1);
                m.put("path", node.pathString());
            }
            m.put("advisory", vuln.toJson());
            m.put("fixedIn", fix);
            m.put("kev", kev == null ? null : kev.toJson());
            m.put("epss", epss == null ? null : epss.toJson());
            m.put("priority", priority);
            m.put("priorityLabel", priorityLabel());
            m.put("score", Math.round(score * 10) / 10.0);
            return m;
        }
    }

    /**
     * Findings for the given dependency nodes, most urgent first. withExploitData=false skips the KEV
     * and EPSS lookups (OSV only).
     */
    public static List<Finding> assess(Ctx ctx, List<DepNode> nodes, boolean withExploitData) throws HttpException {
        List<Gav> gavs = new ArrayList<>();
        for (DepNode n : nodes) gavs.add(n.gav());
        Map<String, List<Osv.Vuln>> vulns = ctx.vulnerabilities(gavs);
        List<Finding> out = new ArrayList<>();
        Map<String, DepNode> byGav = new LinkedHashMap<>();
        for (DepNode n : nodes) byGav.putIfAbsent(n.gav().toString(), n);
        for (Map.Entry<String, List<Osv.Vuln>> e : vulns.entrySet()) {
            DepNode n = byGav.get(e.getKey());
            Gav g = Gav.parse(e.getKey());
            for (Osv.Vuln v : e.getValue()) {
                Finding f = new Finding(n, g, v);
                f.fix = v.fixFor(g.ga(), g.version);
                out.add(f);
            }
        }
        enrich(ctx, out, withExploitData);
        return out;
    }

    /** Adds KEV/EPSS data and computes priorities (also usable for findings built elsewhere). */
    public static void enrich(Ctx ctx, List<Finding> findings, boolean withExploitData) throws HttpException {
        Map<String, Kev.Entry> kev = new LinkedHashMap<>();
        Map<String, Epss.Score> epss = new LinkedHashMap<>();
        if (withExploitData && !findings.isEmpty()) {
            List<String> cves = new ArrayList<>();
            for (Finding f : findings) for (String c : f.vuln.cves()) if (!cves.contains(c)) cves.add(c);
            try {
                kev = ctx.kev.catalog();
            } catch (HttpException e) {
                ctx.ui.warnErr("CISA KEV unavailable: " + e.getMessage());
            }
            try {
                epss = ctx.epss.scores(cves);
            } catch (HttpException e) {
                ctx.ui.warnErr("EPSS unavailable: " + e.getMessage());
            }
        }
        for (Finding f : findings) {
            for (String c : f.vuln.cves()) {
                if (f.kev == null) f.kev = kev.get(c);
                Epss.Score s = epss.get(c);
                if (s != null && (f.epss == null || s.epss > f.epss.epss)) f.epss = s;
            }
            prioritize(f);
        }
        findings.sort((a, b) -> {
            int c = a.priority.compareTo(b.priority);
            return c != 0 ? c : Double.compare(b.score, a.score);
        });
    }

    static void prioritize(Finding f) {
        String sev = f.vuln.severity == null ? "unknown" : f.vuln.severity;
        double cvss = f.vuln.score >= 0 ? f.vuln.score : sev.equals("critical") ? 9.5 : sev.equals("high") ? 7.5 : sev.equals("medium") ? 5.0 : sev.equals("low") ? 2.5 : 5.0;
        double exploit = f.kev != null ? 1.0 : f.epss != null ? f.epss.epss : 0.0;
        boolean nonShipping = f.node != null && ("test".equals(f.node.scope) || "provided".equals(f.node.scope));
        f.score = 45 * (cvss / 10.0) + 55 * exploit;
        if (f.kev != null && f.kev.ransomware) f.score += 5;
        if (nonShipping) f.score *= 0.4;
        int rank = Cvss.rank(sev);
        if (nonShipping) f.priority = f.kev != null ? "P3" : "P4";
        else if (f.kev != null || (f.epss != null && f.epss.epss >= 0.5 && rank >= 3)) f.priority = "P1";
        else if ((f.epss != null && f.epss.epss >= 0.1) || rank >= 4) f.priority = "P2";
        else if (rank >= 2) f.priority = "P3";
        else f.priority = "P4";
    }
}
