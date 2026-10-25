package in.slashmark.maven.tools;

import in.slashmark.maven.analysis.Risk;
import in.slashmark.maven.cli.Args;
import in.slashmark.maven.cli.Command;
import in.slashmark.maven.cli.Ctx;
import in.slashmark.maven.cli.Exit;
import in.slashmark.maven.cli.Project;
import in.slashmark.maven.cli.Ui;
import in.slashmark.maven.cli.UsageException;
import in.slashmark.maven.data.Cvss;
import in.slashmark.maven.data.Osv;
import in.slashmark.maven.resolve.DepNode;
import in.slashmark.maven.util.HttpException;
import in.slashmark.maven.util.Json;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Exploit Prioritizer: Rank vulnerabilities by real-world exploitation: CISA KEV, EPSS and CVSS. */
public final class Prioritize extends Command {
    @Override public String name() { return "prioritize"; }
    @Override public String title() { return "Exploit Prioritizer"; }
    @Override public String group() { return "Live threat intelligence"; }
    @Override public String summary() { return "Rank vulnerabilities by real-world exploitation: CISA KEV, EPSS and CVSS"; }

    @Override
    public String help() {
        return String.join("\n",
                "Usage: sm-maven prioritize [group:artifact[:version]] [options]",
                "",
                summary() + ".",
                "",
                "Every known vulnerability in the resolved dependencies (and shaded copies) is scored with live",
                "data and placed in a priority band:",
                "  P1 act now  known exploited (CISA KEV), or EPSS >= 50% with high/critical severity",
                "  P2 attend   EPSS >= 10%, or critical severity",
                "  P3 track    high or medium severity",
                "  P4 defer    low severity, or only in test/provided scope",
                "It also prints a fix plan: one upgrade per artifact that clears all of its advisories.",
                "",
                "Options:",
                "  --min-priority <P1-P4>  Only show findings at or above this priority (default P4: all)",
                "  --top <n>               Only show the n most urgent findings",
                "  --min-epss <p>          Only show findings with EPSS >= p (0.1 or 10%) or in CISA KEV",
                "  --scope <scopes>        Only these dependency scopes, e.g. compile,runtime (default: all)",
                "  --no-shaded             Do not inspect JARs for shaded/bundled copies",
                "  --fail-on <P1-P4|none>  Exit 1 when a shown finding is at or above this priority",
                "                          (default: any shown finding)",
                "",
                "Examples:",
                "  sm-maven prioritize",
                "  sm-maven prioritize --min-priority P2 --fail-on P1",
                "  sm-maven prioritize --top 5 --json",
                "  sm-maven prioritize org.springframework:spring-beans:5.3.17");
    }

    @Override public Set<String> flags() { return Set.of("no-shaded"); }

    @Override
    public int run(Ctx ctx, Args args) throws Exception {
        String minPriority = args.get("min-priority") == null ? "P4" : ThreatSupport.priority("min-priority", args.get("min-priority"));
        int top = args.getInt("top", 0);
        if (top < 0) throw new UsageException("--top expects a positive number");
        double minEpss = args.getDouble("min-epss", -1);
        if (minEpss > 1) throw new UsageException("--min-epss expects a probability between 0 and 1 (or a percentage like 10%)");
        Set<String> scopes = ThreatSupport.scopes(args.getAll("scope"));
        String failOnRaw = args.get("fail-on");
        String failOn = failOnRaw == null ? "P4" : "none".equalsIgnoreCase(failOnRaw) ? null : ThreatSupport.priority("fail-on", failOnRaw);
        boolean shadedScan = !args.flag("no-shaded");

        Ctx.Target target = ctx.target(args, 0);
        Project project = target.project;
        List<DepNode> nodes = target.dependencies(scopes);
        List<ThreatSupport.Shaded> shaded = shadedScan ? ThreatSupport.shaded(ctx, nodes) : List.of();
        ctx.osv.setTtl(0);
        List<Risk.Finding> all = ThreatSupport.assess(ctx, nodes, shaded, true);

        Map<String, Integer> counts = new LinkedHashMap<>();
        for (String p : List.of("P1", "P2", "P3", "P4")) counts.put(p, 0);
        for (Risk.Finding f : all) counts.merge(f.priority, 1, Integer::sum);

        List<Risk.Finding> shown = new ArrayList<>();
        for (Risk.Finding f : all) {
            if (f.priority.compareTo(minPriority) > 0) continue;
            if (minEpss >= 0 && f.kev == null && (f.epss == null || f.epss.epss < minEpss)) continue;
            shown.add(f);
        }
        if (top > 0 && shown.size() > top) shown = new ArrayList<>(shown.subList(0, top));

        List<Map<String, Object>> plan = fixPlan(ctx, all, project, target);
        String kevVersion = ctx.kev.version();

        if (ctx.ui.json) {
            List<Object> items = new ArrayList<>();
            int rank = 0;
            for (Risk.Finding f : shown) items.add(findingJson(f, ++rank, target));
            ctx.ui.emitJson(Json.obj("target", target.label, "dependencies", nodes.size(),
                    "sources", Json.obj("osv", true, "kevCatalog", kevVersion, "epssDate", epssDate(all)),
                    "filters", Json.obj("minPriority", minPriority, "top", top > 0 ? top : null, "minEpss", minEpss >= 0 ? minEpss : null,
                            "scopes", scopes == null ? null : new ArrayList<>(scopes)),
                    "counts", counts, "total", all.size(), "shown", shown.size(), "findings", items, "fixPlan", plan));
        } else {
            print(ctx.ui, target, nodes.size(), all.size(), counts, shown, plan, kevVersion, epssDate(all), project);
        }
        if (failOn == null) return Exit.OK;
        for (Risk.Finding f : shown) if (f.priority.compareTo(failOn) <= 0) return Exit.ISSUES;
        return Exit.OK;
    }

    private static String epssDate(List<Risk.Finding> all) {
        for (Risk.Finding f : all) if (f.epss != null && f.epss.date != null) return f.epss.date;
        return null;
    }

    /** Why a finding got its priority, in plain words. */
    static List<String> reasons(Risk.Finding f) {
        List<String> r = new ArrayList<>();
        if (f.kev != null) r.add("in CISA KEV since " + f.kev.dateAdded + (f.kev.ransomware ? " (ransomware)" : ""));
        if (f.epss != null) r.add("EPSS " + ThreatSupport.pct(f.epss.epss) + " (" + ThreatSupport.percentile(f.epss.percentile) + ")");
        if (f.vuln.score >= 0) r.add("CVSS " + String.format(Locale.ROOT, "%.1f", f.vuln.score) + " " + f.vuln.severity);
        else r.add(f.vuln.severity + " severity");
        if (f.node != null && ("test".equals(f.node.scope) || "provided".equals(f.node.scope))) r.add("only in " + f.node.scope + " scope");
        if (ThreatSupport.isShaded(f)) r.add("shaded in " + f.node.gav());
        if (f.fix == null) r.add("no fix released");
        return r;
    }

    @SuppressWarnings("unchecked")
    private static Object findingJson(Risk.Finding f, int rank, Ctx.Target target) {
        Project project = target.project;
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("rank", rank);
        m.putAll((Map<String, Object>) f.toJson());
        m.put("shadedIn", ThreatSupport.isShaded(f) ? f.node.gav().toString() : null);
        if (f.node != null) m.put("direct", ThreatSupport.directSomewhere(target, f.node.ga()));
        List<String> modules = new ArrayList<>();
        if (project != null && f.node != null) for (Project.Module mod : project.modulesUsing(f.node.gav().toString())) modules.add(mod.model.pom.artifactId);
        m.put("modules", modules);
        m.put("reasons", reasons(f));
        return m;
    }

    /** One upgrade per vulnerable artifact (not shaded) that clears all of its advisories. */
    private static List<Map<String, Object>> fixPlan(Ctx ctx, List<Risk.Finding> all, Project project, Ctx.Target target) throws HttpException {
        Map<String, List<Risk.Finding>> byGav = new LinkedHashMap<>();
        for (Risk.Finding f : all) byGav.computeIfAbsent(ThreatSupport.isShaded(f) ? f.gav + " in " + f.node.gav() : f.gav.toString(), k -> new ArrayList<>()).add(f);
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map.Entry<String, List<Risk.Finding>> e : byGav.entrySet()) {
            Risk.Finding first = e.getValue().get(0);
            List<Osv.Vuln> vs = new ArrayList<>();
            List<String> ids = new ArrayList<>();
            for (Risk.Finding f : e.getValue()) {
                vs.add(f.vuln);
                ids.add(f.vuln.displayId());
            }
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("artifact", first.gav.ga());
            m.put("current", first.gav.version);
            boolean shaded = ThreatSupport.isShaded(first);
            m.put("shadedIn", shaded ? first.node.gav().toString() : null);
            m.put("upgradeTo", shaded ? null : ThreatSupport.recommend(ctx, first.gav.ga(), first.gav.version, vs));
            m.put("direct", !shaded && ThreatSupport.directSomewhere(target, first.gav.ga()));
            m.put("topPriority", first.priority);
            m.put("fixes", ids);
            List<String> modules = new ArrayList<>();
            if (project != null && first.node != null) for (Project.Module mod : project.modulesUsing(first.node.gav().toString())) modules.add(mod.model.pom.artifactId);
            m.put("modules", modules);
            out.add(m);
        }
        out.sort((a, b) -> String.valueOf(a.get("topPriority")).compareTo(String.valueOf(b.get("topPriority"))));
        return out;
    }

    private static void print(Ui ui, Ctx.Target target, int deps, int total, Map<String, Integer> counts, List<Risk.Finding> shown,
                              List<Map<String, Object>> plan, String kevVersion, String epssDate, Project project) {
        ui.title("Exploit Prioritizer " + ui.dot() + " " + target.label);
        ui.note(Ui.plural(deps, "dependency", "dependencies") + " " + ui.dot() + " OSV " + ui.dot() + " CISA KEV"
                + (kevVersion == null ? "" : " " + kevVersion) + " " + ui.dot() + " FIRST EPSS" + (epssDate == null ? "" : " " + epssDate));
        if (total == 0) {
            ui.println();
            ui.good("No known vulnerabilities in " + target.label);
            return;
        }
        StringBuilder s = new StringBuilder();
        for (Map.Entry<String, Integer> e : counts.entrySet()) {
            if (s.length() > 0) s.append("   ");
            String label = e.getKey() + " " + e.getValue();
            s.append(e.getValue() == 0 ? ui.dim(label) : e.getKey().equals("P1") ? ui.red(ui.bold(label)) : e.getKey().equals("P2") ? ui.yellow(label) : label);
        }
        ui.line(s.toString());
        String current = null;
        Ui.Table t = null;
        int rank = 0;
        for (Risk.Finding f : shown) {
            if (!f.priority.equals(current)) {
                if (t != null) ui.table(t);
                current = f.priority;
                ui.section(f.priority + " " + ui.dot() + " " + f.priorityLabel() + " (" + counts.get(f.priority) + ")");
                t = new Ui.Table("#", "Advisory", "Severity", "CVSS", "EPSS", "KEV", "Artifact", "Fix", "Why").rightAlign(0, 3, 4);
            }
            String artifact = f.gav.toString() + (ThreatSupport.isShaded(f) ? " (shaded in " + f.node.artifactId + ")" : "");
            if (project != null && f.node != null && f.node.depth > 1) artifact += ui.dim(" via " + f.node.path().get(0).artifactId);
            t.row(++rank, f.vuln.displayId(), ui.severity(f.vuln.severity), f.vuln.score >= 0 ? String.format(Locale.ROOT, "%.1f", f.vuln.score) : "",
                    f.epss == null ? ui.dim("-") : ThreatSupport.pct(f.epss.epss), f.kev == null ? "" : ui.red(f.kev.ransomware ? "yes, ransomware" : "yes"),
                    artifact, f.fix == null ? ui.dim("none") : f.fix, String.join("; ", firstReason(f)));
        }
        if (t != null) ui.table(t);
        if (shown.size() < total) ui.note("  " + (total - shown.size()) + " more not shown (filters); use --min-priority P4 to see everything");

        List<Map<String, Object>> fixable = new ArrayList<>();
        for (Map<String, Object> p : plan) fixable.add(p);
        if (!fixable.isEmpty()) {
            ui.section("Fix plan");
            for (Map<String, Object> p : fixable) {
                @SuppressWarnings("unchecked") List<String> ids = (List<String>) p.get("fixes");
                String fixes = ids.size() + (ids.size() == 1 ? " advisory" : " advisories") + " (" + p.get("topPriority") + ")";
                if (p.get("shadedIn") != null) {
                    ui.line(ui.warnMark() + " " + p.get("artifact") + ":" + p.get("current") + " shaded in " + p.get("shadedIn") + ": " + fixes
                            + ui.dim(" - needs a rebuilt " + p.get("shadedIn") + "; see sm-maven impact " + ids.get(0)));
                } else if (p.get("upgradeTo") == null) {
                    ui.line(ui.bad() + " " + p.get("artifact") + ":" + p.get("current") + ": " + fixes + ui.dim(" - no published release fixes all of them"));
                } else {
                    ui.line(ui.ok() + " " + p.get("artifact") + " " + p.get("current") + " " + ui.arrow() + " " + ui.bold(String.valueOf(p.get("upgradeTo"))) + "  clears " + fixes
                            + (Boolean.TRUE.equals(p.get("direct")) ? "" : ui.dim(" (transitive: pin it in <dependencyManagement>)")));
                }
            }
        }
        ui.println();
    }

    private static List<String> firstReason(Risk.Finding f) {
        List<String> r = reasons(f);
        // The table already shows CVSS/EPSS/KEV; keep the distinctive parts.
        List<String> out = new ArrayList<>();
        for (String x : r) if (!x.startsWith("CVSS") && !x.startsWith("EPSS") && !x.startsWith("in CISA") && !x.startsWith("shaded")) out.add(x);
        if (out.isEmpty()) {
            if (f.kev != null) out.add("exploited in the wild");
            else if (f.epss != null && f.epss.epss >= 0.1) out.add("likely to be exploited");
            else if (Cvss.rank(f.vuln.severity) >= 4) out.add("critical severity");
            else out.add(f.vuln.summary == null ? "" : f.vuln.summary);
        }
        return out;
    }
}
