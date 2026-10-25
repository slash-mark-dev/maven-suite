package in.slashmark.maven.tools;

import in.slashmark.maven.analysis.Risk;
import in.slashmark.maven.cli.Args;
import in.slashmark.maven.cli.Command;
import in.slashmark.maven.cli.Ctx;
import in.slashmark.maven.cli.Project;
import in.slashmark.maven.cli.Ui;
import in.slashmark.maven.data.Cvss;
import in.slashmark.maven.model.Gav;
import in.slashmark.maven.resolve.DepNode;
import in.slashmark.maven.watch.Watcher;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Live CVE Watch: Watch your dependency tree and alert the moment a new advisory affects it. */
public final class CveWatch extends Command {
    @Override public String name() { return "cve-watch"; }
    @Override public String title() { return "Live CVE Watch"; }
    @Override public String group() { return "Live threat intelligence"; }
    @Override public String summary() { return "Watch your dependency tree and alert the moment a new advisory affects it"; }

    @Override
    public String help() {
        return String.join("\n",
                "Usage: sm-maven cve-watch [group:artifact[:version]] [options]",
                "",
                summary() + ".",
                "",
                "Checks every resolved dependency of every module (and copies shaded into fat JARs) against OSV,",
                "enriched with CISA KEV and FIRST EPSS. Advisories are always fetched live. What was seen is",
                "remembered per project, so repeated runs (cron, CI, or --watch) report and alert only NEW ones.",
                "",
                "Options:",
                "  --min-severity <level>  Only watch low, medium, high or critical advisories (default: all)",
                "  --scope <scopes>        Only these dependency scopes, e.g. compile,runtime (default: all)",
                "  --no-shaded             Do not inspect JARs for shaded/bundled copies",
                "  --no-exploit            Skip the CISA KEV and EPSS lookups",
                "",
                Watcher.HELP,
                "  --cycles <n>           Stop after n checks (watch mode)",
                "  --state <file>         Keep the seen-advisory state in this file",
                "",
                "Examples:",
                "  sm-maven cve-watch                          one check, exit 1 when there are new advisories",
                "  sm-maven cve-watch --baseline               accept what is known today, alert on news only",
                "  sm-maven cve-watch --watch --interval 15m --min-severity high",
                "  sm-maven cve-watch org.apache.logging.log4j:log4j-core:2.14.1 --json");
    }

    @Override public Set<String> flags() { return Set.of("no-shaded", "no-exploit"); }

    @Override
    public int run(Ctx ctx, Args args) throws Exception {
        int minSev = ThreatSupport.minSeverity(args.get("min-severity"));
        Set<String> scopes = ThreatSupport.scopes(args.getAll("scope"));
        boolean shaded = !args.flag("no-shaded");
        boolean exploit = !args.flag("no-exploit");
        // Advisory queries are always live: this tool exists to notice new advisories.
        ctx.osv.setTtl(0);

        Ctx.Target target = ctx.target(args, 0);
        Project project = target.project;
        String scope = project != null ? project.rootModule().pom.toString() : target.label;
        int[] depCount = {0};

        Watcher.Cycle cycle = c -> {
            List<DepNode> nodes = target.dependencies(scopes);
            depCount[0] = nodes.size();
            List<ThreatSupport.Shaded> sh = shaded ? ThreatSupport.shaded(ctx, nodes) : List.of();
            List<Risk.Finding> found = ThreatSupport.assess(ctx, nodes, sh, exploit);
            List<Watcher.Finding> out = new ArrayList<>();
            for (Risk.Finding f : found) {
                if (Cvss.rank(f.vuln.severity) < minSev) continue;
                out.add(toFinding(f, target));
            }
            return out;
        };
        Watcher.Printer printer = (all, fresh, c, baseline) -> print(ctx.ui, target, depCount[0], all, fresh, c, baseline);
        return Watcher.run(ctx, args, name(), scope, "vulnerabilities", cycle, printer);
    }

    @SuppressWarnings("unchecked")
    private static Watcher.Finding toFinding(Risk.Finding f, Ctx.Target target) {
        Project project = target.project;
        Map<String, Object> j = new LinkedHashMap<>((Map<String, Object>) f.toJson());
        boolean shaded = ThreatSupport.isShaded(f);
        j.put("shadedIn", shaded ? f.node.gav().toString() : null);
        if (f.node != null) j.put("direct", ThreatSupport.directSomewhere(target, f.node.ga()));
        List<String> modules = new ArrayList<>();
        if (project != null && f.node != null) {
            for (Project.Module m : project.modulesUsing(f.node.gav().toString())) modules.add(m.model.pom.artifactId);
        }
        j.put("modules", modules);
        String id = f.vuln.displayId();
        StringBuilder line = new StringBuilder();
        line.append(id).append(" (").append(f.vuln.severity).append(") in ").append(f.gav);
        if (shaded) line.append(" shaded in ").append(f.node.gav());
        line.append(f.fix != null ? " - fixed in " + f.fix : " - no fix yet");
        if (f.kev != null) line.append(" - KNOWN EXPLOITED");
        else if (f.epss != null && f.epss.epss >= 0.1) line.append(" - EPSS ").append(ThreatSupport.pct(f.epss.epss));
        if (f.vuln.summary != null) line.append(": ").append(f.vuln.summary);
        return new Watcher.Finding(ThreatSupport.key(f), f.vuln.severity, line.toString(), j);
    }

    @SuppressWarnings("unchecked")
    private static void print(Ui ui, Ctx.Target target, int deps, List<Watcher.Finding> all, Set<String> fresh, int cycle, boolean baseline) {
        String when = java.time.Instant.now().toString().substring(11, 19) + " UTC";
        if (cycle == 1) {
            ui.title("Live CVE Watch " + ui.dot() + " " + target.label);
            String mods = target.project != null ? Ui.plural(target.graphs.size(), "module") + ", " : "";
            ui.note(mods + Ui.plural(deps, "dependency", "dependencies") + " checked against OSV, CISA KEV and EPSS");
        }
        ui.section("Check #" + cycle + " at " + when);
        if (all.isEmpty()) {
            ui.good("No known vulnerabilities affect " + target.label);
            return;
        }
        Ui.Table t = new Ui.Table("", "Severity", "Advisory", "Artifact", "Fix", "Priority", "Exploit", "Where");
        List<Watcher.Finding> ordered = new ArrayList<>();
        for (Watcher.Finding f : all) if (fresh.contains(f.key)) ordered.add(f);
        for (Watcher.Finding f : all) if (!fresh.contains(f.key)) ordered.add(f);
        for (Watcher.Finding f : ordered) {
            Map<String, Object> j = (Map<String, Object>) f.json;
            Map<String, Object> adv = (Map<String, Object>) j.get("advisory");
            Object cve = adv.get("cve");
            String id = cve instanceof List && !((List<Object>) cve).isEmpty() ? String.valueOf(((List<Object>) cve).get(0)) : String.valueOf(adv.get("id"));
            String exploit = j.get("kev") != null ? ui.red("KEV") : "";
            Object epss = j.get("epss");
            if (epss instanceof Map) {
                double e = ((Number) ((Map<String, Object>) epss).get("epss")).doubleValue();
                exploit = (exploit.isEmpty() ? "" : exploit + " ") + "EPSS " + ThreatSupport.pct(e);
            }
            String artifact = String.valueOf(j.get("artifact"));
            List<Object> modules = (List<Object>) j.get("modules");
            String where = modules == null || modules.isEmpty() ? String.valueOf(j.getOrDefault("scope", "")) : String.join(",", modules.stream().map(String::valueOf).toList()) + " " + ui.dim(String.valueOf(j.get("scope")));
            if (j.get("shadedIn") != null) where += ", shaded in " + Gav.parse(String.valueOf(j.get("shadedIn"))).artifactId;
            boolean isNew = fresh.contains(f.key) && !baseline;
            t.row(isNew ? ui.yellow("NEW") : "", ui.severity(f.severity), id, artifact, j.get("fixedIn") == null ? ui.dim("none") : j.get("fixedIn"),
                    j.get("priority"), exploit, where);
        }
        ui.table(t);
        ui.println();
        int n = fresh.size();
        if (baseline) {
            ui.good("Baseline recorded: " + Ui.plural(all.size(), "known vulnerability", "known vulnerabilities") + "; future checks alert only on new advisories");
        } else if (n == 0) {
            ui.good("No new advisories since the last check (" + Ui.plural(all.size(), "known vulnerability", "known vulnerabilities") + ")");
        } else {
            ui.fail(Ui.plural(n, "new vulnerability", "new vulnerabilities") + " since the last check (" + all.size() + " in total)");
            ui.note("  Plan the fixes: sm-maven prioritize  " + ui.dot() + "  every affected path: sm-maven impact <CVE>");
        }
    }
}
