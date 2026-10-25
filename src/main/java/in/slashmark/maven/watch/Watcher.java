package in.slashmark.maven.watch;

import in.slashmark.maven.cli.Args;
import in.slashmark.maven.cli.Ctx;
import in.slashmark.maven.cli.Exit;
import in.slashmark.maven.cli.Ui;
import in.slashmark.maven.util.Json;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Shared engine for the watch tools. Each cycle the tool reports its current findings; the watcher
 * compares them with what it saw before (persisted per project), prints the result, sends alerts for
 * new findings and, with --watch, repeats every --interval.
 *
 * Options it handles: --watch, --interval, --cycles, --baseline, --reset, --notify / --no-notify,
 * --channel (limit alerts to named channels), --state (custom state file).
 */
public final class Watcher {
    private Watcher() {}

    /** One finding. The key identifies it across runs (e.g. "CVE-2021-44228@org.apache.logging.log4j:log4j-core:2.14.1"). */
    public static final class Finding {
        public final String key;
        public final String severity;
        public final String line;
        public final Object json;

        public Finding(String key, String severity, String line, Object json) {
            this.key = key;
            this.severity = severity == null ? "info" : severity;
            this.line = line;
            this.json = json;
        }
    }

    @FunctionalInterface
    public interface Cycle {
        /** Collects the current findings. cycle starts at 1. */
        List<Finding> collect(int cycle) throws Exception;
    }

    @FunctionalInterface
    public interface Printer {
        /** Prints a cycle's result for humans; newKeys marks findings not seen before. */
        void print(List<Finding> all, java.util.Set<String> newKeys, int cycle, boolean baseline);
    }

    public static final String HELP = String.join("\n",
            "Watch options:",
            "  --watch                Keep running and re-check every --interval (Ctrl+C to stop)",
            "  --interval <time>      Time between checks in watch mode: 30s, 15m, 6h (default 15m)",
            "  --baseline             Record the current findings as known without alerting",
            "  --reset                Forget what was seen before (everything counts as new)",
            "  --notify / --no-notify Send alerts for new findings (default: on when channels exist)",
            "  --channel <name>       Only alert these channels (see: sm-maven alerts list)",
            "  --fail-on <new|any|none>  Exit 1 when there are new findings (default), any findings, or never");

    /**
     * Runs the watch loop and returns the exit code.
     *
     * @param tool   tool name (state folder, alert source)
     * @param scope  what is being watched (project path or coordinates) - separates state per project
     * @param what   noun for messages, e.g. "vulnerabilities"
     */
    public static int run(Ctx ctx, Args args, String tool, String scope, String what, Cycle cycle, Printer printer) throws Exception {
        boolean watch = args.flag("watch");
        long interval = args.getDuration("interval", 15 * 60 * 1000L);
        if (interval < 10_000) interval = 10_000;
        int maxCycles = args.getInt("cycles", watch ? Integer.MAX_VALUE : 1);
        String failOn = args.get("fail-on", "new");
        boolean baselineOnly = args.flag("baseline");
        List<String> channels = args.getAll("channel");
        State state = args.get("state") != null ? new State(java.nio.file.Paths.get(args.get("state"))) : ctx.state(tool, scope);
        if (args.flag("reset")) state.reset();
        if (watch) ctx.live(0);

        Alerts alerts = ctx.alerts();
        boolean notify = args.has("notify") ? args.flag("notify") : !args.flag("no-notify") && !alerts.channels().isEmpty();
        Ui ui = ctx.ui;
        int exit = Exit.OK;
        for (int c = 1; c <= maxCycles; c++) {
            List<Finding> findings;
            try {
                findings = cycle.collect(c);
            } catch (Exception e) {
                if (!watch) throw e;
                ui.error("check failed: " + e.getMessage() + " (retrying in " + (interval / 1000) + "s)");
                sleep(interval);
                continue;
            }
            Map<String, Object> seen = state.map("seen");
            boolean firstRun = seen.isEmpty() && !state.exists();
            java.util.Set<String> fresh = new java.util.LinkedHashSet<>();
            long now = System.currentTimeMillis();
            for (Finding f : findings) {
                if (!seen.containsKey(f.key)) {
                    fresh.add(f.key);
                    seen.put(f.key, Instant.ofEpochMilli(now).toString());
                }
            }
            // Findings that disappeared are dropped from state so they alert again if they come back.
            java.util.Set<String> current = new java.util.HashSet<>();
            for (Finding f : findings) current.add(f.key);
            seen.keySet().retainAll(current);
            state.data().put("lastRun", Instant.ofEpochMilli(now).toString());
            state.data().put("scope", scope);
            state.save();

            boolean silent = baselineOnly;
            if (ui.json) {
                List<Object> items = new ArrayList<>();
                for (Finding f : findings) {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("key", f.key);
                    m.put("new", fresh.contains(f.key));
                    m.put("severity", f.severity);
                    m.put("finding", f.json);
                    items.add(m);
                }
                Map<String, Object> doc = Json.obj("tool", tool, "scope", scope, "cycle", c, "checkedAt", Instant.ofEpochMilli(now).toString(),
                        "total", findings.size(), "new", fresh.size(), "baseline", baselineOnly || firstRun ? Boolean.TRUE : null, "findings", items);
                ui.emitJson(doc);
            } else {
                printer.print(findings, fresh, c, baselineOnly);
            }

            if (!fresh.isEmpty() && notify && !silent) {
                Alerts.Alert a = new Alerts.Alert(tool, fresh.size() + " new " + what + " in " + shortScope(scope));
                String top = "info";
                List<Object> data = new ArrayList<>();
                for (Finding f : findings) {
                    if (!fresh.contains(f.key)) continue;
                    if (rank(f.severity) > rank(top)) top = f.severity;
                    if (a.lines.size() < 25) a.line(f.line);
                    data.add(f.json);
                }
                if (fresh.size() > 25) a.line("... and " + (fresh.size() - 25) + " more");
                a.severity = top;
                a.data = data;
                for (Alerts.Delivery d : alerts.send(a, channels)) {
                    if (d.ok) ui.note("  alert sent to " + d.channel);
                    else ui.warnErr("alert to " + d.channel + " failed: " + d.error);
                }
            }
            if ("any".equals(failOn) && !findings.isEmpty()) exit = Exit.ISSUES;
            if ("new".equals(failOn) && !fresh.isEmpty() && !silent) exit = Exit.ISSUES;
            if (c < maxCycles) {
                if (!ui.json) ui.note("next check " + Ui.ago(System.currentTimeMillis() + interval) + " (" + Instant.ofEpochMilli(System.currentTimeMillis() + interval).toString().substring(11, 16) + " UTC)");
                sleep(interval);
            }
        }
        return exit;
    }

    static String shortScope(String scope) {
        if (scope == null) return "project";
        int slash = Math.max(scope.lastIndexOf('/'), scope.lastIndexOf('\\'));
        if (scope.endsWith("pom.xml") && slash > 0) {
            String dir = scope.substring(0, slash);
            int s2 = Math.max(dir.lastIndexOf('/'), dir.lastIndexOf('\\'));
            return s2 >= 0 ? dir.substring(s2 + 1) : dir;
        }
        return scope;
    }

    static int rank(String sev) {
        switch (sev == null ? "" : sev) {
            case "critical": return 4;
            case "high": return 3;
            case "medium": return 2;
            case "low": return 1;
            default: return 0;
        }
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
