package in.slashmark.maven.tools;

import in.slashmark.maven.cli.Args;
import in.slashmark.maven.cli.Command;
import in.slashmark.maven.cli.Ctx;
import in.slashmark.maven.cli.Exit;
import in.slashmark.maven.cli.Ui;
import in.slashmark.maven.cli.UsageException;
import in.slashmark.maven.watch.Alerts;
import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Alert Hub: Configure and test Slack, Teams, Discord, webhook and e-mail alerts. */
public final class AlertsCmd extends Command {
    @Override public String name() { return "alerts"; }
    @Override public String title() { return "Alert Hub"; }
    @Override public String group() { return "Operations"; }
    @Override public String summary() { return "Configure and test Slack, Teams, Discord, webhook and e-mail alerts"; }

    @Override
    public String help() {
        return String.join("\n",
                "Usage: sm-maven alerts <list|add|remove|route|test|send> [args] [options]",
                "",
                summary() + ".",
                "Channels are used by every watch tool (cve-watch, repo-status --watch, publish-track --wait, ...). They are stored",
                "in alerts.json in the sm-maven config folder (owner-only permissions); SM_MAVEN_SLACK_WEBHOOK, SM_MAVEN_TEAMS_WEBHOOK,",
                "SM_MAVEN_DISCORD_WEBHOOK and SM_MAVEN_WEBHOOK (+ SM_MAVEN_WEBHOOK_SECRET) add channels from the environment (CI secrets).",
                "Webhook URLs, signing secrets and SMTP passwords are never printed.",
                "",
                "Commands:",
                "  list                        Channels with masked secrets (default)",
                "  add <name> --type <type>    Add a channel: slack, teams, discord, webhook, email or file",
                "  remove <name>               Delete a channel",
                "  route <name> <severity>     Only send alerts at or above low|medium|high|critical to it (all = everything)",
                "  test [name ...]             Send a test alert to every channel (or the named ones) and report delivery",
                "  send --title <text>         Send an alert from scripts (honours each channel's minimum severity)",
                "",
                "Options for add:",
                "  --url <url>                 Incoming-webhook URL (slack, teams, discord, webhook)",
                "  --secret <s>                HMAC-SHA256 signing secret for webhook channels (X-SM-Maven-Signature header)",
                "  --secret-env <VAR>          Read the signing secret from an environment variable instead",
                "  --file <path>               Append alerts as JSON lines to this file (type file)",
                "  --host, --port, --tls       SMTP server (port default 587; tls starttls|ssl|none)",
                "  --user, --password          SMTP login (or --password-env <VAR>)",
                "  --from <addr>, --to <list>  Sender and comma-separated recipients (type email)",
                "  --min-severity <level>      Same as route: low, medium, high or critical",
                "  --force                     Replace an existing channel with the same name",
                "",
                "Options for send:",
                "  --title <text>              Alert title (required)",
                "  --severity <level>          info (default), low, medium, high or critical",
                "  --line <text>               A detail line (repeatable)",
                "  --link <url>                Link to more details",
                "  --channel <names>           Only these channels (also for test)",
                "  --source <name>             Tool name shown in the alert (default: script)",
                "",
                "Exit codes: 0 delivered, 1 a delivery failed (or nothing to send to), 2 usage error.",
                "",
                "Examples:",
                "  sm-maven alerts add team-slack --type slack --url https://hooks.slack.com/services/T000/B000/XXXX",
                "  sm-maven alerts add siem --type webhook --url https://siem.example.com/ingest --secret-env SIEM_SECRET --min-severity high",
                "  sm-maven alerts add oncall --type email --host smtp.example.com --user bot --password-env SMTP_PW --from bot@example.com --to ops@example.com",
                "  sm-maven alerts test",
                "  sm-maven alerts send --title 'Deploy blocked by gate' --severity high --line 'see build #42'");
    }

    @Override
    public int run(Ctx ctx, Args args) throws Exception {
        String action = args.pos(0) == null ? "list" : args.pos(0).toLowerCase(Locale.ROOT);
        Alerts alerts = ctx.alerts();
        switch (action) {
            case "list": case "ls": return list(ctx, alerts);
            case "add": return add(ctx, args, alerts);
            case "remove": case "rm": case "delete": return remove(ctx, args, alerts);
            case "route": return route(ctx, args, alerts);
            case "test": return test(ctx, args, alerts);
            case "send": return send(ctx, args, alerts);
            default: throw new UsageException("unknown alerts command '" + args.pos(0) + "' (use list, add, remove, route, test or send)");
        }
    }

    // ---------------------------------------------------------------- list

    static String destination(Alerts.Channel c) {
        switch (c.type == null ? "" : c.type) {
            case "file": return c.file == null ? "—" : c.file;
            case "email": return String.join(", ", c.to) + " via " + (c.host == null ? "?" : c.host + ":" + c.port) + " (" + c.tls + ")";
            default: {
                Object u = c.toJson(true).get("url");
                return u == null ? "—" : String.valueOf(u);
            }
        }
    }

    private int list(Ctx ctx, Alerts alerts) {
        List<Object> chans = new ArrayList<>();
        for (Alerts.Channel c : alerts.channels()) {
            Map<String, Object> m = c.toJson(true);
            m.put("destination", destination(c));
            m.put("signed", c.secret != null);
            chans.add(m);
        }
        if (ctx.ui.json) {
            ctx.ui.emitJson(OpsCommon.m("tool", "alerts", "action", "list", "configFile", alerts.file().toString(), "channels", chans));
            return Exit.OK;
        }
        ctx.ui.title("Alert channels " + ctx.ui.dot() + " " + Ui.plural(alerts.channels().size(), "channel"));
        ctx.ui.note("config: " + alerts.file());
        if (alerts.channels().isEmpty()) {
            ctx.ui.println();
            ctx.ui.warn("No alert channels configured: watch tools only print to the terminal.");
            ctx.ui.line("Add one with: sm-maven alerts add team-slack --type slack --url <incoming-webhook-url>");
            return Exit.OK;
        }
        Ui.Table t = new Ui.Table("Name", "Type", "Destination", "Min severity", "Signed", "Source");
        for (Alerts.Channel c : alerts.channels()) {
            t.row(c.name, c.type, destination(c), c.minSeverity == null ? ctx.ui.dim("all") : c.minSeverity,
                    "webhook".equals(c.type) ? (c.secret != null ? ctx.ui.green("HMAC") : ctx.ui.yellow("no")) : ctx.ui.dim("—"),
                    c.fromEnv ? "environment" : "alerts.json");
        }
        ctx.ui.table(t);
        ctx.ui.note("secrets are masked; test delivery with: sm-maven alerts test");
        return Exit.OK;
    }

    // ---------------------------------------------------------------- add / remove / route

    private static String httpUrl(String option, String v) {
        try {
            URI u = URI.create(v);
            if (u.getHost() != null && ("https".equalsIgnoreCase(u.getScheme()) || "http".equalsIgnoreCase(u.getScheme()))) return v;
        } catch (IllegalArgumentException ignored) {
            // reported below
        }
        throw new UsageException("--" + option + " expects an http(s) URL");
    }

    private static String fromEnv(Ctx ctx, String var) {
        String v = ctx.env.get(var);
        if (v == null) throw new UsageException("environment variable " + var + " is not set");
        return v;
    }

    private int add(Ctx ctx, Args args, Alerts alerts) throws Exception {
        String name = args.pos(1);
        if (name == null) throw new UsageException("alerts add needs a channel name, e.g. sm-maven alerts add team-slack --type slack --url <url>");
        if (!name.matches("[A-Za-z0-9_.\\-]+")) throw new UsageException("channel names may only contain letters, digits, '.', '-' and '_'");
        String type = args.get("type", null);
        if (type == null) throw new UsageException("--type is required: " + String.join(", ", Alerts.TYPES));
        type = type.toLowerCase(Locale.ROOT);
        if (!Alerts.TYPES.contains(type)) throw new UsageException("--type expects one of " + String.join(", ", Alerts.TYPES) + ", got '" + type + "'");
        Alerts.Channel existing = alerts.find(name);
        if (existing != null && existing.fromEnv) throw new UsageException("'" + name + "' comes from the environment; pick another name");
        if (existing != null && !args.flag("force")) throw new UsageException("channel '" + name + "' already exists (use --force to replace it)");

        Alerts.Channel c = new Alerts.Channel();
        c.name = name;
        c.type = type;
        String url = args.get("url", null);
        String secret = args.get("secret", null);
        if (args.get("secret-env") != null) secret = fromEnv(ctx, args.get("secret-env"));
        String file = args.get("path", args.get("file", null));
        switch (type) {
            case "slack": case "teams": case "discord": case "webhook":
                if (url == null) throw new UsageException("--url is required for " + type + " channels");
                c.url = httpUrl("url", url);
                if (secret != null) {
                    if (!type.equals("webhook")) throw new UsageException("--secret is only supported for webhook channels");
                    c.secret = secret;
                }
                if (OpsCommon.insecureHttp(c.url)) ctx.ui.warnErr("the webhook URL uses plain HTTP: alerts (and the URL token) travel unencrypted");
                break;
            case "file":
                if (file == null) throw new UsageException("--file <path> is required for file channels");
                c.file = java.nio.file.Paths.get(file).toAbsolutePath().normalize().toString();
                break;
            case "email": {
                c.host = args.get("host", null);
                c.from = args.get("from", null);
                c.to.addAll(args.getAll("to"));
                if (c.host == null || c.from == null || c.to.isEmpty()) throw new UsageException("email channels need --host, --from and --to");
                c.port = args.getInt("port", 587);
                c.tls = args.get("tls", "starttls").toLowerCase(Locale.ROOT);
                if (!List.of("starttls", "ssl", "none").contains(c.tls)) throw new UsageException("--tls expects starttls, ssl or none");
                c.user = args.get("user", null);
                c.password = args.get("password", null);
                if (args.get("password-env") != null) c.password = fromEnv(ctx, args.get("password-env"));
                if (c.password != null && c.user == null) throw new UsageException("--password needs --user");
                break;
            }
            default: break;
        }
        if (args.get("min-severity") != null) c.minSeverity = minSeverity(args.get("min-severity"));
        if (existing != null) alerts.channels().remove(existing);
        alerts.channels().add(c);
        alerts.save();
        if (ctx.ui.json) {
            ctx.ui.emitJson(OpsCommon.m("tool", "alerts", "action", "add", "replaced", existing != null, "channel", c.toJson(true)));
        } else {
            ctx.ui.good((existing != null ? "Replaced" : "Added") + " " + type + " channel " + ctx.ui.bold(name) + " " + ctx.ui.arrow() + " " + destination(c)
                    + (c.minSeverity == null ? "" : " (" + c.minSeverity + " and above)"));
            ctx.ui.note("send a test alert with: sm-maven alerts test " + name);
        }
        return Exit.OK;
    }

    private static String minSeverity(String v) {
        String s = v.trim().toLowerCase(Locale.ROOT);
        if (s.equals("all") || s.equals("info") || s.equals("none") || s.equals("any")) return null;
        String n = OpsCommon.severityOption("min-severity", s);
        return n.equals("info") ? null : n;
    }

    private Alerts.Channel configured(Alerts alerts, String name, String verb) {
        if (name == null) throw new UsageException("alerts " + verb + " needs a channel name (see: sm-maven alerts list)");
        Alerts.Channel c = alerts.find(name);
        if (c == null) throw new UsageException("no alert channel named '" + name + "' (see: sm-maven alerts list)");
        if (c.fromEnv) throw new UsageException("'" + name + "' is defined by an environment variable; change it there");
        return c;
    }

    private int remove(Ctx ctx, Args args, Alerts alerts) throws Exception {
        Alerts.Channel c = configured(alerts, args.pos(1), "remove");
        alerts.channels().remove(c);
        alerts.save();
        if (ctx.ui.json) ctx.ui.emitJson(OpsCommon.m("tool", "alerts", "action", "remove", "channel", c.name));
        else ctx.ui.good("Removed channel " + ctx.ui.bold(c.name));
        return Exit.OK;
    }

    private int route(Ctx ctx, Args args, Alerts alerts) throws Exception {
        Alerts.Channel c = configured(alerts, args.pos(1), "route");
        String level = args.pos(2) != null ? args.pos(2) : args.get("min-severity", null);
        if (level == null) throw new UsageException("alerts route <name> <low|medium|high|critical|all>");
        c.minSeverity = minSeverity(level);
        alerts.save();
        if (ctx.ui.json) ctx.ui.emitJson(OpsCommon.m("tool", "alerts", "action", "route", "channel", c.name, "minSeverity", c.minSeverity));
        else ctx.ui.good(ctx.ui.bold(c.name) + " now receives " + (c.minSeverity == null ? "every alert" : c.minSeverity + " and above"));
        return Exit.OK;
    }

    // ---------------------------------------------------------------- test / send

    private List<Alerts.Channel> select(Alerts alerts, List<String> names) {
        List<Alerts.Channel> out = new ArrayList<>();
        if (names.isEmpty()) return new ArrayList<>(alerts.channels());
        for (String n : names) {
            Alerts.Channel c = alerts.find(n);
            if (c == null) throw new UsageException("no alert channel named '" + n + "' (see: sm-maven alerts list)");
            if (!out.contains(c)) out.add(c);
        }
        return out;
    }

    private int test(Ctx ctx, Args args, Alerts alerts) {
        List<String> names = new ArrayList<>(args.posFrom(1));
        names.addAll(args.getAll("channel"));
        List<Alerts.Channel> chans = select(alerts, names);
        String base = OpsCommon.severityOption("severity", args.get("severity", "info"));
        if (chans.isEmpty()) {
            if (ctx.ui.json) ctx.ui.emitJson(OpsCommon.m("tool", "alerts", "action", "test", "ok", false, "deliveries", List.of()));
            else ctx.ui.warn("No alert channels configured; add one with: sm-maven alerts add <name> --type slack --url <url>");
            return Exit.ISSUES;
        }
        List<Object> results = new ArrayList<>();
        boolean allOk = true;
        if (!ctx.ui.json) ctx.ui.title("Alert test " + ctx.ui.dot() + " " + Ui.plural(chans.size(), "channel"));
        for (Alerts.Channel c : chans) {
            // A test must reach the channel, so it is sent at the channel's minimum severity when that is higher.
            String sev = c.minSeverity != null && OpsCommon.sevRank(c.minSeverity) > OpsCommon.sevRank(base) ? c.minSeverity : base;
            Alerts.Alert a = new Alerts.Alert("alerts", "Test alert from sm-maven");
            a.severity = sev;
            a.line("This is a test of the '" + c.name + "' " + c.type + " channel.");
            a.line("If you can read this, sm-maven watch tools can reach you.");
            a.line("Sent " + Instant.now().toString().substring(0, 19).replace('T', ' ') + " UTC");
            a.link = "https://slashmark.in";
            a.data = OpsCommon.m("test", true, "channel", c.name);
            long t0 = System.currentTimeMillis();
            List<Alerts.Delivery> ds = alerts.send(a, List.of(c.name));
            long ms = System.currentTimeMillis() - t0;
            Alerts.Delivery d = ds.isEmpty() ? null : ds.get(0);
            boolean ok = d != null && d.ok;
            String err = d == null ? "not delivered (filtered)" : d.error;
            if (!ok) allOk = false;
            results.add(OpsCommon.m("channel", c.name, "type", c.type, "severity", sev, "ok", ok, "error", err, "millis", ms));
            if (!ctx.ui.json) {
                if (ok) ctx.ui.good(ctx.ui.bold(c.name) + " " + ctx.ui.dim("(" + c.type + ")") + " delivered in " + ms + " ms " + ctx.ui.dim(destination(c)));
                else ctx.ui.fail(ctx.ui.bold(c.name) + " " + ctx.ui.dim("(" + c.type + ")") + " failed: " + err);
            }
        }
        if (ctx.ui.json) ctx.ui.emitJson(OpsCommon.m("tool", "alerts", "action", "test", "ok", allOk, "deliveries", results));
        else {
            ctx.ui.println();
            if (allOk) ctx.ui.good("All test alerts delivered");
            else ctx.ui.fail("Some channels could not be reached: check the URL/credentials with sm-maven alerts list");
        }
        return allOk ? Exit.OK : Exit.ISSUES;
    }

    private int send(Ctx ctx, Args args, Alerts alerts) {
        String title = args.get("title", null);
        if (title == null || title.isBlank()) throw new UsageException("alerts send needs --title <text>");
        String sev = OpsCommon.severityOption("severity", args.get("severity", "info"));
        List<String> names = new ArrayList<>(args.getAll("channel"));
        names.addAll(args.posFrom(1));
        List<Alerts.Channel> chans = select(alerts, names);
        Alerts.Alert a = new Alerts.Alert(args.get("source", "script"), title);
        a.severity = sev;
        for (String l : args.getRaw("line")) if (!l.equals("true")) a.line(l);
        String link = args.get("link", null);
        if (link != null) a.link = httpUrl("link", link);
        List<String> only = new ArrayList<>();
        for (Alerts.Channel c : chans) only.add(c.name);
        List<Alerts.Delivery> ds = only.isEmpty() ? List.of() : alerts.send(a, only);
        List<Object> results = new ArrayList<>();
        List<String> skipped = new ArrayList<>();
        boolean allOk = true;
        for (Alerts.Channel c : chans) {
            Alerts.Delivery d = null;
            for (Alerts.Delivery x : ds) if (x.channel.equals(c.name)) d = x;
            if (d == null) {
                skipped.add(c.name);
                results.add(OpsCommon.m("channel", c.name, "type", c.type, "ok", null, "skipped", true, "reason", "below " + c.minSeverity, "error", null));
                continue;
            }
            if (!d.ok) allOk = false;
            results.add(OpsCommon.m("channel", c.name, "type", c.type, "ok", d.ok, "skipped", false, "reason", null, "error", d.error));
        }
        int delivered = 0;
        for (Alerts.Delivery d : ds) if (d.ok) delivered++;
        if (ctx.ui.json) {
            ctx.ui.emitJson(OpsCommon.m("tool", "alerts", "action", "send", "title", title, "severity", sev, "delivered", delivered,
                    "skipped", skipped.size(), "ok", allOk && !chans.isEmpty(), "deliveries", results));
        } else {
            for (Alerts.Delivery d : ds) {
                if (d.ok) ctx.ui.good("sent to " + ctx.ui.bold(d.channel));
                else ctx.ui.fail("failed for " + ctx.ui.bold(d.channel) + ": " + d.error);
            }
            if (!skipped.isEmpty()) ctx.ui.note("skipped (below their minimum severity): " + String.join(", ", skipped));
            if (chans.isEmpty()) ctx.ui.warn("No alert channels configured: nothing was sent");
            else if (delivered == 0 && ds.isEmpty()) ctx.ui.warn("No channel accepts " + sev + " alerts: nothing was sent");
        }
        return allOk && !chans.isEmpty() ? Exit.OK : Exit.ISSUES;
    }
}
