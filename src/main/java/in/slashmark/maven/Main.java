package in.slashmark.maven;

import in.slashmark.maven.cli.Args;
import in.slashmark.maven.cli.Command;
import in.slashmark.maven.cli.Ctx;
import in.slashmark.maven.cli.Exit;
import in.slashmark.maven.cli.Ui;
import in.slashmark.maven.cli.UsageException;
import in.slashmark.maven.tools.Tools;
import in.slashmark.maven.util.Env;
import in.slashmark.maven.util.Http;
import in.slashmark.maven.util.HttpException;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** sm-maven: the Slash Mark Maven Suite command line. */
public final class Main {
    private Main() {}

    public static void main(String[] argv) {
        PrintStream out = new PrintStream(new java.io.FileOutputStream(java.io.FileDescriptor.out), true, StandardCharsets.UTF_8);
        PrintStream err = new PrintStream(new java.io.FileOutputStream(java.io.FileDescriptor.err), true, StandardCharsets.UTF_8);
        int code = run(argv, out, err, Env.system());
        out.flush();
        err.flush();
        System.exit(code);
    }

    /** Entry point used by tests: runs one command and returns its exit code. */
    public static int run(String[] argv, PrintStream out, PrintStream err, Env env) {
        List<Command> commands = Tools.all();
        Map<String, Command> byName = new LinkedHashMap<>();
        for (Command c : commands) {
            byName.put(c.name(), c);
            for (String a : c.aliases()) byName.put(a, c);
        }
        // Find the command: the first argument that is not an option.
        String name = null;
        int idx = -1;
        for (int i = 0; i < argv.length; i++) {
            String a = argv[i];
            if (a.startsWith("-")) {
                // skip values of known value options placed before the command
                if (a.equals("-f") || a.equals("--file") || a.equals("--settings") || a.equals("-s") || a.equals("--jdk")) i++;
                continue;
            }
            name = a;
            idx = i;
            break;
        }
        List<String> rest = new ArrayList<>();
        for (int i = 0; i < argv.length; i++) if (i != idx) rest.add(argv[i]);
        Command cmd = name == null ? null : byName.get(name);
        Set<String> flags = new HashSet<>(cmd == null ? Set.of() : cmd.flags());
        Args args;
        try {
            args = Args.parse(rest.toArray(new String[0]), flags);
        } catch (UsageException e) {
            err.println("error: " + e.getMessage());
            return Exit.USAGE;
        }
        boolean json = args.flag("json");
        boolean color = !args.flag("no-color") && !env.noColor() && System.console() != null;
        Ui ui = new Ui(out, err, color, json, args.flag("quiet"), args.flag("verbose"), args.flag("ascii"));

        if (name == null || name.equals("help")) {
            if (name != null && args.pos(0) != null && byName.containsKey(args.pos(0))) {
                out.println(byName.get(args.pos(0)).help());
                out.println(Command.COMMON_OPTIONS);
                return Exit.OK;
            }
            if (args.flag("version") || args.has("V")) {
                out.println("sm-maven " + Http.VERSION);
                return Exit.OK;
            }
            printHelp(ui, commands);
            return name == null && argv.length > 0 && !args.flag("help") ? Exit.USAGE : Exit.OK;
        }
        if (name.equals("version") || name.equals("--version")) {
            out.println("sm-maven " + Http.VERSION + " (Java " + System.getProperty("java.version") + ")");
            return Exit.OK;
        }
        if (name.equals("cache:clear") || name.equals("cache-clear")) {
            try {
                long n = new Http(env.cacheDir()).clearCache();
                ui.good("Removed " + Ui.plural(n, "cached response") + " from " + env.cacheDir());
                return Exit.OK;
            } catch (IOException e) {
                ui.error(e.getMessage());
                return Exit.ERROR;
            }
        }
        if (cmd == null) {
            err.println("error: unknown tool '" + name + "'" + suggestion(name, byName.keySet()));
            err.println("Run 'sm-maven help' to list the 25 tools.");
            return Exit.USAGE;
        }
        if (args.flag("help")) {
            out.println(cmd.help());
            out.println(Command.COMMON_OPTIONS);
            return Exit.OK;
        }
        try {
            Ctx ctx = new Ctx(env, ui, args);
            int code = cmd.run(ctx, args);
            List<String> unused = args.unused();
            unused.removeAll(List.of("json", "no-color", "no-cache", "verbose", "quiet", "ascii", "file", "profiles", "define", "settings", "jdk", "no-local", "help", "no-test"));
            if (!unused.isEmpty()) ui.warnErr("ignored option" + (unused.size() > 1 ? "s" : "") + " for " + cmd.name() + ": --" + String.join(", --", unused));
            return code;
        } catch (UsageException e) {
            ui.progressDone();
            ui.error(e.getMessage());
            err.println("Usage: run 'sm-maven " + cmd.name() + " --help'");
            return Exit.USAGE;
        } catch (HttpException e) {
            ui.progressDone();
            ui.error(e.getMessage());
            if (e.status == 0) err.println("Check your network or proxy (HTTPS_PROXY), or point SM_MAVEN_* variables at a mirror.");
            if (e.status == 401 || e.status == 403) err.println("The repository needs credentials: add a <server> with the same id to settings.xml.");
            return Exit.ERROR;
        } catch (IOException e) {
            ui.progressDone();
            ui.error(e.getMessage() == null ? e.toString() : e.getMessage());
            return Exit.ERROR;
        } catch (RuntimeException e) {
            ui.progressDone();
            ui.error("internal error: " + e);
            if (args.flag("verbose")) e.printStackTrace(err);
            else err.println("Re-run with --verbose for details, and please report it to mukesh@slashmark.in.");
            return Exit.ERROR;
        } catch (Exception e) {
            ui.progressDone();
            ui.error(e.getMessage() == null ? e.toString() : e.getMessage());
            return Exit.ERROR;
        }
    }

    private static void printHelp(Ui ui, List<Command> commands) {
        PrintStream out = ui.out();
        out.println(ui.bold("Slash Mark Maven Suite") + " " + ui.dim("v" + Http.VERSION));
        out.println("Java Package Intelligence Suite: 25 real-time tools for Maven builds, on live data from");
        out.println("Maven Central, OSV, CISA KEV, FIRST EPSS, deps.dev and GitHub.");
        out.println();
        out.println(ui.bold("Usage:") + " sm-maven <tool> [arguments] [options]");
        String group = null;
        for (Command c : commands) {
            if (!c.group().equals(group)) {
                group = c.group();
                out.println();
                out.println(ui.bold(ui.cyan(group)));
            }
            String n = c.name();
            out.println("  " + ui.green(n) + " ".repeat(Math.max(1, 15 - n.length())) + c.summary());
        }
        out.println();
        out.println("Run " + ui.bold("sm-maven <tool> --help") + " for options and examples.");
        out.println("Other commands: version, cache:clear");
        out.println(ui.dim("Exit codes: 0 ok · 1 issues found · 2 usage error · 3 network/runtime error"));
        out.println(ui.dim("MIT licensed · https://slashmark.in · mukesh@slashmark.in"));
    }

    static String suggestion(String name, Set<String> names) {
        String best = null;
        int bestD = 3;
        for (String n : names) {
            int d = distance(name, n);
            if (d < bestD) {
                bestD = d;
                best = n;
            }
        }
        return best == null ? "" : " (did you mean '" + best + "'?)";
    }

    static int distance(String a, String b) {
        int[] prev = new int[b.length() + 1], cur = new int[b.length() + 1];
        for (int j = 0; j <= b.length(); j++) prev[j] = j;
        for (int i = 1; i <= a.length(); i++) {
            cur[0] = i;
            for (int j = 1; j <= b.length(); j++) {
                cur[j] = Math.min(Math.min(cur[j - 1] + 1, prev[j] + 1), prev[j - 1] + (a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1));
            }
            int[] t = prev;
            prev = cur;
            cur = t;
        }
        return prev[b.length()];
    }
}
