package in.slashmark.maven.cli;

import java.util.Set;

/**
 * One tool of the suite. Implementations print human output through ctx.ui (which is silent with
 * --json) and emit a single JSON document with ctx.ui.emitJson when --json is set. They return an
 * exit code from {@link Exit}.
 */
public abstract class Command {
    /** Sub-command name, e.g. "cve-watch". */
    public abstract String name();

    /** Display name, e.g. "Live CVE Watch". */
    public abstract String title();

    /** Group heading in the help listing. */
    public abstract String group();

    /** One-line description. */
    public abstract String summary();

    /** Full help text: usage line, options and examples (plain text, no colours). */
    public abstract String help();

    /** Boolean options of this command (so "--flag value" is not read as "--flag=value"). */
    public Set<String> flags() { return Set.of(); }

    /** Other names that also run this command. */
    public Set<String> aliases() { return Set.of(); }

    public abstract int run(Ctx ctx, Args args) throws Exception;

    /** Help lines shared by every command. */
    public static final String COMMON_OPTIONS = String.join("\n",
            "Common options:",
            "  -f, --file <path>      pom.xml or project folder (default: current folder)",
            "  -P, --profiles <ids>   Maven profiles to activate (comma separated, !id to disable)",
            "  -D<key>=<value>        Properties for profile activation and interpolation",
            "  --settings <file>      settings.xml (default ~/.m2/settings.xml) for mirrors and credentials",
            "  --json                 Machine-readable output",
            "  --no-cache             Bypass the response cache",
            "  --no-color, --ascii    Plain output",
            "  -v, --verbose          Show HTTP requests and debug details",
            "  -q, --quiet            Only print results");
}
