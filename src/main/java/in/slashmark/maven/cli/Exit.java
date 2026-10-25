package in.slashmark.maven.cli;

/** Exit codes shared by every tool (same as the Composer and NuGet suites). */
public final class Exit {
    private Exit() {}

    /** Nothing to report. */
    public static final int OK = 0;
    /** The tool found issues (vulnerabilities, policy violations, breaking changes...). */
    public static final int ISSUES = 1;
    /** Wrong usage. */
    public static final int USAGE = 2;
    /** Network or runtime error. */
    public static final int ERROR = 3;
}
