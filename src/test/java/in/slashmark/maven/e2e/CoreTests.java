package in.slashmark.maven.e2e;

/** Basics shared by every tool: help, versions, errors, exit codes. */
public final class CoreTests {
    public static void run(Harness h) {
        Harness.Result r = h.run("help");
        h.check("help lists 25 tools", r.code == 0 && r.out.contains("cve-watch") && r.out.contains("alerts"), r);
        r = h.run("version");
        h.check("version", r.code == 0 && r.out.startsWith("sm-maven 1.0.0"), r);
        r = h.run("cve-wach");
        h.check("unknown tool -> exit 2 with suggestion", r.code == 2 && r.err.contains("did you mean 'cve-watch'"), r);
        r = h.run("graph", "--help");
        h.check("tool --help", r.code == 0 && r.out.contains("sm-maven graph"), r);
    }
}
