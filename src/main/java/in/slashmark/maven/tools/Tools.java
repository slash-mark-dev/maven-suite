package in.slashmark.maven.tools;

import in.slashmark.maven.cli.Command;
import java.util.List;

/** Every tool of the suite, in help order. */
public final class Tools {
    private Tools() {}

    public static List<Command> all() {
        return List.of(
                new CveWatch(),
                new Impact(),
                new Prioritize(),
                new ReleaseGuard(),
                new Takeover(),
                new Radar(),
                new Pulse(),
                new BreakCheck(),
                new Adoption(),
                new Relocations(),
                new GraphCmd(),
                new Blast(),
                new Drift(),
                new ResolveCmd(),
                new Classpath(),
                new Simulate(),
                new Safe(),
                new Jdk(),
                new LicenseWatch(),
                new Sbom(),
                new Gate(),
                new RepoStatus(),
                new PublishTrack(),
                new Dashboard(),
                new AlertsCmd());
    }
}
