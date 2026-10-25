package in.slashmark.maven.diff;

import in.slashmark.maven.model.MavenVersion;
import in.slashmark.maven.model.VersionRange;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.apache.maven.artifact.versioning.ComparableVersion;
import org.apache.maven.artifact.versioning.DefaultArtifactVersion;

/**
 * Differential test: our MavenVersion/VersionRange vs Maven's own ComparableVersion/VersionRange
 * (maven-artifact from the local Maven installation). Run with maven-artifact on the classpath.
 */
public class VersionDiff {
    public static void main(String[] a) throws Exception {
        List<String> vs = new ArrayList<>(List.of(
            "1", "1.0", "1.0.0", "1.0.0.0", "1-0", "1.0-0", "1-1", "1.1", "1-sp", "1-sp-1", "1-ga", "1-final", "1-release",
            "1-alpha", "1-alpha1", "1-alpha-1", "1-a1", "1a1", "1-beta", "1-b2", "1b2", "1-milestone", "1-m1", "1m1", "1-rc", "1-rc1",
            "1-cr1", "1-CR1", "1-SNAPSHOT", "1.0-SNAPSHOT", "1-snapshot", "1-xyz", "1-abc", "1-zzz", "1.0.0.RELEASE", "1.0.0.Final",
            "1.0.0.GA", "2.0.0.M1", "2.0.0.RC2", "5.3.0.CR1", "1.0-jre", "33.4.8-jre", "33.4.8-android", "1.0.0-beta.11",
            "1.0.0-alpha.beta", "1.0.0-rc.1", "1.0.0+build.1", "1.0.0-0.3.7", "1.0.0-x.7.z.92", "1.2.3-1", "1.2.3.1",
            "2.17.1", "2.17.0", "2.15.0-rc1", "9.4.51.v20230217", "9.4.51.v20230218", "12.0.0.beta0", "1.7.36", "2.0.0-alpha1",
            "1.0.0-", "1..0", ".1", "1.", "-1", "1--1", "1.0.0-SNAPSHOT-1", "10000000000", "1.10000000000", "1.999999999", "1.1000000000",
            "1.00000000000000000001", "1.123456789012345678901", "3.0-alpha-1", "3.0-alpha-10", "3.0-alpha-2", "1-1.foo-bar1baz-.1",
            "1.0.0.Beta2", "6.0.0.Alpha5", "3.141592653589793", "20030101", "20030101.120000", "r09", "r10", "v1", "v2.0",
            "1.0-a", "1.0-b", "1.0-m", "1.0a", "1.0b", "1.0m", "1.0.a1", "1.0.b1", "1.0-sp1", "1.0.sp1", "1.0-pre1", "1.0-dev",
            "1.0-ea", "17-ea", "21.0.1", "1.8.0_202", "1.0.0-RC.1", "1.0RC1", "1.0rc1", "1.0.RC1", "1.0-RC-1", "0", "0.0", "0.0.1",
            "1.0.0-M1", "1.0.0-M10", "1.0.0-M2", "4.0.0-beta-3", "4.0.0-rc-1", "1.0.0-preview", "2.0.0-alpha.1+exp.sha.5114f85"));
        Random r = new Random(42);
        String[] parts = {"1", "2", "10", "0", "00", "01", "alpha", "beta", "rc", "sp", "ga", "final", "snapshot", "a", "b", "m", "cr", "xyz", "release", "", "SNAPSHOT", "Beta", "999999999999", "1234567890123456789012"};
        String[] seps = {".", "-", "", "_"};
        for (int i = 0; i < 6000; i++) {
            StringBuilder b = new StringBuilder();
            int n = 1 + r.nextInt(5);
            for (int k = 0; k < n; k++) {
                if (k > 0) b.append(seps[r.nextInt(seps.length)]);
                b.append(parts[r.nextInt(parts.length)]);
            }
            vs.add(b.toString());
        }
        long pairs = 0, bad = 0;
        for (int i = 0; i < vs.size(); i++) {
            String x = vs.get(i);
            ComparableVersion cx = new ComparableVersion(x);
            MavenVersion mx = MavenVersion.of(x);
            if (!cx.getCanonical().equals(mx.canonical())) {
                if (bad++ < 15) System.out.println("CANON " + x + " maven=" + cx.getCanonical() + " ours=" + mx.canonical());
            }
            int lim = i < 150 ? vs.size() : 40;
            for (int j = 0; j < lim; j++) {
                String y = vs.get(i < 150 ? j : r.nextInt(vs.size()));
                int e = Integer.signum(cx.compareTo(new ComparableVersion(y)));
                int o = Integer.signum(mx.compareTo(MavenVersion.of(y)));
                pairs++;
                if (e != o && bad++ < 30) System.out.println("CMP " + x + " vs " + y + " maven=" + e + " ours=" + o);
            }
        }
        // Ranges
        String[] specs = {"[1.0,2.0)", "[1.0,2.0]", "(1.0,2.0)", "(,1.0]", "[1.5,)", "[1.0]", "(,1.0],[1.2,)", "[1.0,1.0]", "(,2.0-SNAPSHOT)", "[2.0-alpha,2.0]", "[1,2),[3,4)", "1.0"};
        long rangeChecks = 0;
        for (String s : specs) {
            org.apache.maven.artifact.versioning.VersionRange mr = org.apache.maven.artifact.versioning.VersionRange.createFromVersionSpec(s);
            VersionRange ours = VersionRange.parse(s);
            for (String v : vs.subList(0, 150)) {
                boolean e = mr.containsVersion(new DefaultArtifactVersion(v));
                boolean o = ours.contains(v);
                rangeChecks++;
                if (e != o && bad++ < 50) System.out.println("RANGE " + s + " contains " + v + " maven=" + e + " ours=" + o);
            }
        }
        String[] invalid = {"[1.0,2.0", "(1.0)", "[2.0,1.0]", "[1.0,2.0),[1.5,3.0)", "1.0,2.0", "(1.0,1.0)", "[1.0,2.0)x"};
        for (String s : invalid) {
            boolean mvnFails = false, oursFails = false;
            try { org.apache.maven.artifact.versioning.VersionRange.createFromVersionSpec(s); } catch (Exception e) { mvnFails = true; }
            try { VersionRange.parse(s); } catch (Exception e) { oursFails = true; }
            rangeChecks++;
            if (mvnFails != oursFails && bad++ < 60) System.out.println("INVALID " + s + " maven fails=" + mvnFails + " ours fails=" + oursFails);
        }
        System.out.println("versions=" + vs.size() + " comparisons=" + pairs + " rangeChecks=" + rangeChecks + " mismatches=" + bad);
        if (bad > 0) System.exit(1);
    }
}
