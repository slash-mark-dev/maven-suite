package in.slashmark.maven.e2e;

import java.lang.reflect.Method;

/** Runs every end-to-end test group against the mock services. Usage: RunE2E [group...] */
public final class RunE2E {
    static final String[] GROUPS = {"CoreTests", "ThreatTests", "ReleaseTests", "DependencyTests", "UpgradeTests", "OperationsTests"};

    public static void main(String[] args) throws Exception {
        long t0 = System.currentTimeMillis();
        try (Harness h = Harness.start()) {
            for (String g : GROUPS) {
                if (args.length > 0 && !java.util.Arrays.asList(args).contains(g)) continue;
                Class<?> c;
                try {
                    c = Class.forName("in.slashmark.maven.e2e." + g);
                } catch (ClassNotFoundException e) {
                    continue;
                }
                h.group = g;
                System.out.println("== " + g);
                int before = h.passed + h.failed;
                Method m = c.getMethod("run", Harness.class);
                try {
                    m.invoke(null, h);
                } catch (java.lang.reflect.InvocationTargetException e) {
                    h.check("group completed without exception", false, e.getCause());
                    e.getCause().printStackTrace(System.out);
                }
                System.out.println("   " + (h.passed + h.failed - before) + " checks");
            }
            System.out.println();
            for (String f : h.failures) System.out.println("FAILED: " + f + "\n");
            System.out.println("e2e: " + h.passed + " passed, " + h.failed + " failed (" + (System.currentTimeMillis() - t0) / 1000 + "s)");
            System.exit(h.failed == 0 ? 0 : 1);
        }
    }
}
