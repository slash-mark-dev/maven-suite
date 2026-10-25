package in.slashmark.maven.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Maven version specification: a soft requirement ("1.2.3") or one or more ranges
 * ("[1.0,2.0)", "(,1.0],[1.2,)", "[1.5]"). Semantics follow Maven's VersionRange.
 */
public final class VersionRange {
    public final String spec;
    /** Set for soft requirements such as "1.2.3"; null for pure ranges. */
    public final String recommended;
    public final List<Restriction> restrictions;

    private VersionRange(String spec, String recommended, List<Restriction> r) {
        this.spec = spec;
        this.recommended = recommended;
        this.restrictions = Collections.unmodifiableList(r);
    }

    public boolean isRange() { return recommended == null; }

    public static final class Restriction {
        public final String lower, upper;
        public final boolean lowerInclusive, upperInclusive;

        Restriction(String lower, boolean li, String upper, boolean ui) {
            this.lower = lower;
            this.lowerInclusive = li;
            this.upper = upper;
            this.upperInclusive = ui;
        }

        public boolean contains(MavenVersion v) {
            if (lower != null) {
                int c = MavenVersion.of(lower).compareTo(v);
                if (c > 0 || (c == 0 && !lowerInclusive)) return false;
            }
            if (upper != null) {
                int c = MavenVersion.of(upper).compareTo(v);
                if (c < 0 || (c == 0 && !upperInclusive)) return false;
            }
            return true;
        }

        public boolean isExact() { return lower != null && lower.equals(upper) && lowerInclusive && upperInclusive; }

        @Override
        public String toString() {
            if (isExact()) return "[" + lower + "]";
            return (lowerInclusive ? "[" : "(") + (lower == null ? "" : lower) + "," + (upper == null ? "" : upper) + (upperInclusive ? "]" : ")");
        }
    }

    public static final Restriction EVERYTHING = new Restriction(null, false, null, false);

    public static VersionRange parse(String spec) {
        if (spec == null) throw new IllegalArgumentException("version is null");
        String s = spec.trim();
        if (s.isEmpty()) throw new IllegalArgumentException("empty version");
        if (s.charAt(0) != '[' && s.charAt(0) != '(') {
            return new VersionRange(spec, s, List.of(EVERYTHING));
        }
        List<Restriction> out = new ArrayList<>();
        String rest = s;
        Restriction prev = null;
        while (rest.startsWith("[") || rest.startsWith("(")) {
            int i1 = rest.indexOf(']');
            int i2 = rest.indexOf(')');
            int idx = i1 < 0 ? i2 : i2 < 0 ? i1 : Math.min(i1, i2);
            if (idx < 0) throw new IllegalArgumentException("unbounded range: " + spec);
            Restriction r = restriction(rest.substring(0, idx + 1), spec);
            if (prev != null && prev.upper != null && r.lower != null
                    && MavenVersion.of(r.lower).compareTo(MavenVersion.of(prev.upper)) < 0) {
                throw new IllegalArgumentException("ranges overlap: " + spec);
            }
            out.add(r);
            prev = r;
            rest = rest.substring(idx + 1).trim();
            if (rest.startsWith(",")) rest = rest.substring(1).trim();
        }
        if (!rest.isEmpty()) throw new IllegalArgumentException("only fully-qualified sets allowed in multiple set scenario: " + spec);
        return new VersionRange(spec, null, out);
    }

    private static Restriction restriction(String r, String spec) {
        boolean li = r.charAt(0) == '[';
        boolean ui = r.charAt(r.length() - 1) == ']';
        String inner = r.substring(1, r.length() - 1).trim();
        int comma = inner.indexOf(',');
        if (comma < 0) {
            if (!li || !ui) throw new IllegalArgumentException("single version must be surrounded by []: " + spec);
            if (inner.isEmpty()) throw new IllegalArgumentException("empty range: " + spec);
            return new Restriction(inner, true, inner, true);
        }
        String lo = inner.substring(0, comma).trim();
        String hi = inner.substring(comma + 1).trim();
        if (hi.contains(",")) throw new IllegalArgumentException("invalid range " + r);
        Restriction res = new Restriction(lo.isEmpty() ? null : lo, li, hi.isEmpty() ? null : hi, ui);
        if (res.lower != null && res.upper != null) {
            int c = MavenVersion.of(res.upper).compareTo(MavenVersion.of(res.lower));
            if (c < 0) throw new IllegalArgumentException("range defies version ordering: " + spec);
            if (c == 0 && !(li && ui)) throw new IllegalArgumentException("empty range: " + spec);
        }
        return res;
    }

    /** True if v satisfies the range. A soft requirement contains every version. */
    public boolean contains(String v) { return contains(MavenVersion.of(v)); }

    public boolean contains(MavenVersion v) {
        for (Restriction r : restrictions) if (r.contains(v)) return true;
        return false;
    }

    /** Highest version from the candidates satisfying the range, preferring final releases. */
    public String bestMatch(List<String> candidates, boolean allowPreRelease) {
        if (!isRange()) return recommended;
        String best = null;
        for (String c : candidates) {
            MavenVersion v = MavenVersion.of(c);
            if (!contains(v)) continue;
            if (v.isSnapshot()) continue;
            if (best == null || v.compareTo(MavenVersion.of(best)) > 0) best = c;
        }
        // Maven itself does not exclude pre-releases from ranges; allowPreRelease is kept for callers
        // that want the "stable" interpretation.
        if (!allowPreRelease && best != null && MavenVersion.of(best).isPreRelease()) {
            String stable = null;
            for (String c : candidates) {
                MavenVersion v = MavenVersion.of(c);
                if (!contains(v) || v.isPreRelease()) continue;
                if (stable == null || v.compareTo(MavenVersion.of(stable)) > 0) stable = c;
            }
            if (stable != null) return stable;
        }
        return best;
    }

    @Override
    public String toString() { return spec; }
}
