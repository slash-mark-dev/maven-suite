package in.slashmark.maven.model;

import java.math.BigInteger;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Maven version ordering, a faithful port of Maven 3.9's ComparableVersion
 * (org.apache.maven.artifact.versioning). Differentially tested against maven-artifact 3.9.11.
 *
 * Ordering of qualifiers: alpha &lt; beta &lt; milestone &lt; rc = cr &lt; snapshot &lt; "" = ga = final = release &lt; sp,
 * with unknown qualifiers after sp in lexical order; a, b, m directly followed by a digit mean alpha, beta, milestone.
 */
public final class MavenVersion implements Comparable<MavenVersion> {
    private final String value;
    private final ListItem items;

    private MavenVersion(String v) {
        this.value = v;
        this.items = parse(v);
    }

    public static MavenVersion of(String v) { return new MavenVersion(v == null ? "" : v); }

    public static int compare(String a, String b) { return of(a).compareTo(of(b)); }

    @Override
    public int compareTo(MavenVersion o) { return items.compareTo(o.items); }

    @Override
    public boolean equals(Object o) { return o instanceof MavenVersion && compareTo((MavenVersion) o) == 0; }

    @Override
    public int hashCode() { return items.toString().hashCode(); }

    @Override
    public String toString() { return value; }

    public String canonical() { return items.toString(); }

    // ---------------------------------------------------------------- classification helpers

    public boolean isSnapshot() { return value.toUpperCase(Locale.ROOT).endsWith("SNAPSHOT"); }

    /**
     * True for alpha/beta/milestone/rc/snapshot/preview/ea/dev style versions. Mirrors what most tools
     * (and humans) treat as "not a final release".
     */
    public boolean isPreRelease() {
        String v = value.toLowerCase(Locale.ROOT);
        if (isSnapshot()) return true;
        return v.matches(".*(?:^|[.\\-_])(?:alpha|beta|milestone|rc|cr|preview|pre|ea|dev|incubating|nightly|canary|m)\\d*(?:[.\\-_].*)?$")
                || v.matches(".*\\d(?:a|b|m)\\d+.*") && !v.matches(".*-?jre.*|.*android.*");
    }

    /** Numeric leading components, e.g. 2.17.1 -> [2,17,1]; 1.0-beta-2 -> [1,0]. */
    public List<Long> numericPrefix() {
        List<Long> out = new ArrayList<>();
        for (String p : value.split("[.\\-_]")) {
            if (p.isEmpty() || !p.chars().allMatch(Character::isDigit)) break;
            try { out.add(Long.parseLong(p.length() > 18 ? p.substring(0, 18) : p)); } catch (NumberFormatException e) { break; }
        }
        return out;
    }

    public long major() { List<Long> n = numericPrefix(); return n.isEmpty() ? -1 : n.get(0); }
    public long minor() { List<Long> n = numericPrefix(); return n.size() < 2 ? 0 : n.get(1); }
    public long patch() { List<Long> n = numericPrefix(); return n.size() < 3 ? 0 : n.get(2); }

    /** "major", "minor", "patch" or "other" describing the jump from this version to newer. */
    public String jumpTo(MavenVersion newer) {
        if (newer.major() != major()) return "major";
        if (newer.minor() != minor()) return "minor";
        if (newer.patch() != patch()) return "patch";
        return "other";
    }

    // ---------------------------------------------------------------- the port

    private interface Item {
        int INT = 3, LONG = 4, BIGINT = 0, STRING = 1, LIST = 2;

        int compareTo(Item o);
        int type();
        boolean isNull();
    }

    private static final class IntItem implements Item {
        static final IntItem ZERO = new IntItem(0);
        final int v;
        IntItem(int v) { this.v = v; }
        IntItem(String s) { this.v = Integer.parseInt(s); }
        public int type() { return INT; }
        public boolean isNull() { return v == 0; }
        public int compareTo(Item o) {
            if (o == null) return v == 0 ? 0 : 1;
            switch (o.type()) {
                case INT: return Integer.compare(v, ((IntItem) o).v);
                case LONG: case BIGINT: return -1;
                case STRING: return 1;
                case LIST: return 1;
                default: throw new IllegalStateException();
            }
        }
        public String toString() { return Integer.toString(v); }
    }

    private static final class LongItem implements Item {
        final long v;
        LongItem(String s) { this.v = Long.parseLong(s); }
        public int type() { return LONG; }
        public boolean isNull() { return v == 0; }
        public int compareTo(Item o) {
            if (o == null) return v == 0 ? 0 : 1;
            switch (o.type()) {
                case INT: return 1;
                case LONG: return Long.compare(v, ((LongItem) o).v);
                case BIGINT: return -1;
                case STRING: return 1;
                case LIST: return 1;
                default: throw new IllegalStateException();
            }
        }
        public String toString() { return Long.toString(v); }
    }

    private static final class BigIntItem implements Item {
        final BigInteger v;
        BigIntItem(String s) { this.v = new BigInteger(s); }
        public int type() { return BIGINT; }
        public boolean isNull() { return BigInteger.ZERO.equals(v); }
        public int compareTo(Item o) {
            if (o == null) return BigInteger.ZERO.equals(v) ? 0 : 1;
            switch (o.type()) {
                case INT: case LONG: return 1;
                case BIGINT: return v.compareTo(((BigIntItem) o).v);
                case STRING: return 1;
                case LIST: return 1;
                default: throw new IllegalStateException();
            }
        }
        public String toString() { return v.toString(); }
    }

    private static final List<String> QUALIFIERS = List.of("alpha", "beta", "milestone", "rc", "snapshot", "", "sp");
    private static final Map<String, String> ALIASES = Map.of("ga", "", "final", "", "release", "", "cr", "rc");
    private static final String RELEASE_INDEX = String.valueOf(QUALIFIERS.indexOf(""));

    private static final class StringItem implements Item {
        final String v;

        StringItem(String v, boolean followedByDigit) {
            if (followedByDigit && v.length() == 1) {
                switch (v.charAt(0)) {
                    case 'a': v = "alpha"; break;
                    case 'b': v = "beta"; break;
                    case 'm': v = "milestone"; break;
                    default: break;
                }
            }
            this.v = ALIASES.getOrDefault(v, v);
        }

        static String comparable(String q) {
            int i = QUALIFIERS.indexOf(q);
            return i == -1 ? QUALIFIERS.size() + "-" + q : String.valueOf(i);
        }

        public int type() { return STRING; }
        public boolean isNull() { return comparable(v).compareTo(RELEASE_INDEX) == 0; }
        public int compareTo(Item o) {
            if (o == null) return comparable(v).compareTo(RELEASE_INDEX);
            switch (o.type()) {
                case INT: case LONG: case BIGINT: return -1;
                case STRING: return comparable(v).compareTo(comparable(((StringItem) o).v));
                case LIST: return -1;
                default: throw new IllegalStateException();
            }
        }
        public String toString() { return v; }
    }

    private static final class ListItem extends ArrayList<Item> implements Item {
        public int type() { return LIST; }
        public boolean isNull() { return isEmpty(); }

        void normalize() {
            for (int i = size() - 1; i >= 0; i--) {
                Item last = get(i);
                if (last.isNull()) remove(i);
                else if (!(last instanceof ListItem)) break;
            }
        }

        public int compareTo(Item o) {
            if (o == null) {
                // Compare every item with null, not just the first (MNG-6964).
                for (Item i : this) {
                    int r = i.compareTo(null);
                    if (r != 0) return r;
                }
                return 0;
            }
            switch (o.type()) {
                case INT: case LONG: case BIGINT: return -1;
                case STRING: return 1;
                case LIST:
                    Iterator<Item> l = iterator();
                    Iterator<Item> r = ((ListItem) o).iterator();
                    while (l.hasNext() || r.hasNext()) {
                        Item li = l.hasNext() ? l.next() : null;
                        Item ri = r.hasNext() ? r.next() : null;
                        int res = li == null ? (ri == null ? 0 : -1 * ri.compareTo(null)) : li.compareTo(ri);
                        if (res != 0) return res;
                    }
                    return 0;
                default: throw new IllegalStateException();
            }
        }

        @Override
        public String toString() {
            StringBuilder b = new StringBuilder();
            for (Item it : this) {
                if (b.length() > 0) b.append(it instanceof ListItem ? '-' : '.');
                b.append(it);
            }
            return b.toString();
        }
    }

    private static Item parseItem(boolean isDigit, String buf) {
        if (isDigit) {
            buf = stripLeadingZeroes(buf);
            if (buf.length() <= 9) return new IntItem(buf);
            if (buf.length() <= 18) return new LongItem(buf);
            return new BigIntItem(buf);
        }
        return new StringItem(buf, false);
    }

    private static String stripLeadingZeroes(String buf) {
        if (buf == null || buf.isEmpty()) return "0";
        for (int i = 0; i < buf.length(); i++) if (buf.charAt(i) != '0') return buf.substring(i);
        return buf;
    }

    private static ListItem parse(String version) {
        ListItem items = new ListItem();
        version = version.toLowerCase(Locale.ENGLISH);
        ListItem list = items;
        Deque<ListItem> stack = new ArrayDeque<>();
        stack.push(list);
        boolean isDigit = false;
        int start = 0;
        for (int i = 0; i < version.length(); i++) {
            char c = version.charAt(i);
            if (c == '.') {
                if (i == start) list.add(IntItem.ZERO);
                else list.add(parseItem(isDigit, version.substring(start, i)));
                start = i + 1;
            } else if (c == '-') {
                if (i == start) list.add(IntItem.ZERO);
                else list.add(parseItem(isDigit, version.substring(start, i)));
                start = i + 1;
                ListItem n = new ListItem();
                list.add(n);
                list = n;
                stack.push(list);
            } else if (Character.isDigit(c)) {
                if (!isDigit && i > start) {
                    if (!list.isEmpty()) {
                        ListItem n = new ListItem();
                        list.add(n);
                        list = n;
                        stack.push(list);
                    }
                    list.add(new StringItem(version.substring(start, i), true));
                    start = i;
                    ListItem n = new ListItem();
                    list.add(n);
                    list = n;
                    stack.push(list);
                }
                isDigit = true;
            } else {
                if (isDigit && i > start) {
                    list.add(parseItem(true, version.substring(start, i)));
                    start = i;
                    ListItem n = new ListItem();
                    list.add(n);
                    list = n;
                    stack.push(list);
                }
                isDigit = false;
            }
        }
        if (version.length() > start) {
            if (!isDigit && !list.isEmpty()) {
                ListItem n = new ListItem();
                list.add(n);
                list = n;
                stack.push(list);
            }
            list.add(parseItem(isDigit, version.substring(start)));
        }
        while (!stack.isEmpty()) stack.pop().normalize();
        return items;
    }
}
