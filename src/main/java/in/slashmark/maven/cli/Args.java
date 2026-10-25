package in.slashmark.maven.cli;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Command-line arguments: positionals plus options. Options take the forms --name, --name value,
 * --name=value, -x value and repeated options (getAll). Boolean flags are declared per command so
 * "--json pom.xml" is not read as "--json=pom.xml".
 */
public final class Args {
    private final List<String> positionals = new ArrayList<>();
    private final Map<String, List<String>> options = new LinkedHashMap<>();
    private final java.util.Set<String> used = new java.util.HashSet<>();

    /** Flags that never take a value (global ones plus those a command declares). */
    public static final Set<String> GLOBAL_FLAGS = Set.of("json", "no-color", "no-cache", "verbose", "v", "quiet", "q", "help", "h",
            "offline", "ascii", "watch", "once", "all", "fail", "no-fail", "strict", "direct", "include-test", "no-test", "dry-run",
            "verbose-tree", "stable", "pre", "force", "list", "md", "markdown", "sarif", "junit", "html", "stdin", "explain", "fix", "write",
            "deep", "baseline", "reset", "notify", "no-notify", "summary", "transitive", "local", "remote", "ci", "no-local");

    private static final Map<String, String> SHORT = Map.of("v", "verbose", "q", "quiet", "h", "help", "f", "file", "P", "profiles",
            "n", "limit", "o", "output", "s", "settings");

    public static Args parse(String[] argv, Set<String> extraFlags) {
        Args a = new Args();
        boolean onlyPositionals = false;
        for (int i = 0; i < argv.length; i++) {
            String s = argv[i];
            if (onlyPositionals || s.equals("-") || !s.startsWith("-") || s.matches("-\\d.*")) {
                a.positionals.add(s);
                continue;
            }
            if (s.equals("--")) {
                onlyPositionals = true;
                continue;
            }
            String name, value = null;
            if (s.startsWith("--")) {
                name = s.substring(2);
                int eq = name.indexOf('=');
                if (eq >= 0) {
                    value = name.substring(eq + 1);
                    name = name.substring(0, eq);
                }
            } else {
                // -D key=value, -Pprofile, -n10, -v
                String body = s.substring(1);
                if (body.startsWith("D") && body.length() > 1) {
                    a.add("define", body.substring(1));
                    continue;
                }
                if (body.startsWith("P") && body.length() > 1) {
                    a.add("profiles", body.substring(1));
                    continue;
                }
                String key = body.substring(0, 1);
                name = SHORT.getOrDefault(key, key);
                if (body.length() > 1) value = body.substring(1);
            }
            if (name.equals("D")) name = "define";
            boolean flag = GLOBAL_FLAGS.contains(name) || (extraFlags != null && extraFlags.contains(name)) || name.startsWith("no-");
            if (value == null && !flag && i + 1 < argv.length && !(argv[i + 1].startsWith("--") || (argv[i + 1].startsWith("-") && argv[i + 1].length() > 1 && !argv[i + 1].matches("-\\d.*")))) {
                value = argv[++i];
            }
            a.add(name, value == null ? "true" : value);
        }
        return a;
    }

    private void add(String name, String value) { options.computeIfAbsent(name, k -> new ArrayList<>()).add(value); }

    public List<String> positionals() { return positionals; }

    public String pos(int i) { return i < positionals.size() ? positionals.get(i) : null; }

    public List<String> posFrom(int i) { return i < positionals.size() ? positionals.subList(i, positionals.size()) : List.of(); }

    public boolean has(String name) {
        used.add(name);
        return options.containsKey(name);
    }

    public boolean flag(String name) {
        used.add(name);
        List<String> v = options.get(name);
        if (v == null) return false;
        String last = v.get(v.size() - 1);
        return !(last.equalsIgnoreCase("false") || last.equals("0") || last.equalsIgnoreCase("no"));
    }

    public String get(String name) {
        used.add(name);
        List<String> v = options.get(name);
        return v == null ? null : v.get(v.size() - 1);
    }

    /** Value of an option, or def when it is absent or given without a value. */
    public String get(String name, String def) {
        String v = get(name);
        return v == null || v.equals("true") ? def : v;
    }

    /** All values of a repeated option, also splitting comma-separated values. */
    public List<String> getAll(String name) {
        used.add(name);
        List<String> out = new ArrayList<>();
        List<String> v = options.get(name);
        if (v == null) return out;
        for (String s : v) {
            for (String p : splitList(s)) {
                if (!p.equals("true")) out.add(p);
            }
        }
        return out;
    }

    /**
     * Splits a comma-separated list, keeping commas inside version ranges intact:
     * "a:*,g:a:[2.0,2.17.1)" -> ["a:*", "g:a:[2.0,2.17.1)"]. Blank items are dropped.
     */
    public static List<String> splitList(String s) {
        List<String> out = new ArrayList<>();
        if (s == null) return out;
        int depth = 0;
        StringBuilder cur = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (c == '[' || c == '(') depth++;
            else if ((c == ']' || c == ')') && depth > 0) depth--;
            if (c == ',' && depth == 0) {
                if (!cur.toString().isBlank()) out.add(cur.toString().trim());
                cur.setLength(0);
            } else cur.append(c);
        }
        if (!cur.toString().isBlank()) out.add(cur.toString().trim());
        return out;
    }

    /** Values of a repeated option without comma splitting (e.g. -D key=a,b). */
    public List<String> getRaw(String name) {
        used.add(name);
        List<String> v = options.get(name);
        return v == null ? List.of() : v;
    }

    public int getInt(String name, int def) {
        String v = get(name);
        if (v == null || v.equals("true")) return def;
        try {
            return Integer.parseInt(v.trim().replace("_", ""));
        } catch (NumberFormatException e) {
            throw new UsageException("--" + name + " expects a number, got '" + v + "'");
        }
    }

    public double getDouble(String name, double def) {
        String v = get(name);
        if (v == null || v.equals("true")) return def;
        try {
            String t = v.trim();
            if (t.endsWith("%")) return Double.parseDouble(t.substring(0, t.length() - 1)) / 100.0;
            return Double.parseDouble(t);
        } catch (NumberFormatException e) {
            throw new UsageException("--" + name + " expects a number, got '" + v + "'");
        }
    }

    /** Durations like 90s, 15m, 6h, 2d, 1w (bare numbers are seconds). Returns millis. */
    public long getDuration(String name, long defMillis) {
        String v = get(name);
        if (v == null || v.equals("true")) return defMillis;
        return parseDuration(v, name);
    }

    public static long parseDuration(String v, String optionName) {
        String t = v.trim().toLowerCase();
        try {
            long mult = 1000;
            if (t.endsWith("ms")) { mult = 1; t = t.substring(0, t.length() - 2); }
            else if (t.endsWith("s")) { t = t.substring(0, t.length() - 1); }
            else if (t.endsWith("m")) { mult = 60_000; t = t.substring(0, t.length() - 1); }
            else if (t.endsWith("h")) { mult = 3_600_000; t = t.substring(0, t.length() - 1); }
            else if (t.endsWith("d")) { mult = 86_400_000; t = t.substring(0, t.length() - 1); }
            else if (t.endsWith("w")) { mult = 7 * 86_400_000L; t = t.substring(0, t.length() - 1); }
            return (long) (Double.parseDouble(t) * mult);
        } catch (NumberFormatException e) {
            throw new UsageException("--" + optionName + " expects a duration like 30s, 15m, 6h or 7d, got '" + v + "'");
        }
    }

    /** -D key=value definitions. */
    public Map<String, String> defines() {
        Map<String, String> m = new LinkedHashMap<>();
        for (String d : getRaw("define")) {
            int eq = d.indexOf('=');
            if (eq < 0) m.put(d, "true");
            else m.put(d.substring(0, eq), d.substring(eq + 1));
        }
        return m;
    }

    /** Options the command never looked at (to warn about typos). */
    public List<String> unused() {
        List<String> out = new ArrayList<>();
        for (String k : options.keySet()) if (!used.contains(k)) out.add(k);
        return out;
    }

    public Map<String, List<String>> options() { return options; }
}
