package in.slashmark.maven.cli;

import in.slashmark.maven.util.Json;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Terminal output: colours, symbols, tables, sections, and the --json switch. */
public final class Ui {
    private final PrintStream out;
    private final PrintStream err;
    private final boolean color;
    private final boolean unicode;
    public final boolean json;
    public final boolean quiet;
    public final boolean verbose;
    private final boolean tty;

    public Ui(PrintStream out, PrintStream err, boolean color, boolean json, boolean quiet, boolean verbose, boolean ascii) {
        this.out = out;
        this.err = err;
        this.color = color && !json;
        this.json = json;
        this.quiet = quiet;
        this.verbose = verbose;
        this.tty = System.console() != null;
        boolean windows = System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
        this.unicode = !ascii && (!windows || "UTF-8".equalsIgnoreCase(System.getProperty("stdout.encoding", "")));
    }

    public static Ui forStreams(PrintStream out, PrintStream err, boolean json) {
        return new Ui(out, err, false, json, false, false, true);
    }

    public PrintStream out() { return out; }
    public PrintStream err() { return err; }
    public boolean color() { return color; }
    public boolean unicode() { return unicode; }

    // ---------------------------------------------------------------- colours

    private String c(String code, String s) { return color ? "\u001b[" + code + "m" + s + "\u001b[0m" : s; }

    public String bold(String s) { return c("1", s); }
    public String dim(String s) { return c("2", s); }
    public String red(String s) { return c("31", s); }
    public String green(String s) { return c("32", s); }
    public String yellow(String s) { return c("33", s); }
    public String blue(String s) { return c("34", s); }
    public String magenta(String s) { return c("35", s); }
    public String cyan(String s) { return c("36", s); }

    public String ok() { return green(unicode ? "✔" : "OK"); }
    public String bad() { return red(unicode ? "✖" : "X"); }
    public String warnMark() { return yellow(unicode ? "▲" : "!"); }
    public String info() { return cyan(unicode ? "●" : "*"); }
    public String arrow() { return unicode ? "→" : "->"; }
    public String dot() { return unicode ? "·" : "-"; }

    /** Colours a severity word: critical/high red, medium yellow, low blue. */
    public String severity(String sev) {
        if (sev == null) return dim("unknown");
        String s = sev.toLowerCase(Locale.ROOT);
        switch (s) {
            case "critical": return c("1;31", "CRITICAL");
            case "high": return red("HIGH");
            case "medium": case "moderate": return yellow("MEDIUM");
            case "low": return blue("LOW");
            default: return dim(s.toUpperCase(Locale.ROOT));
        }
    }

    // ---------------------------------------------------------------- printing

    public void println(String s) {
        if (!json) out.println(s);
    }

    public void println() { if (!json) out.println(); }

    public void title(String s) {
        if (json || quiet) return;
        out.println(bold(s));
    }

    public void section(String s) {
        if (json) return;
        out.println();
        out.println(bold(cyan(s)));
    }

    public void line(String s) { if (!json) out.println("  " + s); }

    public void good(String s) { if (!json) out.println(ok() + " " + s); }

    public void warn(String s) { if (!json) out.println(warnMark() + " " + s); }

    public void fail(String s) { if (!json) out.println(bad() + " " + s); }

    public void note(String s) { if (!json && !quiet) out.println(dim(s)); }

    /** Progress and diagnostics go to stderr so stdout stays clean for pipes. */
    public void progress(String s) {
        if (!quiet && !json && tty) err.print("\r" + dim(s) + "\u001b[K");
    }

    public void progressDone() { if (!quiet && !json && tty) err.print("\r\u001b[K"); }

    public void debug(String s) { if (verbose) err.println(dim("[debug] " + s)); }

    public void error(String s) { err.println(red((unicode ? "✖ " : "error: ") + s)); }

    public void warnErr(String s) { if (!quiet) err.println(yellow((unicode ? "▲ " : "warning: ") + s)); }

    public void emitJson(Object o) {
        byte[] b = (Json.write(o) + "\n").getBytes(StandardCharsets.UTF_8);
        out.write(b, 0, b.length);
        out.flush();
    }

    // ---------------------------------------------------------------- tables

    public static final class Table {
        private final List<String> headers;
        private final List<List<String>> rows = new ArrayList<>();
        private final boolean[] right;

        public Table(String... headers) {
            this.headers = List.of(headers);
            this.right = new boolean[headers.length];
        }

        public Table rightAlign(int... cols) {
            for (int c : cols) right[c] = true;
            return this;
        }

        public Table row(Object... cells) {
            List<String> r = new ArrayList<>();
            for (Object o : cells) r.add(o == null ? "" : String.valueOf(o));
            while (r.size() < headers.size()) r.add("");
            rows.add(r);
            return this;
        }

        public boolean isEmpty() { return rows.isEmpty(); }
        public int size() { return rows.size(); }
    }

    /** Visible width of a string, ignoring ANSI escapes and counting wide characters as 2. */
    public static int width(String s) {
        int w = 0;
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch == '\u001b') {
                while (i < s.length() && s.charAt(i) != 'm') i++;
                continue;
            }
            if (Character.isHighSurrogate(ch)) { w += 2; i++; continue; }
            if (ch >= 0x1100 && (ch <= 0x115f || (ch >= 0x2e80 && ch <= 0xa4cf) || (ch >= 0xac00 && ch <= 0xd7a3) || (ch >= 0xf900 && ch <= 0xfaff) || (ch >= 0xfe30 && ch <= 0xfe4f) || (ch >= 0xff00 && ch <= 0xff60))) w += 2;
            else w += 1;
        }
        return w;
    }

    private static String pad(String s, int w, boolean right) {
        int d = w - width(s);
        if (d <= 0) return s;
        String sp = " ".repeat(d);
        return right ? sp + s : s + sp;
    }

    public void table(Table t) {
        if (json) return;
        int n = t.headers.size();
        int[] w = new int[n];
        for (int i = 0; i < n; i++) w[i] = width(t.headers.get(i));
        for (List<String> r : t.rows) for (int i = 0; i < n; i++) w[i] = Math.max(w[i], width(r.get(i)));
        // Keep tables within ~160 columns by truncating the widest text column.
        int total = 0;
        for (int x : w) total += x + 2;
        int max = 160;
        String cols = System.getenv("COLUMNS");
        if (cols != null) try { max = Math.max(60, Integer.parseInt(cols.trim())); } catch (NumberFormatException ignored) {}
        if (total > max) {
            int widest = 0;
            for (int i = 1; i < n; i++) if (w[i] > w[widest]) widest = i;
            w[widest] = Math.max(12, w[widest] - (total - max));
        }
        StringBuilder h = new StringBuilder("  ");
        for (int i = 0; i < n; i++) h.append(pad(bold(t.headers.get(i)), w[i], t.right[i])).append(i < n - 1 ? "  " : "");
        out.println(h.toString().stripTrailing());
        StringBuilder sep = new StringBuilder("  ");
        for (int i = 0; i < n; i++) sep.append(dim((unicode ? "─" : "-").repeat(w[i]))).append(i < n - 1 ? "  " : "");
        out.println(sep);
        for (List<String> r : t.rows) {
            StringBuilder b = new StringBuilder("  ");
            for (int i = 0; i < n; i++) {
                String cell = r.get(i);
                if (width(cell) > w[i]) cell = truncate(cell, w[i]);
                b.append(pad(cell, w[i], t.right[i])).append(i < n - 1 ? "  " : "");
            }
            out.println(b.toString().stripTrailing());
        }
    }

    static String truncate(String s, int w) {
        // Strip colour when truncating to keep escapes balanced.
        String plain = s.replaceAll("\u001b\\[[0-9;]*m", "");
        if (plain.length() <= w) return plain;
        return plain.substring(0, Math.max(0, w - 1)) + "…";
    }

    /** Horizontal bar for scores 0..100. */
    public String bar(double value, double max, int width) {
        int filled = (int) Math.round(Math.max(0, Math.min(1, value / max)) * width);
        String full = unicode ? "█" : "#";
        String empty = unicode ? "░" : ".";
        String b = full.repeat(filled) + empty.repeat(width - filled);
        double pct = value / max;
        return pct >= 0.7 ? green(b) : pct >= 0.4 ? yellow(b) : red(b);
    }

    public static String plural(long n, String one, String many) { return n + " " + (n == 1 ? one : many); }

    public static String plural(long n, String word) { return plural(n, word, word + "s"); }

    /** "3 days ago", "in 2 hours". */
    public static String ago(long epochMillis) {
        if (epochMillis <= 0) return "unknown";
        long d = System.currentTimeMillis() - epochMillis;
        boolean future = d < 0;
        d = Math.abs(d);
        String s;
        long sec = d / 1000;
        if (sec < 90) s = sec + "s";
        else if (sec < 5400) s = (sec / 60) + " min";
        else if (sec < 129600) s = (sec / 3600) + " h";
        else if (sec < 86400L * 60) s = (sec / 86400) + " days";
        else if (sec < 86400L * 730) s = (sec / (86400L * 30)) + " months";
        else s = String.format(Locale.ROOT, "%.1f years", sec / (86400.0 * 365));
        return future ? "in " + s : s + " ago";
    }

    public static String date(long epochMillis) {
        if (epochMillis <= 0) return "—";
        return java.time.Instant.ofEpochMilli(epochMillis).toString().substring(0, 10);
    }

    public static String bytes(long b) {
        if (b < 1024) return b + " B";
        if (b < 1024 * 1024) return String.format(Locale.ROOT, "%.1f KB", b / 1024.0);
        if (b < 1024L * 1024 * 1024) return String.format(Locale.ROOT, "%.1f MB", b / 1048576.0);
        return String.format(Locale.ROOT, "%.2f GB", b / 1073741824.0);
    }
}
