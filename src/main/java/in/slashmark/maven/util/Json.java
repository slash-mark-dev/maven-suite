package in.slashmark.maven.util;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal JSON reader/writer. Objects become LinkedHashMap&lt;String,Object&gt;, arrays become
 * ArrayList&lt;Object&gt;, numbers become Long (when integral and in range) or Double.
 */
public final class Json {
    private Json() {}

    // ---------------------------------------------------------------- parsing

    public static Object parse(String text) {
        Parser p = new Parser(text);
        p.ws();
        Object v = p.value();
        p.ws();
        if (p.i < p.s.length()) throw p.err("trailing characters");
        return v;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String text) {
        Object o = parse(text);
        if (!(o instanceof Map)) throw new IllegalArgumentException("JSON: expected an object");
        return (Map<String, Object>) o;
    }

    private static final class Parser {
        final String s;
        int i;

        Parser(String s) { this.s = s; }

        IllegalArgumentException err(String m) {
            int line = 1;
            for (int k = 0; k < Math.min(i, s.length()); k++) if (s.charAt(k) == '\n') line++;
            return new IllegalArgumentException("JSON: " + m + " at line " + line);
        }

        void ws() {
            while (i < s.length()) {
                char c = s.charAt(i);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '﻿') i++;
                else break;
            }
        }

        Object value() {
            if (i >= s.length()) throw err("unexpected end");
            char c = s.charAt(i);
            switch (c) {
                case '{': return object();
                case '[': return array();
                case '"': return string();
                case 't': lit("true"); return Boolean.TRUE;
                case 'f': lit("false"); return Boolean.FALSE;
                case 'n': lit("null"); return null;
                default:
                    if (c == '-' || (c >= '0' && c <= '9')) return number();
                    throw err("unexpected '" + c + "'");
            }
        }

        void lit(String w) {
            if (!s.startsWith(w, i)) throw err("expected " + w);
            i += w.length();
        }

        Map<String, Object> object() {
            Map<String, Object> m = new LinkedHashMap<>();
            i++;
            ws();
            if (i < s.length() && s.charAt(i) == '}') { i++; return m; }
            while (true) {
                ws();
                if (i >= s.length() || s.charAt(i) != '"') throw err("expected key");
                String k = string();
                ws();
                if (i >= s.length() || s.charAt(i) != ':') throw err("expected ':'");
                i++;
                ws();
                m.put(k, value());
                ws();
                if (i >= s.length()) throw err("unterminated object");
                char c = s.charAt(i++);
                if (c == '}') return m;
                if (c != ',') throw err("expected ',' or '}'");
            }
        }

        List<Object> array() {
            List<Object> a = new ArrayList<>();
            i++;
            ws();
            if (i < s.length() && s.charAt(i) == ']') { i++; return a; }
            while (true) {
                ws();
                a.add(value());
                ws();
                if (i >= s.length()) throw err("unterminated array");
                char c = s.charAt(i++);
                if (c == ']') return a;
                if (c != ',') throw err("expected ',' or ']'");
            }
        }

        String string() {
            i++;
            StringBuilder b = new StringBuilder();
            while (true) {
                if (i >= s.length()) throw err("unterminated string");
                char c = s.charAt(i++);
                if (c == '"') return b.toString();
                if (c != '\\') { b.append(c); continue; }
                if (i >= s.length()) throw err("bad escape");
                char e = s.charAt(i++);
                switch (e) {
                    case '"': b.append('"'); break;
                    case '\\': b.append('\\'); break;
                    case '/': b.append('/'); break;
                    case 'b': b.append('\b'); break;
                    case 'f': b.append('\f'); break;
                    case 'n': b.append('\n'); break;
                    case 'r': b.append('\r'); break;
                    case 't': b.append('\t'); break;
                    case 'u':
                        if (i + 4 > s.length()) throw err("bad \\u escape");
                        b.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                        i += 4;
                        break;
                    default: throw err("bad escape \\" + e);
                }
            }
        }

        Object number() {
            int st = i;
            if (s.charAt(i) == '-') i++;
            while (i < s.length() && "0123456789.eE+-".indexOf(s.charAt(i)) >= 0) i++;
            String n = s.substring(st, i);
            try {
                if (n.indexOf('.') < 0 && n.indexOf('e') < 0 && n.indexOf('E') < 0) {
                    if (n.length() < 19) return Long.parseLong(n);
                    BigDecimal bd = new BigDecimal(n);
                    try { return bd.longValueExact(); } catch (ArithmeticException x) { return bd.doubleValue(); }
                }
                return Double.parseDouble(n);
            } catch (NumberFormatException x) {
                throw err("bad number " + n);
            }
        }
    }

    // ---------------------------------------------------------------- writing

    public static String write(Object v) { return write(v, true); }

    public static String write(Object v, boolean pretty) {
        StringBuilder b = new StringBuilder();
        write(b, v, pretty, 0);
        return b.toString();
    }

    @SuppressWarnings("unchecked")
    private static void write(StringBuilder b, Object v, boolean pretty, int ind) {
        if (v == null) { b.append("null"); return; }
        if (v instanceof String) { quote(b, (String) v); return; }
        if (v instanceof Boolean) { b.append(v); return; }
        if (v instanceof Double || v instanceof Float) {
            double d = ((Number) v).doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) { b.append("null"); return; }
            if (d == Math.rint(d) && Math.abs(d) < 1e15) { b.append((long) d); return; }
            b.append(BigDecimal.valueOf(d).stripTrailingZeros().toPlainString());
            return;
        }
        if (v instanceof Number) { b.append(v); return; }
        if (v instanceof JsonWritable) { write(b, ((JsonWritable) v).toJson(), pretty, ind); return; }
        if (v instanceof Map) {
            Map<Object, Object> m = (Map<Object, Object>) v;
            if (m.isEmpty()) { b.append("{}"); return; }
            b.append('{');
            boolean first = true;
            for (Map.Entry<Object, Object> e : m.entrySet()) {
                if (!first) b.append(',');
                first = false;
                if (pretty) nl(b, ind + 1);
                quote(b, String.valueOf(e.getKey()));
                b.append(pretty ? ": " : ":");
                write(b, e.getValue(), pretty, ind + 1);
            }
            if (pretty) nl(b, ind);
            b.append('}');
            return;
        }
        if (v instanceof Collection || v instanceof Object[]) {
            Collection<Object> c = v instanceof Object[] ? List.of((Object[]) v) : (Collection<Object>) v;
            if (c.isEmpty()) { b.append("[]"); return; }
            b.append('[');
            boolean first = true;
            for (Object o : c) {
                if (!first) b.append(',');
                first = false;
                if (pretty) nl(b, ind + 1);
                write(b, o, pretty, ind + 1);
            }
            if (pretty) nl(b, ind);
            b.append(']');
            return;
        }
        if (v instanceof Enum) { quote(b, ((Enum<?>) v).name().toLowerCase()); return; }
        quote(b, v.toString());
    }

    private static void nl(StringBuilder b, int ind) {
        b.append('\n');
        for (int k = 0; k < ind; k++) b.append("  ");
    }

    public static void quote(StringBuilder b, String s) {
        b.append('"');
        for (int k = 0; k < s.length(); k++) {
            char c = s.charAt(k);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                case '\b': b.append("\\b"); break;
                case '\f': b.append("\\f"); break;
                default:
                    if (c < 0x20 || c == ' ' || c == ' ') b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        b.append('"');
    }

    public static String quote(String s) {
        StringBuilder b = new StringBuilder();
        quote(b, s);
        return b.toString();
    }

    // ---------------------------------------------------------------- building + reading helpers

    /** Builds an ordered map from alternating key/value arguments; null values are skipped. */
    public static Map<String, Object> obj(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int k = 0; k + 1 < kv.length; k += 2) if (kv[k + 1] != null) m.put(String.valueOf(kv[k]), kv[k + 1]);
        return m;
    }

    /** Navigates nested maps/lists: get(root, "a", "b", 0, "c"). Returns null on any miss. */
    public static Object get(Object root, Object... path) {
        Object cur = root;
        for (Object p : path) {
            if (cur == null) return null;
            if (p instanceof Integer && cur instanceof List) {
                List<?> l = (List<?>) cur;
                int ix = (Integer) p;
                cur = ix >= 0 && ix < l.size() ? l.get(ix) : null;
            } else if (cur instanceof Map) {
                cur = ((Map<?, ?>) cur).get(String.valueOf(p));
            } else return null;
        }
        return cur;
    }

    public static String str(Object root, Object... path) {
        Object v = get(root, path);
        return v == null ? null : v instanceof String ? (String) v : String.valueOf(v);
    }

    public static long num(Object root, long def, Object... path) {
        Object v = get(root, path);
        if (v instanceof Number) return ((Number) v).longValue();
        if (v instanceof String) try { return Long.parseLong((String) v); } catch (NumberFormatException e) { return def; }
        return def;
    }

    public static double dbl(Object root, double def, Object... path) {
        Object v = get(root, path);
        if (v instanceof Number) return ((Number) v).doubleValue();
        if (v instanceof String) try { return Double.parseDouble((String) v); } catch (NumberFormatException e) { return def; }
        return def;
    }

    public static boolean bool(Object root, boolean def, Object... path) {
        Object v = get(root, path);
        return v instanceof Boolean ? (Boolean) v : def;
    }

    @SuppressWarnings("unchecked")
    public static List<Object> list(Object root, Object... path) {
        Object v = get(root, path);
        return v instanceof List ? (List<Object>) v : new ArrayList<>();
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> map(Object root, Object... path) {
        Object v = get(root, path);
        return v instanceof Map ? (Map<String, Object>) v : new LinkedHashMap<>();
    }

    /** Implemented by result types so they can be emitted with --json. */
    public interface JsonWritable {
        Object toJson();
    }
}
