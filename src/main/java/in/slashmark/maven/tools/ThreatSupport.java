package in.slashmark.maven.tools;

import in.slashmark.maven.analysis.Risk;
import in.slashmark.maven.bytecode.Jar;
import in.slashmark.maven.cli.Ctx;
import in.slashmark.maven.cli.Ui;
import in.slashmark.maven.cli.UsageException;
import in.slashmark.maven.data.Osv;
import in.slashmark.maven.model.Gav;
import in.slashmark.maven.model.MavenVersion;
import in.slashmark.maven.repo.Repos;
import in.slashmark.maven.resolve.DepNode;
import in.slashmark.maven.util.HttpException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Helpers shared by the live threat intelligence tools (cve-watch, impact, prioritize, release-guard,
 * takeover): shaded-copy detection, fix version selection, OpenPGP signature metadata and option parsing.
 */
final class ThreatSupport {
    private ThreatSupport() {}

    // ---------------------------------------------------------------- shaded copies

    /** A copy of another artifact embedded in a dependency's JAR (detected via META-INF/maven pom.properties). */
    static final class Shaded {
        final DepNode host;
        final Gav embedded;

        Shaded(DepNode host, Gav embedded) {
            this.host = host;
            this.embedded = embedded;
        }
    }

    /** Embedded (shaded/bundled) artifacts in the JARs of the given nodes. JARs that cannot be read are skipped. */
    static List<Shaded> shaded(Ctx ctx, List<DepNode> nodes) {
        List<DepNode> jars = new ArrayList<>();
        for (DepNode n : nodes) if (!"pom".equals(n.type)) jars.add(n);
        if (jars.isEmpty()) return new ArrayList<>();
        ctx.ui.progress("Inspecting " + Ui.plural(jars.size(), "JAR") + " for shaded copies...");
        List<Jar> opened = ctx.http.parallelOrNull(jars, n -> ctx.jar(n.gav()));
        ctx.ui.progressDone();
        List<Shaded> out = new ArrayList<>();
        for (int i = 0; i < jars.size(); i++) {
            Jar j = opened.get(i);
            if (j == null) continue;
            DepNode host = jars.get(i);
            for (String e : j.embeddedMavenArtifacts()) {
                Gav g;
                try {
                    g = Gav.parse(e);
                } catch (IllegalArgumentException ex) {
                    continue;
                }
                if (g.version == null || g.ga().equals(host.ga())) continue;
                out.add(new Shaded(host, g));
            }
        }
        return out;
    }

    /**
     * Vulnerability findings for dependency nodes plus shaded copies, enriched with KEV/EPSS and
     * prioritised (one OSV batch for everything). Shaded findings carry the host node.
     */
    static List<Risk.Finding> assess(Ctx ctx, List<DepNode> nodes, List<Shaded> shaded, boolean exploitData) throws HttpException {
        List<Gav> gavs = new ArrayList<>();
        for (DepNode n : nodes) gavs.add(n.gav());
        for (Shaded s : shaded) gavs.add(s.embedded);
        Map<String, List<Osv.Vuln>> vulns = ctx.vulnerabilities(gavs);
        List<Risk.Finding> out = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (DepNode n : nodes) {
            for (Osv.Vuln v : vulns.getOrDefault(n.gav().toString(), List.of())) {
                if (!seen.add(v.id + "@" + n.gav())) continue;
                Risk.Finding f = new Risk.Finding(n, n.gav(), v);
                f.fix = v.fixFor(n.ga(), n.version);
                out.add(f);
            }
        }
        for (Shaded s : shaded) {
            for (Osv.Vuln v : vulns.getOrDefault(s.embedded.toString(), List.of())) {
                if (!seen.add(v.id + "@" + s.embedded + "#" + s.host.gav())) continue;
                Risk.Finding f = new Risk.Finding(s.host, s.embedded, v);
                f.fix = v.fixFor(s.embedded.ga(), s.embedded.version);
                out.add(f);
            }
        }
        Risk.enrich(ctx, out, exploitData);
        return out;
    }

    /** True when the finding is about a copy embedded in another artifact rather than the dependency itself. */
    static boolean isShaded(Risk.Finding f) { return f.node != null && !f.node.ga().equals(f.gav.ga()); }

    /** Watch/state key for a finding. */
    static String key(Risk.Finding f) { return isShaded(f) ? f.key() + "#shaded-in:" + f.node.gav() : f.key(); }

    // ---------------------------------------------------------------- fix versions

    /** "jre" for 31.1-jre, null for 2.17.1: the build flavour a replacement version should keep. */
    static String flavor(String version) {
        if (version == null) return null;
        int i = version.lastIndexOf('-');
        if (i < 0) return null;
        String q = version.substring(i + 1).toLowerCase(Locale.ROOT);
        return q.matches("[a-z]+[0-9]*") && !MavenVersion.of(version).isPreRelease() ? q : null;
    }

    /**
     * Smallest published release above current that none of the advisories affect (and that is at or
     * above each advisory's fixed version), preferring the same flavour (e.g. -jre). Null when none exists.
     */
    static String recommend(Ctx ctx, String ga, String current, List<Osv.Vuln> vulns) throws HttpException {
        String[] p = ga.split(":");
        List<String> versions = ctx.versions(p[0], p[1], !MavenVersion.of(current).isPreRelease());
        String fl = flavor(current);
        String any = null;
        for (String v : versions) {
            if (MavenVersion.compare(v, current) <= 0) continue;
            boolean ok = true;
            for (Osv.Vuln vu : vulns) {
                String fix = vu.fixFor(ga, current);
                if (vu.affects(ga, v) || (fix != null && MavenVersion.compare(v, fix) < 0)) {
                    ok = false;
                    break;
                }
            }
            if (!ok) continue;
            if (any == null) any = v;
            if (fl == null || fl.equals(flavor(v))) return v;
        }
        return any;
    }

    // ---------------------------------------------------------------- options

    static final List<String> SEVERITIES = List.of("low", "medium", "high", "critical");

    /** --min-severity value as a rank (0 = everything). */
    static int minSeverity(String v) {
        if (v == null) return 0;
        String s = v.trim().toLowerCase(Locale.ROOT);
        if (s.equals("moderate")) s = "medium";
        int i = SEVERITIES.indexOf(s);
        if (i < 0) throw new UsageException("--min-severity expects low, medium, high or critical, got '" + v + "'");
        return i + 1;
    }

    /** Scopes from --scope (null = all). */
    static Set<String> scopes(List<String> raw) {
        if (raw.isEmpty()) return null;
        Set<String> out = new LinkedHashSet<>();
        for (String s : raw) {
            String t = s.toLowerCase(Locale.ROOT);
            if (!List.of("compile", "runtime", "provided", "test", "system").contains(t)) {
                throw new UsageException("--scope expects compile, runtime, provided, test or system, got '" + s + "'");
            }
            out.add(t);
        }
        return out;
    }

    /** P1..P4 from an option value (accepts "1" or "p2"). */
    static String priority(String option, String v) {
        String t = v.trim().toUpperCase(Locale.ROOT);
        if (t.matches("[1-4]")) t = "P" + t;
        if (!t.matches("P[1-4]")) throw new UsageException("--" + option + " expects P1, P2, P3 or P4, got '" + v + "'");
        return t;
    }

    static String pct(double d) {
        double p = d * 100;
        return p >= 10 ? String.format(Locale.ROOT, "%.0f%%", p) : p >= 1 ? String.format(Locale.ROOT, "%.1f%%", p) : String.format(Locale.ROOT, "%.2f%%", p);
    }

    /** EPSS percentile (0..1) as "73rd percentile". */
    static String percentile(double p) {
        long n = Math.min(100, Math.round(p * 100));
        String suffix = (n % 100 >= 11 && n % 100 <= 13) ? "th" : n % 10 == 1 ? "st" : n % 10 == 2 ? "nd" : n % 10 == 3 ? "rd" : "th";
        return n + suffix + " percentile";
    }

    /** True when some module of the project (or the artifact target) declares g:a directly. */
    static boolean directSomewhere(Ctx.Target target, String ga) {
        for (in.slashmark.maven.resolve.Graph g : target.graphs) {
            for (DepNode n : g.direct) if (n.selected && n.ga().equals(ga)) return true;
        }
        return false;
    }

    // ---------------------------------------------------------------- OpenPGP signatures

    /** Issuer of a detached OpenPGP signature: 16-hex key id and (v4) 40-hex fingerprint. */
    static final class Signer {
        String keyId, fingerprint;
        long created;
    }

    /** Signer of an artifact file (.jar, or .pom when there is no JAR); null when unsigned. */
    static Signer signer(Ctx ctx, Gav gav, boolean hasJar) throws HttpException {
        Repos.Fetched f = ctx.repos.fetch(gav, null, (hasJar ? "jar" : "pom") + ".asc");
        if (f == null) return null;
        return parseSignature(new String(f.data, StandardCharsets.US_ASCII));
    }

    /** Parses an ASCII-armored (or binary) signature packet; null when it is not a signature. */
    static Signer parseSignature(String armored) {
        byte[] data;
        try {
            data = dearmor(armored);
        } catch (IllegalArgumentException e) {
            return null;
        }
        if (data == null || data.length < 2) return null;
        int i = 0;
        int tagByte = data[i++] & 0xFF;
        if ((tagByte & 0x80) == 0) return null;
        int tag;
        long len;
        if ((tagByte & 0x40) != 0) {
            tag = tagByte & 0x3F;
            int b0 = data[i++] & 0xFF;
            if (b0 < 192) len = b0;
            else if (b0 < 224) len = ((b0 - 192) << 8) + (data[i++] & 0xFF) + 192;
            else if (b0 == 255) {
                len = ((long) (data[i] & 0xFF) << 24) | ((data[i + 1] & 0xFF) << 16) | ((data[i + 2] & 0xFF) << 8) | (data[i + 3] & 0xFF);
                i += 4;
            } else return null;
        } else {
            tag = (tagByte >> 2) & 0x0F;
            int lt = tagByte & 0x03;
            if (lt == 0) len = data[i++] & 0xFF;
            else if (lt == 1) { len = ((data[i] & 0xFF) << 8) | (data[i + 1] & 0xFF); i += 2; }
            else if (lt == 2) {
                len = ((long) (data[i] & 0xFF) << 24) | ((data[i + 1] & 0xFF) << 16) | ((data[i + 2] & 0xFF) << 8) | (data[i + 3] & 0xFF);
                i += 4;
            } else len = data.length - i;
        }
        if (tag != 2 || i + len > data.length) return null;
        Signer s = new Signer();
        int ver = data[i] & 0xFF;
        if (ver == 3) {
            // v3: version, hashed length 5, type, creation time (4), key id (8)
            int p = i + 3;
            s.created = (((long) (data[p] & 0xFF) << 24) | ((data[p + 1] & 0xFF) << 16) | ((data[p + 2] & 0xFF) << 8) | (data[p + 3] & 0xFF)) * 1000L;
            s.keyId = hex(data, p + 4, 8);
            return s;
        }
        if (ver != 4 && ver != 5) return null;
        int p = i + 4;
        for (int area = 0; area < 2; area++) {
            if (p + 2 > data.length) break;
            int alen = ((data[p] & 0xFF) << 8) | (data[p + 1] & 0xFF);
            p += 2;
            int end = Math.min(data.length, p + alen);
            while (p < end) {
                int l0 = data[p++] & 0xFF;
                int sl;
                if (l0 < 192) sl = l0;
                else if (l0 < 255) { sl = ((l0 - 192) << 8) + (data[p++] & 0xFF) + 192; }
                else { sl = ((data[p] & 0xFF) << 24) | ((data[p + 1] & 0xFF) << 16) | ((data[p + 2] & 0xFF) << 8) | (data[p + 3] & 0xFF); p += 4; }
                if (sl <= 0 || p + sl > end) break;
                int type = data[p] & 0x7F;
                if (type == 2 && sl >= 5) {
                    s.created = (((long) (data[p + 1] & 0xFF) << 24) | ((data[p + 2] & 0xFF) << 16) | ((data[p + 3] & 0xFF) << 8) | (data[p + 4] & 0xFF)) * 1000L;
                } else if (type == 16 && sl >= 9) {
                    s.keyId = hex(data, p + 1, 8);
                } else if (type == 33 && sl >= 22) {
                    int fpLen = sl - 2;
                    s.fingerprint = hex(data, p + 2, fpLen);
                }
                p += sl;
            }
            p = end;
        }
        if (s.keyId == null && s.fingerprint != null && s.fingerprint.length() >= 16) s.keyId = s.fingerprint.substring(s.fingerprint.length() - 16);
        return s.keyId == null && s.fingerprint == null ? null : s;
    }

    private static byte[] dearmor(String text) {
        if (!text.contains("-----BEGIN PGP")) return text.getBytes(StandardCharsets.ISO_8859_1);
        StringBuilder b64 = new StringBuilder();
        boolean body = false, headers = true;
        for (String line : text.split("\r?\n")) {
            String t = line.trim();
            if (t.startsWith("-----BEGIN PGP")) { body = true; headers = true; continue; }
            if (!body) continue;
            if (t.startsWith("-----END PGP")) break;
            if (headers) {
                if (t.isEmpty()) headers = false;
                else if (!t.contains(":")) { headers = false; b64.append(t); }
                continue;
            }
            if (t.startsWith("=")) break; // CRC-24 checksum
            b64.append(t);
        }
        return Base64.getDecoder().decode(b64.toString());
    }

    private static String hex(byte[] b, int off, int len) {
        StringBuilder s = new StringBuilder();
        for (int i = off; i < off + len && i < b.length; i++) s.append(String.format(Locale.ROOT, "%02X", b[i] & 0xFF));
        return s.toString();
    }

    // ---------------------------------------------------------------- misc

    static Map<String, Object> map() { return new LinkedHashMap<>(); }

    static String days(long millis) {
        double d = millis / 86_400_000.0;
        return d < 2 ? String.format(Locale.ROOT, "%.0f h", millis / 3_600_000.0) : String.format(Locale.ROOT, "%.0f days", d);
    }
}
