package in.slashmark.maven.tools;

import in.slashmark.maven.analysis.Licenses;
import in.slashmark.maven.cli.Ctx;
import in.slashmark.maven.cli.Project;
import in.slashmark.maven.model.Gav;
import in.slashmark.maven.model.ModelBuilder;
import in.slashmark.maven.repo.Metadata;
import in.slashmark.maven.resolve.DepNode;
import in.slashmark.maven.resolve.Graph;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/** Helpers shared by the operations tools (gate, repo-status, publish-track, dashboard, alerts). */
final class OpsCommon {
    private OpsCommon() {}

    /** A map that keeps null values (Json.obj drops them), so JSON field sets stay stable. */
    static Map<String, Object> m(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int k = 0; k + 1 < kv.length; k += 2) m.put(String.valueOf(kv[k]), kv[k + 1]);
        return m;
    }

    static int sevRank(String sev) {
        switch (sev == null ? "" : sev.toLowerCase(Locale.ROOT)) {
            case "critical": return 4;
            case "high": return 3;
            case "medium": case "moderate": return 2;
            case "low": return 1;
            default: return 0;
        }
    }

    static final List<String> SEVERITIES = List.of("info", "low", "medium", "high", "critical");

    /** Normalises a severity option value; throws a usage error for unknown words. */
    static String severityOption(String option, String v) {
        String s = v.trim().toLowerCase(Locale.ROOT);
        if (s.equals("moderate")) s = "medium";
        if (!SEVERITIES.contains(s)) throw new in.slashmark.maven.cli.UsageException("--" + option + " expects one of " + String.join(", ", SEVERITIES) + ", got '" + v + "'");
        return s;
    }

    /** Glob match ("org.apache.*:*", "commons-logging:commons-logging") against g:a or g:a:v. */
    static boolean globMatch(String pattern, String value) {
        StringBuilder re = new StringBuilder();
        for (char c : pattern.trim().toCharArray()) {
            if (c == '*') re.append(".*");
            else if (c == '?') re.append('.');
            else re.append(Pattern.quote(String.valueOf(c)));
        }
        return Pattern.compile(re.toString(), Pattern.CASE_INSENSITIVE).matcher(value).matches();
    }

    /** True when a dependency matches a deny pattern: g, g:a, g:a:v (globs allowed; a version may be a range). */
    static boolean coordinateMatches(String pattern, Gav gav) {
        String p = pattern.trim();
        String[] parts = p.split(":");
        if (parts.length == 1) return globMatch(parts[0], gav.groupId);
        if (parts.length == 2) return globMatch(parts[0], gav.groupId) && globMatch(parts[1], gav.artifactId);
        if (!globMatch(parts[0], gav.groupId) || !globMatch(parts[1], gav.artifactId)) return false;
        String v = p.substring(parts[0].length() + parts[1].length() + 2);
        if (v.startsWith("[") || v.startsWith("(")) {
            try {
                return in.slashmark.maven.model.VersionRange.parse(v).contains(in.slashmark.maven.model.MavenVersion.of(gav.version));
            } catch (RuntimeException e) {
                return false;
            }
        }
        return globMatch(v, gav.version);
    }

    /** Removes user:password@ from a URL before printing it. */
    static String safeUrl(String url) {
        if (url == null) return null;
        try {
            URI u = URI.create(url);
            if (u.getUserInfo() == null) return url;
            return url.replace(u.getRawUserInfo() + "@", "***@");
        } catch (RuntimeException e) {
            return url.replaceAll("//[^/@]+@", "//***@");
        }
    }

    static boolean insecureHttp(String url) {
        if (url == null || !url.toLowerCase(Locale.ROOT).startsWith("http:")) return false;
        String h;
        try { h = URI.create(url).getHost(); } catch (RuntimeException e) { return true; }
        if (h == null) return true;
        h = h.toLowerCase(Locale.ROOT);
        return !(h.equals("localhost") || h.startsWith("127.") || h.equals("[::1]") || h.equals("::1"));
    }

    static String html(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;");
    }

    static String xml(String s) {
        if (s == null) return "";
        StringBuilder b = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '&': b.append("&amp;"); break;
                case '<': b.append("&lt;"); break;
                case '>': b.append("&gt;"); break;
                case '"': b.append("&quot;"); break;
                case '\'': b.append("&apos;"); break;
                default:
                    if (c < 0x20 && c != '\n' && c != '\r' && c != '\t') continue;
                    b.append(c);
            }
        }
        return b.toString();
    }

    /** SPDX license ids per g:a:v (effective POM, parents included). Missing POMs map to an empty list. */
    static Map<String, List<String>> licenses(Ctx ctx, List<Gav> gavs) {
        List<List<String>> res = ctx.http.parallelOrNull(gavs, g -> {
            ModelBuilder.Model m = ctx.models.buildRemote(g);
            return m == null ? List.<String>of() : Licenses.of(m.pom);
        });
        Map<String, List<String>> out = new LinkedHashMap<>();
        for (int i = 0; i < gavs.size(); i++) out.put(gavs.get(i).toString(), res.get(i) == null ? List.of() : res.get(i));
        return out;
    }

    /** Release information of an artifact: newest stable version and when the artifact last published anything. */
    static final class ReleaseInfo {
        String newest;
        long lastRelease;
    }

    static Map<String, ReleaseInfo> releases(Ctx ctx, List<String> gas) {
        List<ReleaseInfo> res = ctx.http.parallelOrNull(gas, ga -> {
            String[] p = ga.split(":");
            Metadata md = ctx.repos.metadata(p[0], p[1]);
            ReleaseInfo ri = new ReleaseInfo();
            if (md == null) return ri;
            ri.newest = md.newest(true);
            ri.lastRelease = md.lastUpdatedMillis();
            if (ri.lastRelease <= 0 && ri.newest != null) {
                in.slashmark.maven.data.CentralSearch.Result r = ctx.search.version(p[0], p[1], ri.newest);
                if (!r.docs.isEmpty()) ri.lastRelease = r.docs.get(0).timestamp;
            }
            return ri;
        });
        Map<String, ReleaseInfo> out = new LinkedHashMap<>();
        for (int i = 0; i < gas.size(); i++) out.put(gas.get(i), res.get(i) == null ? new ReleaseInfo() : res.get(i));
        return out;
    }

    /** Where a dependency comes from in the project: the module pom and the line of the declaring direct dependency. */
    static final class Location {
        final String file;
        final int line;

        Location(String file, int line) {
            this.file = file;
            this.line = line;
        }
    }

    static Location locate(Project project, DepNode node) {
        if (project == null || node == null) return null;
        String gav = node.gav().toString();
        Location fallback = null;
        for (Project.Module m : project.codeModules()) {
            Graph g = m.graph();
            if (g == null) continue;
            String file = m.relPath.equals(".") ? "pom.xml" : m.relPath + "/pom.xml";
            for (DepNode n : g.resolved()) {
                if (!n.gav().toString().equals(gav)) continue;
                List<DepNode> path = n.path();
                DepNode direct = path.isEmpty() ? n : path.get(0);
                Location l = new Location(file, Math.max(direct.declaredLine, 0));
                if (n.isDirect()) return l;
                if (fallback == null) fallback = l;
            }
        }
        return fallback;
    }

    /** Every option value as a list (comma separated or repeated), trimmed. */
    static List<String> list(Object v) {
        List<String> out = new ArrayList<>();
        if (v == null) return out;
        if (v instanceof List) {
            for (Object o : (List<?>) v) if (o != null) out.addAll(list(o));
            return out;
        }
        out.addAll(in.slashmark.maven.cli.Args.splitList(String.valueOf(v)));
        return out;
    }
}
