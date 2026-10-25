package in.slashmark.maven.tools;

import in.slashmark.maven.analysis.Licenses;
import in.slashmark.maven.bytecode.ApiDiff;
import in.slashmark.maven.bytecode.Jar;
import in.slashmark.maven.cli.Ctx;
import in.slashmark.maven.cli.Project;
import in.slashmark.maven.cli.UsageException;
import in.slashmark.maven.model.Gav;
import in.slashmark.maven.model.ModelBuilder;
import in.slashmark.maven.model.Pom;
import in.slashmark.maven.util.HttpException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Helpers shared by the upgrade and compliance tools (simulate, safe, jdk, license-watch, sbom):
 * the project's Java release, what the project's bytecode uses, licenses and class-file levels of
 * published artifacts, API impact of a version change, and pom.xml snippets.
 */
final class UpgradeKit {
    private UpgradeKit() {}

    // ---------------------------------------------------------------- Java release

    /** "1.8" -> 8, "11" -> 11; 0 when it is not a Java release number. */
    static int parseRelease(String s) {
        if (s == null) return 0;
        String t = s.trim();
        if (t.startsWith("1.")) t = t.substring(2);
        try {
            int v = Integer.parseInt(t);
            return v >= 1 && v < 100 ? v : 0;
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    /** Release a module compiles for: maven.compiler.release/target/source or the compiler plugin's configuration. 0 when unknown. */
    static int moduleRelease(ModelBuilder.Model m) {
        Pom p = m.pom;
        for (Pom.Plugin pl : p.plugins) {
            if (!"maven-compiler-plugin".equals(pl.artifactId)) continue;
            for (String k : new String[] {"configuration/release", "configuration/target", "configuration/source"}) {
                int r = parseRelease(pl.configuration.get(k));
                if (r > 0) return r;
            }
        }
        for (String k : new String[] {"maven.compiler.release", "maven.compiler.target", "maven.compiler.source"}) {
            int r = parseRelease(p.properties.get(k));
            if (r > 0) return r;
        }
        return 0;
    }

    /** Lowest release among the project's code modules (the most restrictive one); 0 when unknown. */
    static int projectRelease(Project p) {
        int min = 0;
        for (Project.Module m : p.codeModules()) {
            int r = moduleRelease(m.model);
            if (r > 0 && (min == 0 || r < min)) min = r;
        }
        if (min == 0) min = moduleRelease(p.rootModule().model);
        return min;
    }

    /** --release N, else the project's release, else def. */
    static int release(Ctx ctx, in.slashmark.maven.cli.Args args, Project p, int def) {
        String r = args.get("release");
        if (r != null && !r.equals("true")) {
            int v = parseRelease(r);
            if (v < 6 || v > 40) throw new UsageException("--release expects a Java release like 11, 17 or 21, got '" + r + "'");
            return v;
        }
        int v = p == null ? 0 : projectRelease(p);
        return v > 0 ? v : def;
    }

    static int majorFor(int release) { return release + 44; }

    static String javaOf(int major) { return major <= 0 ? "?" : major < 49 ? "1." + (major - 44) : String.valueOf(major - 44); }

    // ---------------------------------------------------------------- project bytecode

    /** Compiled classes of every code module (target/classes), or an empty list when nothing is compiled. */
    static List<Jar> projectClasses(Project p) throws IOException {
        List<Jar> out = new ArrayList<>();
        for (Project.Module m : p.codeModules()) {
            if (m.classesDir() != null) out.add(Jar.read(m.classesDir()));
        }
        return out;
    }

    // ---------------------------------------------------------------- published artifacts

    /** SPDX ids of a published version (empty when its POM declares none). */
    static List<String> licenses(Ctx ctx, Gav gav) throws HttpException {
        ModelBuilder.Model m = ctx.models.buildRemote(gav);
        return m == null ? List.of() : Licenses.of(m.pom);
    }

    /** Highest class-file major version in a version's JAR (0 when it has no JAR or no classes). */
    static int jarMajor(Ctx ctx, Gav gav) throws HttpException, IOException {
        Jar j = ctx.jar(gav);
        return j == null ? 0 : j.maxClassMajor();
    }

    /** Breaking changes from one version to another that the consumer's bytecode actually hits; null when a JAR is missing. */
    static List<ApiDiff.Impact> impacts(Ctx ctx, Gav from, Gav to, ApiDiff.Usage usage) throws HttpException, IOException {
        Jar a = ctx.jar(from), b = ctx.jar(to);
        if (a == null || b == null) return null;
        ApiDiff.Api oldApi = ApiDiff.Api.of(a), newApi = ApiDiff.Api.of(b);
        return ApiDiff.impacts(ApiDiff.diff(oldApi, newApi), oldApi, usage);
    }

    /** Breaking (binary or source) changes from one version to another regardless of usage; null when a JAR is missing. */
    static List<ApiDiff.Change> breaking(Ctx ctx, Gav from, Gav to) throws HttpException, IOException {
        Jar a = ctx.jar(from), b = ctx.jar(to);
        if (a == null || b == null) return null;
        List<ApiDiff.Change> out = new ArrayList<>();
        for (ApiDiff.Change c : ApiDiff.diff(ApiDiff.Api.of(a), ApiDiff.Api.of(b))) if (!"info".equals(c.level)) out.add(c);
        return out;
    }

    // ---------------------------------------------------------------- formatting

    static String licenseText(List<String> ids) { return ids == null || ids.isEmpty() ? "none declared" : String.join(" OR ", ids); }

    /** A &lt;dependency&gt; element. */
    static String dependencyXml(String groupId, String artifactId, String version, String indent) {
        return indent + "<dependency>\n"
                + indent + "  <groupId>" + groupId + "</groupId>\n"
                + indent + "  <artifactId>" + artifactId + "</artifactId>\n"
                + indent + "  <version>" + version + "</version>\n"
                + indent + "</dependency>";
    }

    /** Package URL for a Maven artifact (https://github.com/package-url/purl-spec). */
    static String purl(String groupId, String artifactId, String version, String type, String classifier) {
        StringBuilder b = new StringBuilder("pkg:maven/").append(pct(groupId)).append('/').append(pct(artifactId));
        if (version != null) b.append('@').append(pct(version));
        List<String> q = new ArrayList<>();
        if (classifier != null && !classifier.isEmpty()) q.add("classifier=" + pct(classifier));
        if (type != null && !type.isEmpty() && !"jar".equals(type)) q.add("type=" + pct(type));
        if (!q.isEmpty()) b.append('?').append(String.join("&", q));
        return b.toString();
    }

    private static String pct(String s) {
        StringBuilder b = new StringBuilder();
        for (byte x : s.getBytes(StandardCharsets.UTF_8)) {
            char c = (char) (x & 0xFF);
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' || c == '~') b.append(c);
            else b.append('%').append(String.format(Locale.ROOT, "%02X", x & 0xFF));
        }
        return b.toString();
    }

    static Map<String, Object> obj(Object... kv) { return in.slashmark.maven.util.Json.obj(kv); }
}
