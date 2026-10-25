package in.slashmark.maven.mock;

import in.slashmark.maven.util.Hash;
import in.slashmark.maven.util.Json;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;

/**
 * Builds a realistic local Maven repository for the end-to-end tests: real coordinates (log4j,
 * jackson, spring, guava, mysql...) with tiny compiled JARs, POMs, checksums, PGP signature files,
 * maven-metadata.xml and release timestamps, plus Acme libraries designed to exercise every tool
 * (API breaks, a suspicious agent release, a shaded vulnerable JAR, relicensing, relocations...).
 */
public final class Fixtures {
    public static final long DAY = 86_400_000L;
    public final Path repo;
    public final long now = System.currentTimeMillis();
    /** g:a:v -> publish time. */
    public final Map<String, Long> published = new LinkedHashMap<>();
    /** g:a:v -> SPDX license id. */
    public final Map<String, String> licenses = new LinkedHashMap<>();
    /** g:a:v -> PGP key id used to sign it. */
    public final Map<String, String> signers = new LinkedHashMap<>();
    /** g:a -> versions in publish order. */
    public final Map<String, List<String>> versions = new LinkedHashMap<>();
    /** g:a:v -> github "owner/repo". */
    public final Map<String, String> scm = new LinkedHashMap<>();
    private final Path work;

    public Fixtures(Path root) throws IOException {
        this.repo = root.resolve("repo");
        this.work = root.resolve("work");
        Files.createDirectories(repo);
        Files.createDirectories(work);
    }

    /** A library version to publish. */
    public static final class Lib {
        final String g, a, v;
        int daysAgo = 400;
        final List<String> deps = new ArrayList<>();
        final List<String> managed = new ArrayList<>();
        final Map<String, String> sources = new LinkedHashMap<>();
        final Map<String, byte[]> extra = new LinkedHashMap<>();
        final Map<String, String> manifest = new LinkedHashMap<>();
        String license = "Apache-2.0";
        String github;
        String parent;
        String relocation;
        String packaging = "jar";
        String key = "A1B2C3D4E5F60718";
        String pomExtra = "";
        boolean noJar, noAsc, noSources;
        List<String> classpath = new ArrayList<>();

        Lib(String gav) {
            String[] p = gav.split(":");
            g = p[0];
            a = p[1];
            v = p[2];
        }

        public Lib days(int d) { daysAgo = d; return this; }
        public Lib dep(String... d) { deps.addAll(List.of(d)); return this; }
        public Lib manage(String... d) { managed.addAll(List.of(d)); return this; }
        public Lib src(String cls, String code) { sources.put(cls, code); return this; }
        public Lib file(String path, byte[] data) { extra.put(path, data); return this; }
        public Lib mf(String k, String val) { manifest.put(k, val); return this; }
        public Lib license(String l) { license = l; return this; }
        public Lib github(String r) { github = r; return this; }
        public Lib parent(String p) { parent = p; return this; }
        public Lib relocate(String to) { relocation = to; return this; }
        public Lib pom() { packaging = "pom"; noJar = true; return this; }
        public Lib key(String k) { key = k; return this; }
        public Lib cp(String gav) { classpath.add(gav); return this; }
        public Lib xml(String s) { pomExtra += s; return this; }
    }

    public Lib lib(String gav) { return new Lib(gav); }

    private static final Map<String, String> LICENSE_NAMES = Map.of(
            "Apache-2.0", "Apache License, Version 2.0|https://www.apache.org/licenses/LICENSE-2.0.txt",
            "MIT", "MIT License|https://opensource.org/licenses/MIT",
            "BUSL-1.1", "Business Source License 1.1|https://mariadb.com/bsl11/",
            "GPL-3.0-only", "GNU General Public License v3.0|https://www.gnu.org/licenses/gpl-3.0.txt",
            "GPL-2.0-with-classpath-exception", "GPL2 w/ CPE|https://openjdk.org/legal/gplv2+ce.html",
            "EPL-2.0", "Eclipse Public License 2.0|https://www.eclipse.org/legal/epl-2.0/",
            "BSD-3-Clause", "BSD 3-Clause|https://opensource.org/licenses/BSD-3-Clause",
            "CDDL-1.1", "CDDL 1.1|https://github.com/javaee/javax.annotation/blob/master/LICENSE",
            "AGPL-3.0-only", "GNU Affero General Public License v3|https://www.gnu.org/licenses/agpl-3.0.txt");

    public void publish(Lib l) throws IOException {
        String gav = l.g + ":" + l.a + ":" + l.v;
        Path dir = repo.resolve(l.g.replace('.', '/')).resolve(l.a).resolve(l.v);
        Files.createDirectories(dir);
        String base = l.a + "-" + l.v;
        // POM
        StringBuilder pom = new StringBuilder();
        pom.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n  <modelVersion>4.0.0</modelVersion>\n");
        if (l.parent != null) {
            String[] p = l.parent.split(":");
            pom.append("  <parent><groupId>").append(p[0]).append("</groupId><artifactId>").append(p[1]).append("</artifactId><version>").append(p[2]).append("</version><relativePath/></parent>\n");
        }
        pom.append("  <groupId>").append(l.g).append("</groupId>\n  <artifactId>").append(l.a).append("</artifactId>\n  <version>").append(l.v).append("</version>\n");
        pom.append("  <packaging>").append(l.packaging).append("</packaging>\n  <name>").append(l.a).append("</name>\n");
        if (l.github != null) {
            pom.append("  <url>https://github.com/").append(l.github).append("</url>\n");
            pom.append("  <scm><url>https://github.com/").append(l.github).append("</url><connection>scm:git:https://github.com/").append(l.github).append(".git</connection></scm>\n");
            scm.put(gav, l.github);
        }
        if (l.license != null) {
            String[] ln = LICENSE_NAMES.getOrDefault(l.license, l.license + "|").split("\\|", -1);
            pom.append("  <licenses><license><name>").append(ln[0]).append("</name>").append(ln[1].isEmpty() ? "" : "<url>" + ln[1] + "</url>").append("</license></licenses>\n");
            licenses.put(gav, l.license);
        }
        if (l.relocation != null) {
            String[] r = l.relocation.split(":");
            pom.append("  <distributionManagement><relocation><groupId>").append(r[0]).append("</groupId><artifactId>").append(r[1]).append("</artifactId>")
                    .append(r.length > 2 ? "<version>" + r[2] + "</version>" : "").append("<message>moved</message></relocation></distributionManagement>\n");
        }
        if (!l.managed.isEmpty()) {
            pom.append("  <dependencyManagement><dependencies>\n");
            for (String d : l.managed) pom.append(depXml(d));
            pom.append("  </dependencies></dependencyManagement>\n");
        }
        if (!l.deps.isEmpty()) {
            pom.append("  <dependencies>\n");
            for (String d : l.deps) pom.append(depXml(d));
            pom.append("  </dependencies>\n");
        }
        pom.append(l.pomExtra);
        pom.append("</project>\n");
        byte[] pomBytes = pom.toString().getBytes(StandardCharsets.UTF_8);
        write(dir.resolve(base + ".pom"), pomBytes, l, true);
        if (!l.noJar) {
            byte[] jar = buildJar(l, pomBytes);
            write(dir.resolve(base + ".jar"), jar, l, true);
            if (!l.noSources) write(dir.resolve(base + "-sources.jar"), buildZip(Map.of("README.txt", ("sources of " + gav).getBytes(StandardCharsets.UTF_8))), l, true);
            write(dir.resolve(base + "-javadoc.jar"), buildZip(Map.of("index.html", ("<html>" + gav + "</html>").getBytes(StandardCharsets.UTF_8))), l, true);
        }
        long when = now - (long) l.daysAgo * DAY;
        published.put(gav, when);
        signers.put(gav, l.key);
        versions.computeIfAbsent(l.g + ":" + l.a, k -> new ArrayList<>());
        if (!versions.get(l.g + ":" + l.a).contains(l.v)) versions.get(l.g + ":" + l.a).add(l.v);
        writeMetadata(l.g, l.a);
        // Keep file times consistent with the publish date (repository listings show them).
        for (Path f : Files.list(dir).toList()) Files.setLastModifiedTime(f, java.nio.file.attribute.FileTime.fromMillis(when));
    }

    static String depXml(String d) {
        // g:a:v[:scope][:optional][:type][!excl-g:excl-a]
        String excl = null;
        int bang = d.indexOf('!');
        if (bang > 0) {
            excl = d.substring(bang + 1);
            d = d.substring(0, bang);
        }
        String[] p = d.split(":");
        StringBuilder b = new StringBuilder("    <dependency><groupId>").append(p[0]).append("</groupId><artifactId>").append(p[1]).append("</artifactId>");
        if (p.length > 2 && !p[2].isEmpty()) b.append("<version>").append(p[2]).append("</version>");
        for (int i = 3; i < p.length; i++) {
            if (p[i].equals("optional")) b.append("<optional>true</optional>");
            else if (p[i].equals("pom")) b.append("<type>pom</type>");
            else if (!p[i].isEmpty()) b.append("<scope>").append(p[i]).append("</scope>");
        }
        if (excl != null) {
            String[] e = excl.split(":");
            b.append("<exclusions><exclusion><groupId>").append(e[0]).append("</groupId><artifactId>").append(e[1]).append("</artifactId></exclusion></exclusions>");
        }
        return b.append("</dependency>\n").toString();
    }

    private void write(Path f, byte[] data, Lib l, boolean sign) throws IOException {
        Files.write(f, data);
        Files.writeString(f.resolveSibling(f.getFileName() + ".sha1"), Hash.sha1Hex(data));
        Files.writeString(f.resolveSibling(f.getFileName() + ".md5"), Hash.md5Hex(data));
        Files.writeString(f.resolveSibling(f.getFileName() + ".sha256"), Hash.sha256Hex(data));
        if (sign && !l.noAsc) Files.writeString(f.resolveSibling(f.getFileName() + ".asc"), Pgp.armoredSignature(l.key, data, now - (long) l.daysAgo * DAY));
    }

    public void writeMetadata(String g, String a) throws IOException {
        List<String> vs = versions.get(g + ":" + a);
        Path dir = repo.resolve(g.replace('.', '/')).resolve(a);
        String latest = vs.get(vs.size() - 1);
        long last = 0;
        for (String v : vs) last = Math.max(last, published.getOrDefault(g + ":" + a + ":" + v, 0L));
        String release = null;
        for (String v : vs) if (!v.endsWith("SNAPSHOT")) release = v;
        String ts = java.time.format.DateTimeFormatter.ofPattern("yyyyMMddHHmmss").withZone(java.time.ZoneOffset.UTC).format(java.time.Instant.ofEpochMilli(last));
        StringBuilder m = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<metadata>\n  <groupId>" + g + "</groupId>\n  <artifactId>" + a + "</artifactId>\n  <versioning>\n");
        m.append("    <latest>").append(latest).append("</latest>\n");
        if (release != null) m.append("    <release>").append(release).append("</release>\n");
        m.append("    <versions>\n");
        for (String v : vs) m.append("      <version>").append(v).append("</version>\n");
        m.append("    </versions>\n    <lastUpdated>").append(ts).append("</lastUpdated>\n  </versioning>\n</metadata>\n");
        byte[] b = m.toString().getBytes(StandardCharsets.UTF_8);
        Files.write(dir.resolve("maven-metadata.xml"), b);
        Files.writeString(dir.resolve("maven-metadata.xml.sha1"), Hash.sha1Hex(b));
    }

    // ---------------------------------------------------------------- jars

    private byte[] buildJar(Lib l, byte[] pom) throws IOException {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        if (!l.sources.isEmpty()) entries.putAll(compile(l));
        entries.putAll(l.extra);
        String props = "groupId=" + l.g + "\nartifactId=" + l.a + "\nversion=" + l.v + "\n";
        entries.put("META-INF/maven/" + l.g + "/" + l.a + "/pom.properties", props.getBytes(StandardCharsets.UTF_8));
        entries.put("META-INF/maven/" + l.g + "/" + l.a + "/pom.xml", pom);
        Manifest mf = new Manifest();
        mf.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        mf.getMainAttributes().putValue("Implementation-Title", l.a);
        mf.getMainAttributes().putValue("Implementation-Version", l.v);
        for (Map.Entry<String, String> e : l.manifest.entrySet()) mf.getMainAttributes().putValue(e.getKey(), e.getValue());
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        try (JarOutputStream jo = new JarOutputStream(bo, mf)) {
            for (Map.Entry<String, byte[]> e : entries.entrySet()) {
                JarEntry je = new JarEntry(e.getKey());
                je.setTime(315532800000L);
                jo.putNextEntry(je);
                jo.write(e.getValue());
                jo.closeEntry();
            }
        }
        return bo.toByteArray();
    }

    static byte[] buildZip(Map<String, byte[]> entries) throws IOException {
        ByteArrayOutputStream bo = new ByteArrayOutputStream();
        try (java.util.zip.ZipOutputStream zo = new java.util.zip.ZipOutputStream(bo)) {
            for (Map.Entry<String, byte[]> e : entries.entrySet()) {
                zo.putNextEntry(new java.util.zip.ZipEntry(e.getKey()));
                zo.write(e.getValue());
                zo.closeEntry();
            }
        }
        return bo.toByteArray();
    }

    /** Compiles the library's sources (release 8 unless the source says otherwise) and returns class files. */
    private Map<String, byte[]> compile(Lib l) throws IOException {
        Path src = work.resolve("src-" + l.a + "-" + l.v + "-" + System.nanoTime());
        Path out = src.resolve("out");
        Files.createDirectories(out);
        List<String> files = new ArrayList<>();
        String release = "8";
        for (Map.Entry<String, String> e : l.sources.entrySet()) {
            String code = e.getValue();
            if (code.startsWith("//release=")) {
                release = code.substring(10, code.indexOf('\n')).trim();
            }
            Path f = src.resolve(e.getKey().replace('.', '/') + ".java");
            Files.createDirectories(f.getParent());
            Files.writeString(f, code);
            files.add(f.toString());
        }
        List<String> cp = new ArrayList<>();
        for (String dep : l.classpath) {
            String[] p = dep.split(":");
            cp.add(repo.resolve(p[0].replace('.', '/')).resolve(p[1]).resolve(p[2]).resolve(p[1] + "-" + p[2] + ".jar").toString());
        }
        JavaCompiler jc = ToolProvider.getSystemJavaCompiler();
        List<String> args = new ArrayList<>(List.of("-d", out.toString(), "--release", release, "-nowarn", "-Xlint:none", "-proc:none"));
        if (!cp.isEmpty()) {
            args.add("-cp");
            args.add(String.join(java.io.File.pathSeparator, cp));
        }
        args.addAll(files);
        ByteArrayOutputStream errs = new ByteArrayOutputStream();
        int rc = jc.run(null, null, errs, args.toArray(new String[0]));
        if (rc != 0) throw new IOException("fixture compile failed for " + l.a + ":" + l.v + "\n" + errs);
        Map<String, byte[]> m = new LinkedHashMap<>();
        try (var s = Files.walk(out)) {
            for (Path p : (Iterable<Path>) s::iterator) {
                if (Files.isRegularFile(p)) m.put(out.relativize(p).toString().replace('\\', '/'), Files.readAllBytes(p));
            }
        }
        return m;
    }

    /** Compiles a consumer project's sources into target/classes (we cannot run Maven offline). */
    public void compileInto(Path srcDir, Path outDir, List<String> gavs, String release) throws IOException {
        List<String> files = new ArrayList<>();
        try (var s = Files.walk(srcDir)) {
            for (Path p : (Iterable<Path>) s::iterator) if (p.toString().endsWith(".java")) files.add(p.toString());
        }
        Files.createDirectories(outDir);
        List<String> cp = new ArrayList<>();
        for (String g : gavs) {
            String[] p = g.split(":");
            cp.add(repo.resolve(p[0].replace('.', '/')).resolve(p[1]).resolve(p[2]).resolve(p[1] + "-" + p[2] + ".jar").toString());
        }
        List<String> args = new ArrayList<>(List.of("-d", outDir.toString(), "--release", release, "-nowarn", "-Xlint:none", "-proc:none"));
        if (!cp.isEmpty()) {
            args.add("-cp");
            args.add(String.join(java.io.File.pathSeparator, cp));
        }
        args.addAll(files);
        ByteArrayOutputStream errs = new ByteArrayOutputStream();
        int rc = ToolProvider.getSystemJavaCompiler().run(null, null, errs, args.toArray(new String[0]));
        if (rc != 0) throw new IOException("project compile failed\n" + errs);
    }

    public Object toJsonSummary() {
        return Json.obj("artifacts", versions.size(), "versions", published.size());
    }
}
