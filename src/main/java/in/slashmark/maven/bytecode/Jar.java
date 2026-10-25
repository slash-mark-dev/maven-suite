package in.slashmark.maven.bytecode;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.Manifest;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * An in-memory view of a JAR (or a classes directory): entries, manifest, class files, nested JARs,
 * native libraries and services. Class files are parsed on demand.
 */
public final class Jar {
    public final String name;
    public final long size;
    /** Entry name -> uncompressed bytes. */
    private final Map<String, byte[]> entries = new LinkedHashMap<>();
    private final Map<String, ClassFile> parsed = new LinkedHashMap<>();
    public Manifest manifest;
    /** Entries whose names contain "..", start with "/" or otherwise try to escape the extraction folder. */
    public final List<String> suspiciousPaths = new ArrayList<>();
    private static final long MAX_TOTAL = 512L * 1024 * 1024;

    private Jar(String name, long size) {
        this.name = name;
        this.size = size;
    }

    public static Jar read(String name, byte[] data) throws IOException {
        Jar j = new Jar(name, data.length);
        long total = 0;
        try (ZipInputStream zin = new ZipInputStream(new ByteArrayInputStream(data))) {
            ZipEntry e;
            byte[] buf = new byte[65536];
            while ((e = zin.getNextEntry()) != null) {
                String n = e.getName();
                if (n.contains("..") || n.startsWith("/") || n.contains(":\\") || n.contains("\\")) j.suspiciousPaths.add(n);
                if (e.isDirectory()) continue;
                ByteArrayOutputStream bo = new ByteArrayOutputStream();
                int r;
                while ((r = zin.read(buf)) > 0) {
                    bo.write(buf, 0, r);
                    total += r;
                    if (total > MAX_TOTAL) throw new IOException(name + " expands beyond 512 MB (zip bomb?)");
                }
                j.entries.put(n, bo.toByteArray());
            }
        }
        byte[] mf = j.entries.get("META-INF/MANIFEST.MF");
        if (mf != null) {
            try { j.manifest = new Manifest(new ByteArrayInputStream(mf)); } catch (IOException ignored) {}
        }
        return j;
    }

    /** Reads a JAR file, or a directory of classes (e.g. target/classes). */
    public static Jar read(Path p) throws IOException {
        if (Files.isDirectory(p)) {
            Jar j = new Jar(p.toString(), 0);
            try (Stream<Path> s = Files.walk(p)) {
                for (Path f : (Iterable<Path>) s::iterator) {
                    if (!Files.isRegularFile(f)) continue;
                    String rel = p.relativize(f).toString().replace('\\', '/');
                    j.entries.put(rel, Files.readAllBytes(f));
                }
            }
            byte[] mf = j.entries.get("META-INF/MANIFEST.MF");
            if (mf != null) try { j.manifest = new Manifest(new ByteArrayInputStream(mf)); } catch (IOException ignored) {}
            return j;
        }
        return read(p.getFileName().toString(), Files.readAllBytes(p));
    }

    public Set<String> entryNames() { return entries.keySet(); }

    public byte[] entry(String n) { return entries.get(n); }

    public int entryCount() { return entries.size(); }

    public long uncompressedSize() {
        long t = 0;
        for (byte[] b : entries.values()) t += b.length;
        return t;
    }

    /** Class entries, excluding module-info and (by default) Multi-Release version overlays. */
    public List<String> classEntries(boolean includeVersioned) {
        List<String> out = new ArrayList<>();
        for (String n : entries.keySet()) {
            if (!n.endsWith(".class")) continue;
            if (n.endsWith("module-info.class")) continue;
            if (!includeVersioned && n.startsWith("META-INF/versions/")) continue;
            if (n.startsWith("BOOT-INF/lib/") || n.startsWith("WEB-INF/lib/")) continue;
            out.add(n);
        }
        return out;
    }

    /** Parsed class for an entry (null when it is not a valid class file). */
    public ClassFile classFile(String entry) {
        if (parsed.containsKey(entry)) return parsed.get(entry);
        ClassFile cf = null;
        byte[] b = entries.get(entry);
        if (b != null) {
            try { cf = ClassFile.parse(b); } catch (IOException | RuntimeException ignored) {}
        }
        parsed.put(entry, cf);
        return cf;
    }

    /** All parsed classes (base versions only). */
    public List<ClassFile> classes() {
        List<ClassFile> out = new ArrayList<>();
        for (String e : classEntries(false)) {
            ClassFile cf = classFile(e);
            if (cf != null) out.add(cf);
        }
        return out;
    }

    /** Distinct packages of the classes, dotted. */
    public Set<String> packages() {
        Set<String> s = new LinkedHashSet<>();
        for (String e : classEntries(false)) {
            String path = e.startsWith("BOOT-INF/classes/") ? e.substring(17) : e.startsWith("WEB-INF/classes/") ? e.substring(16) : e;
            int i = path.lastIndexOf('/');
            s.add(i < 0 ? "" : path.substring(0, i).replace('/', '.'));
        }
        return s;
    }

    public String manifestAttr(String key) {
        if (manifest == null) return null;
        String v = manifest.getMainAttributes().getValue(key);
        return v == null ? null : v.trim();
    }

    public boolean multiRelease() { return "true".equalsIgnoreCase(manifestAttr("Multi-Release")); }

    /** Highest class file major version among base classes (0 when there are none). */
    public int maxClassMajor() {
        int m = 0;
        for (String e : classEntries(false)) {
            byte[] b = entries.get(e);
            if (b != null && b.length > 8 && (b[0] & 0xFF) == 0xCA && (b[1] & 0xFF) == 0xFE) m = Math.max(m, ((b[6] & 0xFF) << 8) | (b[7] & 0xFF));
        }
        return m;
    }

    /** Count of base classes per class file major version. */
    public Map<Integer, Integer> majorHistogram() {
        Map<Integer, Integer> h = new java.util.TreeMap<>();
        for (String e : classEntries(false)) {
            byte[] b = entries.get(e);
            if (b != null && b.length > 8) h.merge(((b[6] & 0xFF) << 8) | (b[7] & 0xFF), 1, Integer::sum);
        }
        return h;
    }

    public static boolean isNativeLib(String n) {
        String l = n.toLowerCase();
        return l.endsWith(".so") || l.contains(".so.") || l.endsWith(".dll") || l.endsWith(".dylib") || l.endsWith(".jnilib") || l.endsWith(".a") || l.endsWith(".exe");
    }

    public List<String> nativeLibs() {
        List<String> out = new ArrayList<>();
        for (String n : entries.keySet()) if (isNativeLib(n)) out.add(n);
        return out;
    }

    /** Nested JARs (Spring Boot fat jars, WARs, shaded jar-in-jar). */
    public List<String> nestedJars() {
        List<String> out = new ArrayList<>();
        for (String n : entries.keySet()) if (n.endsWith(".jar")) out.add(n);
        return out;
    }

    public Jar nested(String entry) throws IOException {
        byte[] b = entries.get(entry);
        return b == null ? null : read(entry, b);
    }

    /** META-INF/services registrations: service interface -> implementations. */
    public Map<String, List<String>> services() {
        Map<String, List<String>> out = new LinkedHashMap<>();
        for (Map.Entry<String, byte[]> e : entries.entrySet()) {
            if (!e.getKey().startsWith("META-INF/services/") || e.getKey().endsWith("/")) continue;
            List<String> impls = new ArrayList<>();
            for (String line : new String(e.getValue(), StandardCharsets.UTF_8).split("\n")) {
                int h = line.indexOf('#');
                String t = (h >= 0 ? line.substring(0, h) : line).trim();
                if (!t.isEmpty()) impls.add(t);
            }
            out.put(e.getKey().substring("META-INF/services/".length()), impls);
        }
        return out;
    }

    /** Embedded Maven metadata (META-INF/maven/g/a/pom.properties): "g:a:v" entries, how shading is usually detected. */
    public List<String> embeddedMavenArtifacts() {
        List<String> out = new ArrayList<>();
        for (Map.Entry<String, byte[]> e : entries.entrySet()) {
            String n = e.getKey();
            if (!n.startsWith("META-INF/maven/") || !n.endsWith("/pom.properties")) continue;
            java.util.Properties p = new java.util.Properties();
            try (InputStream in = new ByteArrayInputStream(e.getValue())) {
                p.load(in);
                String g = p.getProperty("groupId"), a = p.getProperty("artifactId"), v = p.getProperty("version");
                if (g != null && a != null) out.add(g + ":" + a + (v == null ? "" : ":" + v));
            } catch (IOException ignored) {}
        }
        return out;
    }

    /** Text of an entry (UTF-8), or null. */
    public String text(String n) {
        byte[] b = entries.get(n);
        return b == null ? null : new String(b, StandardCharsets.UTF_8);
    }
}
