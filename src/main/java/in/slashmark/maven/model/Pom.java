package in.slashmark.maven.model;

import in.slashmark.maven.util.Xml;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.w3c.dom.Element;

/**
 * A parsed pom.xml. Fields hold raw values after {@link #parse}; {@link ModelBuilder} produces an
 * effective model (inheritance, profiles, interpolation, imported BOMs, managed versions).
 */
public final class Pom {
    public String groupId, artifactId, version, packaging = "jar";
    public String name, description, url, inceptionYear;
    public Parent parent;
    public final Map<String, String> properties = new LinkedHashMap<>();
    public final List<Dependency> dependencies = new ArrayList<>();
    public final List<Dependency> dependencyManagement = new ArrayList<>();
    public final List<String> modules = new ArrayList<>();
    public final List<License> licenses = new ArrayList<>();
    public final List<Developer> developers = new ArrayList<>();
    public String scmUrl, scmConnection, scmDeveloperConnection, scmTag;
    public String organizationName, organizationUrl;
    public String issueUrl, ciUrl;
    public Relocation relocation;
    public final List<Repository> repositories = new ArrayList<>();
    public final List<Repository> pluginRepositories = new ArrayList<>();
    public Repository distributionRelease, distributionSnapshot;
    public final List<Plugin> plugins = new ArrayList<>();
    public final List<Plugin> pluginManagement = new ArrayList<>();
    public final List<Profile> profiles = new ArrayList<>();
    public final List<Extension> extensions = new ArrayList<>();
    public String prerequisitesMaven;
    public String modelVersion;

    /** Where this POM came from (file path or repository URL), for messages. */
    public String source;
    /** Set for POMs read from disk. */
    public Path file;
    /** Line numbers of interesting elements (e.g. "parent", "dependencyManagement"). */
    public final Map<String, Integer> lines = new LinkedHashMap<>();

    public static final class Parent {
        public String groupId, artifactId, version, relativePath;
        public boolean relativePathSet;
        public int line;

        public Gav gav() { return new Gav(groupId, artifactId, version); }
    }

    public static final class License {
        public String name, url, distribution, comments;

        @Override
        public String toString() { return name != null ? name : url != null ? url : "(unnamed)"; }
    }

    public static final class Developer {
        public String id, name, email, organization;
    }

    public static final class Relocation {
        public String groupId, artifactId, version, message;
    }

    public static final class Repository {
        public String id, name, url, layout;
        public boolean releases = true, snapshots = true;
        public int line;
    }

    public static final class Plugin {
        public String groupId = "org.apache.maven.plugins", artifactId, version;
        public boolean extensions;
        public boolean inherited = true;
        public final List<String> goals = new ArrayList<>();
        public final List<String> phases = new ArrayList<>();
        public final List<Dependency> dependencies = new ArrayList<>();
        /** Flattened configuration: element path -> text, e.g. "configuration/release" -> "17". */
        public final Map<String, String> configuration = new LinkedHashMap<>();
        public int line;

        public String ga() { return groupId + ":" + artifactId; }
    }

    public static final class Extension {
        public String groupId, artifactId, version;
        public int line;
    }

    public static final class Profile {
        public String id;
        public boolean activeByDefault;
        public String activationJdk;
        public String activationProperty, activationPropertyValue;
        public String activationFileExists, activationFileMissing;
        public String activationOs;
        public final Map<String, String> properties = new LinkedHashMap<>();
        public final List<Dependency> dependencies = new ArrayList<>();
        public final List<Dependency> dependencyManagement = new ArrayList<>();
        public final List<String> modules = new ArrayList<>();
        public final List<Repository> repositories = new ArrayList<>();
        public final List<Plugin> plugins = new ArrayList<>();
        public final List<Plugin> pluginManagement = new ArrayList<>();
    }

    /** Identity using inherited parent values where the child omits them. */
    public String effectiveGroupId() { return groupId != null ? groupId : parent != null ? parent.groupId : null; }

    public String effectiveVersion() { return version != null ? version : parent != null ? parent.version : null; }

    public Gav gav() { return new Gav(effectiveGroupId(), artifactId, effectiveVersion()); }

    // ---------------------------------------------------------------- parsing

    public static Pom parse(byte[] xml, String source) {
        Element root = Xml.parse(xml);
        if (!"project".equals(root.getTagName())) throw new IllegalArgumentException(source + " is not a Maven POM (root element <" + root.getTagName() + ">)");
        Pom p = new Pom();
        p.source = source;
        p.modelVersion = Xml.text(root, "modelVersion");
        p.groupId = Xml.text(root, "groupId");
        p.artifactId = Xml.text(root, "artifactId");
        p.version = Xml.text(root, "version");
        String pk = Xml.text(root, "packaging");
        if (pk != null) p.packaging = pk;
        p.name = Xml.text(root, "name");
        p.description = Xml.text(root, "description");
        p.url = Xml.text(root, "url");
        p.inceptionYear = Xml.text(root, "inceptionYear");

        Element par = Xml.child(root, "parent");
        if (par != null) {
            Parent pa = new Parent();
            pa.groupId = Xml.text(par, "groupId");
            pa.artifactId = Xml.text(par, "artifactId");
            pa.version = Xml.text(par, "version");
            Element rp = Xml.child(par, "relativePath");
            pa.relativePathSet = rp != null;
            pa.relativePath = rp == null ? "../pom.xml" : (rp.getTextContent() == null ? "" : rp.getTextContent().trim());
            pa.line = Xml.line(par);
            p.parent = pa;
            p.lines.put("parent", pa.line);
        }

        readProperties(Xml.child(root, "properties"), p.properties);
        readDeps(Xml.child(root, "dependencies"), p.dependencies);
        Element dm = Xml.child(root, "dependencyManagement");
        if (dm != null) {
            p.lines.put("dependencyManagement", Xml.line(dm));
            readDeps(Xml.child(dm, "dependencies"), p.dependencyManagement);
        }
        for (Element m : Xml.children(Xml.child(root, "modules"), "module")) {
            String t = Xml.text(m);
            if (t != null) p.modules.add(t);
        }
        for (Element l : Xml.children(Xml.child(root, "licenses"), "license")) {
            License li = new License();
            li.name = Xml.text(l, "name");
            li.url = Xml.text(l, "url");
            li.distribution = Xml.text(l, "distribution");
            li.comments = Xml.text(l, "comments");
            p.licenses.add(li);
        }
        for (Element d : Xml.children(Xml.child(root, "developers"), "developer")) {
            Developer dv = new Developer();
            dv.id = Xml.text(d, "id");
            dv.name = Xml.text(d, "name");
            dv.email = Xml.text(d, "email");
            dv.organization = Xml.text(d, "organization");
            p.developers.add(dv);
        }
        Element scm = Xml.child(root, "scm");
        if (scm != null) {
            p.scmUrl = Xml.text(scm, "url");
            p.scmConnection = Xml.text(scm, "connection");
            p.scmDeveloperConnection = Xml.text(scm, "developerConnection");
            p.scmTag = Xml.text(scm, "tag");
        }
        Element org = Xml.child(root, "organization");
        if (org != null) {
            p.organizationName = Xml.text(org, "name");
            p.organizationUrl = Xml.text(org, "url");
        }
        p.issueUrl = Xml.text(Xml.child(root, "issueManagement"), "url");
        p.ciUrl = Xml.text(Xml.child(root, "ciManagement"), "url");
        Element dist = Xml.child(root, "distributionManagement");
        if (dist != null) {
            Element rel = Xml.child(dist, "relocation");
            if (rel != null) {
                Relocation r = new Relocation();
                r.groupId = Xml.text(rel, "groupId");
                r.artifactId = Xml.text(rel, "artifactId");
                r.version = Xml.text(rel, "version");
                r.message = Xml.text(rel, "message");
                p.relocation = r;
            }
            Element dr = Xml.child(dist, "repository");
            if (dr != null) p.distributionRelease = readRepo(dr);
            Element ds = Xml.child(dist, "snapshotRepository");
            if (ds != null) p.distributionSnapshot = readRepo(ds);
        }
        for (Element r : Xml.children(Xml.child(root, "repositories"), "repository")) p.repositories.add(readRepo(r));
        for (Element r : Xml.children(Xml.child(root, "pluginRepositories"), "pluginRepository")) p.pluginRepositories.add(readRepo(r));
        Element build = Xml.child(root, "build");
        if (build != null) {
            readPlugins(Xml.child(build, "plugins"), p.plugins);
            readPlugins(Xml.path(build, "pluginManagement", "plugins"), p.pluginManagement);
            for (Element e : Xml.children(Xml.child(build, "extensions"), "extension")) {
                Extension x = new Extension();
                x.groupId = Xml.text(e, "groupId");
                x.artifactId = Xml.text(e, "artifactId");
                x.version = Xml.text(e, "version");
                x.line = Xml.line(e);
                p.extensions.add(x);
            }
        }
        p.prerequisitesMaven = Xml.text(Xml.child(root, "prerequisites"), "maven");
        for (Element pe : Xml.children(Xml.child(root, "profiles"), "profile")) {
            Profile pr = new Profile();
            pr.id = Xml.text(pe, "id");
            Element act = Xml.child(pe, "activation");
            if (act != null) {
                pr.activeByDefault = "true".equalsIgnoreCase(Xml.text(act, "activeByDefault"));
                pr.activationJdk = Xml.text(act, "jdk");
                Element prop = Xml.child(act, "property");
                if (prop != null) {
                    pr.activationProperty = Xml.text(prop, "name");
                    pr.activationPropertyValue = Xml.text(prop, "value");
                }
                Element file = Xml.child(act, "file");
                if (file != null) {
                    pr.activationFileExists = Xml.text(file, "exists");
                    pr.activationFileMissing = Xml.text(file, "missing");
                }
                Element os = Xml.child(act, "os");
                if (os != null) pr.activationOs = Xml.text(os, "family") != null ? Xml.text(os, "family") : Xml.text(os, "name");
            }
            readProperties(Xml.child(pe, "properties"), pr.properties);
            readDeps(Xml.child(pe, "dependencies"), pr.dependencies);
            readDeps(Xml.path(pe, "dependencyManagement", "dependencies"), pr.dependencyManagement);
            for (Element m : Xml.children(Xml.child(pe, "modules"), "module")) {
                String t = Xml.text(m);
                if (t != null) pr.modules.add(t);
            }
            for (Element r : Xml.children(Xml.child(pe, "repositories"), "repository")) pr.repositories.add(readRepo(r));
            Element pb = Xml.child(pe, "build");
            if (pb != null) {
                readPlugins(Xml.child(pb, "plugins"), pr.plugins);
                readPlugins(Xml.path(pb, "pluginManagement", "plugins"), pr.pluginManagement);
            }
            p.profiles.add(pr);
        }
        return p;
    }

    public static Pom parse(String xml, String source) { return parse(xml.getBytes(StandardCharsets.UTF_8), source); }

    private static void readProperties(Element props, Map<String, String> into) {
        for (Element e : Xml.children(props, null)) {
            String t = e.getTextContent();
            into.put(e.getTagName(), t == null ? "" : t.trim());
        }
    }

    static void readDeps(Element deps, List<Dependency> into) {
        for (Element e : Xml.children(deps, "dependency")) {
            Dependency d = new Dependency();
            d.groupId = Xml.text(e, "groupId");
            d.artifactId = Xml.text(e, "artifactId");
            d.version = Xml.text(e, "version");
            String t = Xml.text(e, "type");
            if (t != null) d.type = t;
            d.classifier = Xml.text(e, "classifier");
            d.scope = Xml.text(e, "scope");
            d.optional = Xml.text(e, "optional");
            d.systemPath = Xml.text(e, "systemPath");
            for (Element x : Xml.children(Xml.child(e, "exclusions"), "exclusion")) {
                String g = Xml.text(x, "groupId");
                String a = Xml.text(x, "artifactId");
                d.exclusions.add(new String[] {g == null ? "*" : g, a == null ? "*" : a});
            }
            d.line = Xml.line(e);
            into.add(d);
        }
    }

    private static Repository readRepo(Element e) {
        Repository r = new Repository();
        r.id = Xml.text(e, "id");
        r.name = Xml.text(e, "name");
        r.url = Xml.text(e, "url");
        r.layout = Xml.text(e, "layout");
        Element rel = Xml.child(e, "releases");
        if (rel != null && "false".equalsIgnoreCase(Xml.text(rel, "enabled"))) r.releases = false;
        Element sn = Xml.child(e, "snapshots");
        if (sn != null && "false".equalsIgnoreCase(Xml.text(sn, "enabled"))) r.snapshots = false;
        r.line = Xml.line(e);
        return r;
    }

    private static void readPlugins(Element plugins, List<Plugin> into) {
        for (Element e : Xml.children(plugins, "plugin")) {
            Plugin pl = new Plugin();
            String g = Xml.text(e, "groupId");
            if (g != null) pl.groupId = g;
            pl.artifactId = Xml.text(e, "artifactId");
            pl.version = Xml.text(e, "version");
            pl.extensions = "true".equalsIgnoreCase(Xml.text(e, "extensions"));
            pl.inherited = !"false".equalsIgnoreCase(Xml.text(e, "inherited"));
            for (Element ex : Xml.children(Xml.child(e, "executions"), "execution")) {
                String ph = Xml.text(ex, "phase");
                if (ph != null) pl.phases.add(ph);
                for (Element gl : Xml.children(Xml.child(ex, "goals"), "goal")) {
                    String t = Xml.text(gl);
                    if (t != null) pl.goals.add(t);
                }
                flatten(Xml.child(ex, "configuration"), "execution/configuration", pl.configuration);
            }
            readDeps(Xml.child(e, "dependencies"), pl.dependencies);
            flatten(Xml.child(e, "configuration"), "configuration", pl.configuration);
            pl.line = Xml.line(e);
            into.add(pl);
        }
    }

    private static void flatten(Element e, String prefix, Map<String, String> into) {
        if (e == null) return;
        List<Element> kids = Xml.children(e, null);
        if (kids.isEmpty()) {
            String t = Xml.text(e);
            if (t != null) into.merge(prefix, t, (a, b) -> a + "," + b);
            return;
        }
        for (Element k : kids) flatten(k, prefix + "/" + k.getTagName(), into);
    }
}
