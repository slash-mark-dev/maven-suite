package in.slashmark.maven.repo;

import in.slashmark.maven.util.Xml;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.w3c.dom.Element;

/** The parts of Maven's settings.xml that affect where artifacts come from. */
public final class Settings {
    public Path file;
    public String localRepository;
    public boolean offline;
    public final List<Server> servers = new ArrayList<>();
    public final List<Mirror> mirrors = new ArrayList<>();
    public final List<Proxy> proxies = new ArrayList<>();
    public final List<ProfileRepo> profileRepositories = new ArrayList<>();
    public final List<String> activeProfiles = new ArrayList<>();

    public static final class Server {
        public String id, username, password, privateKey, passphrase;
        public final Map<String, String> headers = new LinkedHashMap<>();
        public int line;

        public boolean passwordEncrypted() { return password != null && password.matches("(?s).*\\{[A-Za-z0-9+/=]{8,}}.*"); }

        public boolean passwordFromEnv() { return password != null && password.contains("${env."); }
    }

    public static final class Mirror {
        public String id, url, mirrorOf, name;
        public boolean blocked;
        public int line;
    }

    public static final class Proxy {
        public String id, protocol, host, username, password, nonProxyHosts;
        public int port;
        public boolean active = true;
    }

    public static final class ProfileRepo {
        public String profileId, id, url;
        public boolean releases = true, snapshots = true, activeByDefault, plugin;
        public int line;
    }

    public static Settings empty() { return new Settings(); }

    /** Loads settings.xml if present (missing file means defaults). Values like ${env.X} are expanded. */
    public static Settings load(Path file, Map<String, String> env) throws IOException {
        Settings s = new Settings();
        if (file == null || !Files.isRegularFile(file)) return s;
        s.file = file;
        Element root = Xml.parse(Files.readAllBytes(file));
        s.localRepository = expand(Xml.text(root, "localRepository"), env);
        s.offline = "true".equalsIgnoreCase(Xml.text(root, "offline"));
        for (Element e : Xml.children(Xml.child(root, "servers"), "server")) {
            Server sv = new Server();
            sv.id = Xml.text(e, "id");
            sv.username = expand(Xml.text(e, "username"), env);
            String rawPw = Xml.text(e, "password");
            sv.password = rawPw != null && rawPw.contains("${env.") ? rawPw : expand(rawPw, env);
            sv.privateKey = Xml.text(e, "privateKey");
            sv.passphrase = Xml.text(e, "passphrase");
            Element hdrs = Xml.path(e, "configuration", "httpHeaders");
            for (Element p : Xml.children(hdrs, "property")) {
                String n = Xml.text(p, "name");
                if (n != null) sv.headers.put(n, expand(Xml.text(p, "value"), env));
            }
            sv.line = Xml.line(e);
            s.servers.add(sv);
        }
        for (Element e : Xml.children(Xml.child(root, "mirrors"), "mirror")) {
            Mirror m = new Mirror();
            m.id = Xml.text(e, "id");
            m.url = expand(Xml.text(e, "url"), env);
            m.mirrorOf = Xml.text(e, "mirrorOf");
            m.name = Xml.text(e, "name");
            m.blocked = "true".equalsIgnoreCase(Xml.text(e, "blocked"));
            m.line = Xml.line(e);
            s.mirrors.add(m);
        }
        for (Element e : Xml.children(Xml.child(root, "proxies"), "proxy")) {
            Proxy p = new Proxy();
            p.id = Xml.text(e, "id");
            p.active = !"false".equalsIgnoreCase(Xml.text(e, "active"));
            p.protocol = Xml.text(e, "protocol");
            p.host = Xml.text(e, "host");
            try { p.port = Integer.parseInt(Xml.text(e, "port")); } catch (RuntimeException ignored) {}
            p.username = Xml.text(e, "username");
            p.password = Xml.text(e, "password");
            p.nonProxyHosts = Xml.text(e, "nonProxyHosts");
            s.proxies.add(p);
        }
        for (Element a : Xml.children(Xml.child(root, "activeProfiles"), "activeProfile")) {
            String t = Xml.text(a);
            if (t != null) s.activeProfiles.add(t);
        }
        for (Element pe : Xml.children(Xml.child(root, "profiles"), "profile")) {
            String pid = Xml.text(pe, "id");
            boolean abd = "true".equalsIgnoreCase(Xml.text(Xml.child(pe, "activation"), "activeByDefault"));
            for (String kind : new String[] {"repositories/repository", "pluginRepositories/pluginRepository"}) {
                String[] k = kind.split("/");
                for (Element r : Xml.children(Xml.child(pe, k[0]), k[1])) {
                    ProfileRepo pr = new ProfileRepo();
                    pr.profileId = pid;
                    pr.activeByDefault = abd;
                    pr.plugin = k[0].startsWith("plugin");
                    pr.id = Xml.text(r, "id");
                    pr.url = expand(Xml.text(r, "url"), env);
                    Element rel = Xml.child(r, "releases");
                    if (rel != null && "false".equalsIgnoreCase(Xml.text(rel, "enabled"))) pr.releases = false;
                    Element sn = Xml.child(r, "snapshots");
                    if (sn != null && "false".equalsIgnoreCase(Xml.text(sn, "enabled"))) pr.snapshots = false;
                    pr.line = Xml.line(r);
                    s.profileRepositories.add(pr);
                }
            }
        }
        return s;
    }

    private static final Pattern ENV = Pattern.compile("\\$\\{env\\.([A-Za-z0-9_]+)}");

    static String expand(String v, Map<String, String> env) {
        if (v == null) return null;
        Matcher m = ENV.matcher(v);
        StringBuilder b = new StringBuilder();
        while (m.find()) {
            String r = env.get(m.group(1));
            m.appendReplacement(b, Matcher.quoteReplacement(r == null ? m.group(0) : r));
        }
        m.appendTail(b);
        return b.toString();
    }

    public Server server(String id) {
        for (Server s : servers) if (s.id != null && s.id.equals(id)) return s;
        return null;
    }

    /** Repositories contributed by active settings profiles (activeProfiles or activeByDefault). */
    public List<ProfileRepo> activeRepositories() {
        List<ProfileRepo> out = new ArrayList<>();
        for (ProfileRepo r : profileRepositories) {
            if (r.plugin) continue;
            if (activeProfiles.contains(r.profileId) || (r.activeByDefault && activeProfiles.isEmpty())) out.add(r);
        }
        return out;
    }

    /**
     * Finds the mirror for a repository using Maven's mirrorOf rules: exact id, "*", "external:*"
     * (non-localhost, non-file), "external:http:*" (plain HTTP), comma lists and "!id" exclusions.
     */
    public Mirror mirrorFor(String repoId, String repoUrl) {
        // An exact id match wins over patterns, as in Maven.
        for (Mirror m : mirrors) if (m.mirrorOf != null && m.mirrorOf.trim().equals(repoId)) return m;
        for (Mirror m : mirrors) if (matchesPattern(m.mirrorOf, repoId, repoUrl)) return m;
        return null;
    }

    static boolean matchesPattern(String pattern, String id, String url) {
        if (pattern == null) return false;
        boolean matched = false;
        for (String raw : pattern.split(",")) {
            String p = raw.trim();
            if (p.isEmpty()) continue;
            if (p.startsWith("!")) {
                if (p.substring(1).equals(id)) return false;
            } else if (p.equals(id) || p.equals("*")) {
                matched = true;
            } else if (p.equals("external:*") && isExternal(url)) {
                matched = true;
            } else if (p.equals("external:http:*") && isExternal(url) && url != null && url.startsWith("http:")) {
                matched = true;
            }
        }
        return matched;
    }

    static boolean isExternal(String url) {
        if (url == null) return true;
        String u = url.toLowerCase();
        if (u.startsWith("file:")) return false;
        return !(u.contains("://localhost") || u.contains("://127.0.0.1") || u.contains("://[::1]"));
    }
}
