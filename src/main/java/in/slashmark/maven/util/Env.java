package in.slashmark.maven.util;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Locale;
import java.util.Map;

/** Endpoints and folders, overridable with environment variables (and by tests). */
public final class Env {
    private final Map<String, String> env;

    public Env(Map<String, String> env) { this.env = env; }

    public static Env system() { return new Env(System.getenv()); }

    public String get(String name) {
        String v = env.get(name);
        return v == null || v.isBlank() ? null : v.trim();
    }

    public String get(String name, String def) {
        String v = get(name);
        return v == null ? def : v;
    }

    private String url(String name, String def) {
        String v = get(name, def);
        while (v.endsWith("/")) v = v.substring(0, v.length() - 1);
        return v;
    }

    /** Maven Central repository root (the classic repo1 layout). */
    public String central() { return url("SM_MAVEN_CENTRAL", "https://repo1.maven.org/maven2"); }

    /** Central search API (solrsearch). */
    public String search() { return url("SM_MAVEN_SEARCH", "https://search.maven.org"); }

    public String osv() { return url("SM_MAVEN_OSV", "https://api.osv.dev"); }

    public String depsDev() { return url("SM_MAVEN_DEPSDEV", "https://api.deps.dev"); }

    public String kev() { return get("SM_MAVEN_KEV", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"); }

    public String epss() { return url("SM_MAVEN_EPSS", "https://api.first.org/data/v1/epss"); }

    public String github() { return url("SM_MAVEN_GITHUB", "https://api.github.com"); }

    public String javadocIo() { return url("SM_MAVEN_JAVADOC", "https://javadoc.io"); }

    public String githubToken() {
        String t = get("GITHUB_TOKEN");
        return t != null ? t : get("GH_TOKEN");
    }

    public boolean noColor() { return get("NO_COLOR") != null; }

    public boolean ci() { return get("CI") != null; }

    public Path home() {
        String h = get("SM_MAVEN_HOME");
        if (h != null) return Paths.get(h);
        return Paths.get(System.getProperty("user.home"));
    }

    private boolean windows() { return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win"); }

    public Path cacheDir() {
        String c = get("SM_MAVEN_CACHE");
        if (c != null) return Paths.get(c);
        if (windows() && get("LOCALAPPDATA") != null) return Paths.get(get("LOCALAPPDATA"), "sm-maven", "cache");
        String xdg = get("XDG_CACHE_HOME");
        return xdg != null ? Paths.get(xdg, "sm-maven") : home().resolve(".cache").resolve("sm-maven");
    }

    /** Folder for watch state, alert configuration and drift snapshots that are not per-project. */
    public Path configDir() {
        String c = get("SM_MAVEN_CONFIG");
        if (c != null) return Paths.get(c);
        if (windows() && get("APPDATA") != null) return Paths.get(get("APPDATA"), "sm-maven");
        String xdg = get("XDG_CONFIG_HOME");
        return xdg != null ? Paths.get(xdg, "sm-maven") : home().resolve(".config").resolve("sm-maven");
    }

    /** The local Maven repository (~/.m2/repository unless overridden). */
    public Path localRepo() {
        String r = get("SM_MAVEN_LOCAL_REPO");
        if (r != null) return Paths.get(r);
        return home().resolve(".m2").resolve("repository");
    }

    public Path userSettings() {
        String s = get("SM_MAVEN_SETTINGS");
        if (s != null) return Paths.get(s);
        return home().resolve(".m2").resolve("settings.xml");
    }
}
