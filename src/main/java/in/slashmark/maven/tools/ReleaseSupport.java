package in.slashmark.maven.tools;

import in.slashmark.maven.cli.Ctx;
import in.slashmark.maven.cli.UsageException;
import in.slashmark.maven.data.CentralSearch;
import in.slashmark.maven.data.DepsDev;
import in.slashmark.maven.data.GitHub;
import in.slashmark.maven.model.Gav;
import in.slashmark.maven.model.ModelBuilder;
import in.slashmark.maven.resolve.DepNode;
import in.slashmark.maven.resolve.Graph;
import in.slashmark.maven.util.HttpException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Helpers shared by the "Release intelligence" tools (radar, pulse, breakcheck, adoption, relocations). */
final class ReleaseSupport {
    private ReleaseSupport() {}

    static final long DAY = 86_400_000L;

    /** A resolved dependency of the target, merged across modules. */
    static final class Dep {
        final DepNode node;
        boolean direct;
        /** The module graph that declares it directly (null for transitive-only dependencies). */
        Graph directIn;
        final Set<String> modules = new LinkedHashSet<>();

        Dep(DepNode node) { this.node = node; }

        String ga() { return node.ga(); }

        Gav gav() { return node.gav(); }
    }

    /**
     * Selected dependencies of the target (each g:a:v once, reactor modules excluded), direct ones only
     * unless transitive is set. A dependency counts as direct when any module declares it.
     */
    static List<Dep> dependencies(Ctx ctx, Ctx.Target t, boolean transitive) {
        Map<String, Dep> out = new LinkedHashMap<>();
        Set<String> reactor = ctx.models.reactorGavs();
        for (Graph g : t.graphs) {
            String module = g.root.pom.artifactId;
            for (DepNode n : g.resolved()) {
                if (reactor.contains(n.gav().toString())) continue;
                if (n.version == null) continue;
                Dep d = out.computeIfAbsent(n.gav().toString(), k -> new Dep(n));
                if (n.isDirect() && d.directIn == null) d.directIn = g;
                d.direct |= n.isDirect();
                d.modules.add(module);
            }
        }
        List<Dep> list = new ArrayList<>();
        for (Dep d : out.values()) if (transitive || d.direct) list.add(d);
        return list;
    }

    /** State/alert scope for a target: the project's pom.xml path or the artifact coordinates. */
    static String scope(Ctx.Target t) {
        if (t.project != null) return t.project.root.resolve("pom.xml").toString();
        return t.label;
    }

    /** Release timestamps (version -> epoch millis) from Central search; empty when not indexed. */
    static Map<String, Long> releaseTimes(Ctx ctx, String groupId, String artifactId) throws HttpException {
        Map<String, Long> m = new LinkedHashMap<>();
        CentralSearch.Result r = ctx.search.versions(groupId, artifactId, 400);
        for (CentralSearch.Doc d : r.docs) if (d.version != null && d.timestamp > 0) m.putIfAbsent(d.version, d.timestamp);
        return m;
    }

    static Gav parseGav(String s) {
        try {
            return Gav.parse(s);
        } catch (IllegalArgumentException e) {
            throw new UsageException(e.getMessage());
        }
    }

    static String iso(long millis) { return millis <= 0 ? null : Instant.ofEpochMilli(millis).toString(); }

    static Long ageDays(long millis) { return millis <= 0 ? null : Math.max(0, (System.currentTimeMillis() - millis) / DAY); }

    /** Ordered map that keeps null values (stable JSON field sets). */
    static Map<String, Object> o(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) m.put(String.valueOf(kv[i]), kv[i + 1]);
        return m;
    }

    static String shortGa(String ga) {
        int c = ga.indexOf(':');
        return c < 0 ? ga : ga.substring(c + 1);
    }

    // ---------------------------------------------------------------- source repository + activity

    /** Where a library's code lives and how active it is. */
    static final class RepoInfo {
        /** "owner/repo" on GitHub, null when unknown. */
        String repo;
        /** deps.dev project id for the Scorecard, e.g. github.com/google/guava. */
        String projectId;
        /** True when GitHub was asked and knows the repository. */
        boolean found;
        boolean checked;
        boolean archived;
        long pushedAt;
        int commits90d = -1;
        int contributors90d = -1;
        String error;
    }

    /** Finds the GitHub repository through deps.dev, falling back to the POM's scm/url. */
    static RepoInfo sourceRepo(Ctx ctx, Gav gav) {
        RepoInfo ri = new RepoInfo();
        try {
            DepsDev.VersionInfo vi = ctx.depsDev.version(gav.ga(), gav.version);
            if (vi != null) {
                ri.repo = GitHub.repoFromUrl(vi.sourceRepo);
                ri.projectId = vi.projectId;
                if (ri.repo == null && vi.projectId != null) ri.repo = GitHub.repoFromUrl(vi.projectId);
            }
        } catch (HttpException e) {
            ri.error = "deps.dev: " + e.getMessage();
        }
        if (ri.repo == null) {
            try {
                ModelBuilder.Model m = ctx.models.buildRemote(gav);
                if (m != null) {
                    for (String u : new String[] {m.pom.scmUrl, m.pom.scmConnection, m.pom.url}) {
                        ri.repo = GitHub.repoFromUrl(u);
                        if (ri.repo != null) break;
                    }
                }
            } catch (HttpException e) {
                if (ri.error == null) ri.error = e.getMessage();
            }
        }
        if (ri.repo != null && ri.projectId == null) ri.projectId = "github.com/" + ri.repo;
        return ri;
    }

    /** Adds GitHub state (archived, last push, commits and contributors in the last 90 days). */
    static void github(Ctx ctx, RepoInfo ri) {
        if (ri.repo == null) return;
        try {
            GitHub.Repo r = ctx.github.repo(ri.repo);
            ri.checked = true;
            if (r == null) return;
            ri.found = true;
            ri.archived = r.archived;
            ri.pushedAt = r.pushedAt;
            List<String[]> commits = ctx.github.commitsSince(ri.repo, System.currentTimeMillis() - 90 * DAY);
            Set<String> authors = new LinkedHashSet<>();
            for (String[] c : commits) if (c[1] != null) authors.add(c[1]);
            ri.commits90d = commits.size();
            ri.contributors90d = authors.size();
        } catch (HttpException e) {
            ri.error = "GitHub: " + e.getMessage();
        }
    }

    // ---------------------------------------------------------------- retired artifacts

    /** A well-known artifact that was renamed or retired without a POM relocation. */
    static final class Successor {
        final String ga, replacement, reason, note;

        Successor(String ga, String replacement, String reason, String note) {
            this.ga = ga;
            this.replacement = replacement;
            this.reason = reason;
            this.note = note;
        }
    }

    static final Map<String, Successor> RETIRED = new LinkedHashMap<>();

    private static void retired(String ga, String replacement, String reason, String note) {
        RETIRED.put(ga, new Successor(ga, replacement, reason, note));
    }

    static {
        String jakarta = "Java EE moved to the Eclipse Foundation (Jakarta EE); the javax artifact is no longer maintained";
        String pkg = "Jakarta 3+/4+ renames the packages javax.* -> jakarta.* (code changes needed)";
        retired("javax.xml.bind:jaxb-api", "jakarta.xml.bind:jakarta.xml.bind-api", jakarta + " and was removed from the JDK in Java 11", pkg);
        retired("javax.annotation:javax.annotation-api", "jakarta.annotation:jakarta.annotation-api", jakarta, pkg);
        retired("javax.servlet:javax.servlet-api", "jakarta.servlet:jakarta.servlet-api", jakarta, pkg);
        retired("javax.activation:activation", "jakarta.activation:jakarta.activation-api", jakarta, pkg);
        retired("javax.activation:javax.activation-api", "jakarta.activation:jakarta.activation-api", jakarta, pkg);
        retired("javax.ws.rs:javax.ws.rs-api", "jakarta.ws.rs:jakarta.ws.rs-api", jakarta, pkg);
        retired("javax.persistence:javax.persistence-api", "jakarta.persistence:jakarta.persistence-api", jakarta, pkg);
        retired("javax.validation:validation-api", "jakarta.validation:jakarta.validation-api", jakarta, pkg);
        retired("javax.inject:javax.inject", "jakarta.inject:jakarta.inject-api", jakarta, pkg);
        retired("javax.json:javax.json-api", "jakarta.json:jakarta.json-api", jakarta, pkg);
        retired("javax.mail:mail", "org.eclipse.angus:angus-mail", jakarta, pkg);
        retired("com.sun.mail:javax.mail", "org.eclipse.angus:angus-mail", jakarta, pkg);
        retired("com.sun.xml.bind:jaxb-impl", "org.glassfish.jaxb:jaxb-runtime", jakarta, pkg);
        retired("log4j:log4j", "org.apache.logging.log4j:log4j-1.2-api", "Log4j 1.x reached end of life in 2015 and has unfixed CVEs",
                "log4j-1.2-api bridges the 1.x API onto Log4j 2 (add log4j-core as well)");
        retired("org.codehaus.jackson:jackson-mapper-asl", "com.fasterxml.jackson.core:jackson-databind", "Jackson 1.x is end of life", "package org.codehaus.jackson -> com.fasterxml.jackson");
        retired("org.codehaus.jackson:jackson-core-asl", "com.fasterxml.jackson.core:jackson-core", "Jackson 1.x is end of life", "package org.codehaus.jackson -> com.fasterxml.jackson");
        retired("commons-lang:commons-lang", "org.apache.commons:commons-lang3", "Commons Lang 2.x is no longer developed", "package org.apache.commons.lang -> org.apache.commons.lang3");
    }
}
