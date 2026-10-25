package in.slashmark.maven.tools;

import in.slashmark.maven.bytecode.ClassFile;
import in.slashmark.maven.bytecode.Jar;
import in.slashmark.maven.cli.Args;
import in.slashmark.maven.cli.Command;
import in.slashmark.maven.cli.Ctx;
import in.slashmark.maven.cli.Exit;
import in.slashmark.maven.cli.Project;
import in.slashmark.maven.cli.Ui;
import in.slashmark.maven.cli.UsageException;
import in.slashmark.maven.model.MavenVersion;
import in.slashmark.maven.resolve.DepNode;
import in.slashmark.maven.util.HttpException;
import in.slashmark.maven.util.Json;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/** JDK &amp; Jakarta Readiness Scanner: Removed JDK APIs, class-file levels and javax-to-jakarta needs for a target Java. */
public final class Jdk extends Command {
    @Override public String name() { return "jdk"; }
    @Override public String title() { return "JDK & Jakarta Readiness Scanner"; }
    @Override public String group() { return "Upgrade intelligence"; }
    @Override public String summary() { return "Removed JDK APIs, class-file levels and javax-to-jakarta needs for a target Java"; }

    @Override
    public Set<String> flags() { return Set.of("include-test", "no-deps"); }

    @Override
    public String help() {
        return String.join("\n",
                "Usage: sm-maven jdk [group:artifact[:version]] --target <17|21|25> [options]",
                "",
                summary() + ".",
                "",
                "Scans the project's compiled classes (target/classes) and every dependency JAR for:",
                "  - JDK APIs removed by the target release (JAXB, JAX-WS, CORBA, Nashorn, Pack200, RMI",
                "    activation...) unless a dependency on the classpath provides them",
                "  - Security Manager use (deprecated for removal in 17, permanently disabled in 24),",
                "    Thread.stop/suspend/resume, finalization, boxed-primitive constructors, java.applet",
                "  - internal APIs: sun.misc.Unsafe (memory access deprecated in 23, warns in 24+) and",
                "    strongly encapsulated sun.*, com.sun.* and jdk.internal.* packages (Java 17+)",
                "  - class files compiled for a newer Java than the target",
                "  - javax.* packages that moved to jakarta.* (with the Jakarta replacement coordinates)",
                "  - Multi-Release JARs (which overlay the target uses) and bytecode tools (ASM, Lombok)",
                "    too old for the target",
                "Every finding names its location: the class and the member it uses.",
                "",
                "Options:",
                "  --target <N>           Java release to check against (default 21)",
                "  --fail-on <level>      Exit 1 on: error, warning (default) or none",
                "  --include-test         Also scan test-scoped dependencies",
                "  --no-deps              Only scan the project's own classes",
                "",
                "Examples:",
                "  sm-maven jdk --target 17",
                "  sm-maven jdk --target 25 --json",
                "  sm-maven jdk com.acme:acme-core:2.0.0 --target 11");
    }

    // ---------------------------------------------------------------- knowledge

    /** A JDK API that is removed, disabled, encapsulated or deprecated for removal. */
    static final class Rule {
        final String id;
        /** Internal-name prefix of types ("javax/xml/bind/"), an exact type, or "owner#member". */
        final String match;
        /** Release from which it is a warning (deprecated / internal), 0 = never. */
        final int warnFrom;
        /** Release from which it breaks (removed / disabled / throws), 0 = never. */
        final int errorFrom;
        final String what, errorText, warnText, fix;

        Rule(String id, String match, int warnFrom, int errorFrom, String what, String warnText, String errorText, String fix) {
            this.id = id;
            this.match = match;
            this.warnFrom = warnFrom;
            this.errorFrom = errorFrom;
            this.what = what;
            this.warnText = warnText;
            this.errorText = errorText;
            this.fix = fix;
        }

        boolean memberRule() { return match.contains("#"); }

        boolean matchesType(String internal) { return match.endsWith("/") ? internal.startsWith(match) : internal.equals(match); }

        String level(int target) {
            if (errorFrom > 0 && target >= errorFrom) return "error";
            if (warnFrom > 0 && target >= warnFrom) return "warning";
            return null;
        }
    }

    static final List<Rule> RULES = new ArrayList<>();
    /** javax package (internal-name prefix or exact class) -> {jakarta package, groupId:artifactId, known version}. */
    static final Map<String, String[]> JAKARTA = new LinkedHashMap<>();
    /** Exported com.sun.* / sun.* packages that are NOT encapsulated. */
    static final List<String> EXPORTED_INTERNALS = List.of("sun/misc/", "sun/reflect/", "com/sun/net/httpserver/", "com/sun/management/",
            "com/sun/nio/sctp/", "com/sun/nio/file/", "com/sun/jdi/", "com/sun/security/auth/", "com/sun/security/jgss/", "com/sun/source/",
            "com/sun/tools/javac/Main", "com/sun/tools/attach/", "com/sun/tools/jconsole/", "com/sun/java/accessibility/util/", "com/sun/jndi/ldap/spi/",
            "com/sun/crypto/provider/SunJCE");
    /** Bytecode tools: g:a -> {first version supporting 17, 21, 25}. */
    static final Map<String, String[]> TOOLING = new LinkedHashMap<>();

    static {
        String jaxbFix = "add jakarta.xml.bind:jakarta.xml.bind-api plus a runtime (org.glassfish.jaxb:jaxb-runtime), or javax.xml.bind:jaxb-api 2.3.x to keep javax.*";
        RULES.add(new Rule("jaxb-removed", "javax/xml/bind/", 0, 11, "JAXB (javax.xml.bind)", null, "removed from the JDK in Java 11 (JEP 320)", jaxbFix));
        RULES.add(new Rule("activation-removed", "javax/activation/", 0, 11, "JavaBeans Activation (javax.activation)", null, "removed from the JDK in Java 11 (JEP 320)", "add jakarta.activation:jakarta.activation-api"));
        RULES.add(new Rule("jaxws-removed", "javax/xml/ws/", 0, 11, "JAX-WS (javax.xml.ws)", null, "removed from the JDK in Java 11 (JEP 320)", "add jakarta.xml.ws:jakarta.xml.ws-api plus a runtime (com.sun.xml.ws:jaxws-rt)"));
        RULES.add(new Rule("jws-removed", "javax/jws/", 0, 11, "Web Services metadata (javax.jws)", null, "removed from the JDK in Java 11 (JEP 320)", "add jakarta.jws:jakarta.jws-api"));
        RULES.add(new Rule("saaj-removed", "javax/xml/soap/", 0, 11, "SAAJ (javax.xml.soap)", null, "removed from the JDK in Java 11 (JEP 320)", "add jakarta.xml.soap:jakarta.xml.soap-api"));
        for (String c : new String[] {"PostConstruct", "PreDestroy", "Resource", "Resources", "Generated"}) {
            RULES.add(new Rule("common-annotations-removed", "javax/annotation/" + c, 0, 11, "Common Annotations (javax.annotation." + c + ")", null,
                    "removed from the JDK in Java 11 (JEP 320)", "add jakarta.annotation:jakarta.annotation-api (or javax.annotation:javax.annotation-api 1.3.2)"));
        }
        for (String c : new String[] {"InvalidTransactionException", "TransactionRequiredException", "TransactionRolledbackException"}) {
            RULES.add(new Rule("jta-removed", "javax/transaction/" + c, 0, 11, "JTA exceptions (javax.transaction." + c + ")", null,
                    "removed from the JDK in Java 11 (JEP 320)", "add jakarta.transaction:jakarta.transaction-api"));
        }
        RULES.add(new Rule("corba-removed", "org/omg/", 0, 11, "CORBA (org.omg)", null, "removed from the JDK in Java 11 (JEP 320)", "use a standalone ORB such as org.glassfish.corba:glassfish-corba-orb"));
        RULES.add(new Rule("corba-removed", "javax/rmi/CORBA/", 0, 11, "RMI-IIOP (javax.rmi.CORBA)", null, "removed from the JDK in Java 11 (JEP 320)", "use a standalone ORB such as org.glassfish.corba:glassfish-corba-orb"));
        RULES.add(new Rule("pack200-removed", "java/util/jar/Pack200", 0, 14, "Pack200 (java.util.jar.Pack200)", null, "removed in Java 14 (JEP 367)", "use plain JARs, or org.apache.commons:commons-compress Pack200"));
        RULES.add(new Rule("nashorn-removed", "jdk/nashorn/", 0, 15, "Nashorn JavaScript engine (jdk.nashorn)", null, "removed in Java 15 (JEP 372)", "add org.openjdk.nashorn:nashorn-core or move to GraalJS"));
        RULES.add(new Rule("rmi-activation-removed", "java/rmi/activation/", 0, 17, "RMI Activation (java.rmi.activation)", null, "removed in Java 17 (JEP 407)", "use plain RMI or another remoting mechanism"));
        RULES.add(new Rule("compiler-removed", "java/lang/Compiler", 9, 21, "java.lang.Compiler", "deprecated for removal since Java 9", "removed in Java 21", "remove the call (it was a no-op)"));
        RULES.add(new Rule("applet-deprecated", "java/applet/", 17, 0, "Applet API (java.applet)", "deprecated for removal since Java 17 (JEP 398)", null, "remove applet code"));
        RULES.add(new Rule("security-manager", "java/lang/System#setSecurityManager", 17, 18, "System.setSecurityManager",
                "deprecated for removal since Java 17 (JEP 411)", "throws UnsupportedOperationException since Java 18 unless -Djava.security.manager=allow, always since Java 24 (JEP 486)",
                "remove Security Manager installation; use OS/container isolation"));
        RULES.add(new Rule("security-manager", "java/lang/System#getSecurityManager", 17, 0, "System.getSecurityManager",
                "deprecated for removal since Java 17 (JEP 411); always returns null since Java 24 (JEP 486)", null, "remove Security Manager checks"));
        RULES.add(new Rule("security-manager", "java/lang/SecurityManager", 17, 0, "java.lang.SecurityManager",
                "deprecated for removal since Java 17 (JEP 411); permanently disabled since Java 24 (JEP 486)", null, "remove Security Manager code"));
        RULES.add(new Rule("security-manager", "java/security/AccessController", 17, 0, "java.security.AccessController",
                "deprecated for removal since Java 17 (JEP 411); doPrivileged just runs the action since Java 24", null, "call the action directly"));
        RULES.add(new Rule("thread-stop", "java/lang/Thread#stop", 9, 20, "Thread.stop", "deprecated for removal", "throws UnsupportedOperationException since Java 20", "use interruption (Thread.interrupt) instead"));
        RULES.add(new Rule("thread-suspend", "java/lang/Thread#suspend", 14, 19, "Thread.suspend", "deprecated for removal since Java 14", "throws UnsupportedOperationException since Java 19, removed in Java 23", "use wait/notify or java.util.concurrent locks"));
        RULES.add(new Rule("thread-suspend", "java/lang/Thread#resume", 14, 19, "Thread.resume", "deprecated for removal since Java 14", "throws UnsupportedOperationException since Java 19, removed in Java 23", "use wait/notify or java.util.concurrent locks"));
        RULES.add(new Rule("finalization", "java/lang/Runtime#runFinalization", 18, 0, "Runtime.runFinalization", "deprecated for removal since Java 18 (JEP 421)", null, "use try-with-resources or java.lang.ref.Cleaner"));
        RULES.add(new Rule("finalization", "java/lang/System#runFinalization", 18, 0, "System.runFinalization", "deprecated for removal since Java 18 (JEP 421)", null, "use try-with-resources or java.lang.ref.Cleaner"));
        for (String b : new String[] {"Integer", "Long", "Short", "Byte", "Character", "Boolean", "Float", "Double"}) {
            RULES.add(new Rule("boxing-constructor", "java/lang/" + b + "#<init>", 16, 0, "new " + b + "(...)", "deprecated for removal since Java 16 (JEP 390)", null, "use " + b + ".valueOf(...)"));
        }

        jakarta("javax/xml/bind/", "jakarta.xml.bind", "jakarta.xml.bind:jakarta.xml.bind-api", "4.0.2");
        jakarta("javax/activation/", "jakarta.activation", "jakarta.activation:jakarta.activation-api", "2.1.3");
        jakarta("javax/xml/ws/", "jakarta.xml.ws", "jakarta.xml.ws:jakarta.xml.ws-api", "4.0.2");
        jakarta("javax/jws/", "jakarta.jws", "jakarta.jws:jakarta.jws-api", "3.0.0");
        jakarta("javax/xml/soap/", "jakarta.xml.soap", "jakarta.xml.soap:jakarta.xml.soap-api", "3.0.2");
        for (String c : new String[] {"PostConstruct", "PreDestroy", "Resource", "Resources", "Generated", "ManagedBean", "Priority"}) {
            jakarta("javax/annotation/" + c, "jakarta.annotation", "jakarta.annotation:jakarta.annotation-api", "2.1.1");
        }
        jakarta("javax/annotation/security/", "jakarta.annotation.security", "jakarta.annotation:jakarta.annotation-api", "2.1.1");
        jakarta("javax/annotation/sql/", "jakarta.annotation.sql", "jakarta.annotation:jakarta.annotation-api", "2.1.1");
        jakarta("javax/servlet/jsp/", "jakarta.servlet.jsp", "jakarta.servlet.jsp:jakarta.servlet.jsp-api", "3.1.1");
        jakarta("javax/servlet/", "jakarta.servlet", "jakarta.servlet:jakarta.servlet-api", "6.0.0");
        jakarta("javax/persistence/", "jakarta.persistence", "jakarta.persistence:jakarta.persistence-api", "3.1.0");
        jakarta("javax/validation/", "jakarta.validation", "jakarta.validation:jakarta.validation-api", "3.0.2");
        jakarta("javax/ws/rs/", "jakarta.ws.rs", "jakarta.ws.rs:jakarta.ws.rs-api", "3.1.0");
        jakarta("javax/inject/", "jakarta.inject", "jakarta.inject:jakarta.inject-api", "2.0.1");
        jakarta("javax/ejb/", "jakarta.ejb", "jakarta.ejb:jakarta.ejb-api", "4.0.1");
        jakarta("javax/faces/", "jakarta.faces", "jakarta.faces:jakarta.faces-api", "4.0.1");
        jakarta("javax/json/bind/", "jakarta.json.bind", "jakarta.json.bind:jakarta.json.bind-api", "3.0.1");
        jakarta("javax/json/", "jakarta.json", "jakarta.json:jakarta.json-api", "2.1.3");
        jakarta("javax/mail/", "jakarta.mail", "jakarta.mail:jakarta.mail-api", "2.1.3");
        jakarta("javax/transaction/", "jakarta.transaction", "jakarta.transaction:jakarta.transaction-api", "2.0.1");
        jakarta("javax/websocket/", "jakarta.websocket", "jakarta.websocket:jakarta.websocket-api", "2.1.1");
        jakarta("javax/enterprise/", "jakarta.enterprise", "jakarta.enterprise:jakarta.enterprise.cdi-api", "4.0.1");
        jakarta("javax/interceptor/", "jakarta.interceptor", "jakarta.interceptor:jakarta.interceptor-api", "2.1.0");
        jakarta("javax/jms/", "jakarta.jms", "jakarta.jms:jakarta.jms-api", "3.1.0");
        jakarta("javax/batch/", "jakarta.batch", "jakarta.batch:jakarta.batch-api", "2.1.1");
        jakarta("javax/el/", "jakarta.el", "jakarta.el:jakarta.el-api", "5.0.1");
        jakarta("javax/resource/", "jakarta.resource", "jakarta.resource:jakarta.resource-api", "2.1.0");
        jakarta("javax/security/enterprise/", "jakarta.security.enterprise", "jakarta.security.enterprise:jakarta.security.enterprise-api", "3.0.0");
        jakarta("javax/security/auth/message/", "jakarta.security.auth.message", "jakarta.authentication:jakarta.authentication-api", "3.0.0");
        jakarta("javax/security/jacc/", "jakarta.security.jacc", "jakarta.authorization:jakarta.authorization-api", "2.1.0");

        TOOLING.put("org.ow2.asm:asm", new String[] {"9.1", "9.5", "9.8"});
        TOOLING.put("org.projectlombok:lombok", new String[] {"1.18.22", "1.18.30", "1.18.40"});
    }

    private static void jakarta(String javax, String pkg, String ga, String version) { JAKARTA.put(javax, new String[] {pkg, ga, version}); }

    /** The Jakarta mapping for a javax type (null when the type did not move). */
    static Map.Entry<String, String[]> jakartaFor(String internal) {
        if (!internal.startsWith("javax/") || internal.startsWith("javax/transaction/xa/")) return null;
        Map.Entry<String, String[]> best = null;
        for (Map.Entry<String, String[]> e : JAKARTA.entrySet()) {
            String k = e.getKey();
            boolean m = k.endsWith("/") ? internal.startsWith(k) : internal.equals(k);
            if (m && (best == null || k.length() > best.getKey().length())) best = e;
        }
        return best;
    }

    static boolean encapsulated(String internal) {
        boolean internalPkg = internal.startsWith("sun/") || internal.startsWith("com/sun/") || internal.startsWith("jdk/internal/");
        if (!internalPkg) return false;
        for (String ok : EXPORTED_INTERNALS) if (ok.endsWith("/") ? internal.startsWith(ok) : internal.equals(ok)) return false;
        return true;
    }

    // ---------------------------------------------------------------- scanning

    /** One unit of bytecode: a module's classes or a dependency JAR. */
    static final class Unit {
        final String label;
        final boolean project;
        final Jar jar;
        final DepNode node;

        Unit(String label, boolean project, Jar jar, DepNode node) {
            this.label = label;
            this.project = project;
            this.jar = jar;
            this.node = node;
        }
    }

    static final class Finding {
        final String level, category, rule, artifact, cls, member, api, detail, fix;
        Object replacement;

        Finding(String level, String category, String rule, String artifact, String cls, String member, String api, String detail, String fix) {
            this.level = level;
            this.category = category;
            this.rule = rule;
            this.artifact = artifact;
            this.cls = cls;
            this.member = member;
            this.api = api;
            this.detail = detail;
            this.fix = fix;
        }

        Object toJson() {
            return Json.obj("level", level, "category", category, "rule", rule, "artifact", artifact,
                    "location", cls == null ? null : Json.obj("class", cls, "member", member), "api", api, "detail", detail, "fix", fix, "replacement", replacement);
        }
    }

    @Override
    public int run(Ctx ctx, Args args) throws Exception {
        Ui ui = ctx.ui;
        String t = args.get("target");
        if (t == null || t.equals("true")) t = "21";
        int target = UpgradeKit.parseRelease(t);
        if (target < 8 || target > 40) throw new UsageException("--target expects a Java release such as 17, 21 or 25, got '" + t + "'");
        String failOn = args.get("fail-on", "warning");
        if (!List.of("error", "warning", "none").contains(failOn)) throw new UsageException("--fail-on expects error, warning or none, got '" + failOn + "'");
        boolean includeTest = args.flag("include-test"), noDeps = args.flag("no-deps");
        int targetMajor = UpgradeKit.majorFor(target);

        Ctx.Target tg = ctx.target(args, 0);
        List<Unit> units = new ArrayList<>();
        int release = 0;
        Set<String> scopes = includeTest ? null : Set.of("compile", "runtime", "provided", "system");
        if (tg.project != null) {
            release = UpgradeKit.projectRelease(tg.project);
            for (Project.Module m : tg.project.codeModules()) {
                if (m.classesDir() != null) units.add(new Unit(m.model.pom.artifactId, true, Jar.read(m.classesDir()), null));
            }
        } else {
            Jar j = ctx.jar(tg.artifact);
            if (j != null) units.add(new Unit(tg.artifact.toString(), false, j, null));
        }
        if (!noDeps) {
            Set<String> reactor = ctx.models.reactorGavs();
            List<DepNode> deps = new ArrayList<>();
            for (DepNode n : tg.dependencies(scopes)) if (!reactor.contains(n.gav().toString()) && !"pom".equals(n.type)) deps.add(n);
            ui.progress("Downloading " + deps.size() + " dependency JARs...");
            List<Jar> jars = ctx.http.parallelOrNull(deps, n -> ctx.jar(n.gav()));
            ui.progressDone();
            for (int i = 0; i < deps.size(); i++) if (jars.get(i) != null) units.add(new Unit(deps.get(i).gav().toString(), false, jars.get(i), deps.get(i)));
        }

        // Which unit defines each class (to know when a removed JDK API is provided by a dependency).
        Map<String, String> definedBy = new LinkedHashMap<>();
        int classCount = 0;
        for (Unit u : units) {
            for (ClassFile cf : u.jar.classes()) {
                definedBy.putIfAbsent(cf.name, u.label);
                classCount++;
            }
        }

        List<Finding> findings = new ArrayList<>();
        Map<String, Object> jakartaNeeded = new LinkedHashMap<>();
        // ---- project configuration
        if (release > 0 && release > target) {
            findings.add(new Finding("error", "config", "release-above-target", tg.label, null, null, "maven.compiler.release " + release,
                    "the project compiles for Java " + release + ", which cannot run on Java " + target, "run on Java " + release + "+ or lower maven.compiler.release"));
        } else if (release > 0 && release < target) {
            findings.add(new Finding("info", "config", "release-below-target", tg.label, null, null, "maven.compiler.release " + release,
                    "the project compiles for Java " + release + "; it runs on Java " + target + " as is", "raise maven.compiler.release to " + target + " once every module is ready"));
        }

        for (Unit u : units) {
            scanUnit(ctx, u, target, targetMajor, definedBy, findings, jakartaNeeded);
        }

        // ---- tooling too old for the target
        for (Unit u : units) {
            if (u.node == null) continue;
            String[] mins = TOOLING.get(u.node.ga());
            if (mins == null) continue;
            String need = target >= 25 ? mins[2] : target >= 21 ? mins[1] : target >= 17 ? mins[0] : null;
            if (need != null && MavenVersion.compare(u.node.version, need) < 0) {
                findings.add(new Finding("error", "tooling", "bytecode-tool-too-old", u.label, null, null, u.node.ga(),
                        u.node.ga() + " " + u.node.version + " cannot read Java " + target + " class files (support starts with " + need + ")",
                        "upgrade to " + u.node.ga() + ":" + need + " or newer"));
            }
        }

        // ---- replacement coordinates for Jakarta (newest release on the repository, else the known one)
        for (Finding f : findings) {
            if (!"jakarta".equals(f.category)) continue;
            Object rep = f.replacement;
            if (rep instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> m = (Map<String, Object>) rep;
                String ga = (String) m.get("artifact");
                if (!m.containsKey("version")) m.put("version", newestOr(ctx, ga, (String) m.get("knownVersion")));
                m.remove("knownVersion");
            }
        }

        int errors = 0, warnings = 0, infos = 0;
        for (Finding f : findings) {
            if (f.level.equals("error")) errors++;
            else if (f.level.equals("warning")) warnings++;
            else infos++;
        }
        boolean ready = errors == 0;
        int exit = ("error".equals(failOn) && errors > 0) || ("warning".equals(failOn) && errors + warnings > 0) ? Exit.ISSUES : Exit.OK;

        if (ui.json) {
            List<Object> fj = new ArrayList<>();
            for (Finding f : findings) fj.add(f.toJson());
            List<Object> jk = new ArrayList<>(jakartaNeeded.values());
            ui.emitJson(Json.obj("target", target, "project", tg.project == null ? null : tg.label, "artifact", tg.artifact == null ? null : tg.label,
                    "release", release > 0 ? release : null, "scanned", Json.obj("units", units.size(), "classes", classCount),
                    "ready", ready, "summary", Json.obj("errors", errors, "warnings", warnings, "info", infos),
                    "jakarta", jk, "findings", fj));
            return exit;
        }

        ui.title(title() + " " + ui.dot() + " " + tg.label + ui.dim("  target Java " + target + (release > 0 ? ", compiles for Java " + release : "")));
        ui.note("Scanned " + Ui.plural(units.size(), "unit") + " (" + Ui.plural(classCount, "class", "classes") + ")");
        String[][] sections = {
                {"config", "Project configuration"}, {"removed-api", "Removed or disabled JDK APIs"}, {"encapsulated", "Internal and encapsulated JDK APIs"},
                {"deprecated", "Deprecated for removal"}, {"class-version", "Class-file versions above Java " + target}, {"jakarta", "javax -> jakarta migration"},
                {"multi-release", "Multi-Release JARs"}, {"tooling", "Bytecode tools"}};
        for (String[] s : sections) {
            List<Finding> fs = new ArrayList<>();
            for (Finding f : findings) if (f.category.equals(s[0])) fs.add(f);
            if (fs.isEmpty()) continue;
            ui.section(s[1]);
            for (Finding f : fs) {
                String head = f.api + ui.dim("  " + f.detail);
                if (f.level.equals("error")) ui.fail(head);
                else if (f.level.equals("warning")) ui.warn(head);
                else ui.line(ui.info() + " " + head);
                if (f.cls != null) ui.line("    " + ui.dim("at ") + f.artifact + ui.dim(": ") + f.cls + (f.member == null ? "" : " " + ui.arrow() + " " + f.member));
                else if (!f.artifact.equals(tg.label)) ui.line("    " + ui.dim("in ") + f.artifact);
                if (f.fix != null) ui.line("    " + ui.dim("fix: ") + f.fix);
            }
        }
        if (!jakartaNeeded.isEmpty()) {
            ui.section("Jakarta replacements");
            for (Object o : jakartaNeeded.values()) {
                String ga = Json.str(o, "artifact");
                Finding any = null;
                for (Finding f : findings) if ("jakarta".equals(f.category) && f.replacement != null && ga.equals(Json.str(f.replacement, "artifact"))) { any = f; break; }
                String v = any == null ? null : Json.str(any.replacement, "version");
                ui.line(Json.str(o, "javax") + " " + ui.arrow() + " " + Json.str(o, "jakarta") + "  " + ui.cyan(ga + (v == null ? "" : ":" + v)));
            }
        }
        ui.println();
        if (findings.isEmpty()) ui.good("Ready for Java " + target + ": nothing found.");
        else if (ready) ui.println(ui.bold(ui.green("Runs on Java " + target)) + " with " + Ui.plural(warnings, "warning") + " and " + Ui.plural(infos, "note") + " to address.");
        else ui.println(ui.bold(ui.red("Not ready for Java " + target)) + ": " + Ui.plural(errors, "blocking problem") + ", " + Ui.plural(warnings, "warning") + ".");
        return exit;
    }

    private void scanUnit(Ctx ctx, Unit u, int target, int targetMajor, Map<String, String> definedBy, List<Finding> findings, Map<String, Object> jakartaNeeded) {
        Jar jar = u.jar;
        // ---- class-file versions
        if (u.project) {
            Map<Integer, List<String>> above = new LinkedHashMap<>();
            for (ClassFile cf : jar.classes()) if (cf.major > targetMajor) above.computeIfAbsent(cf.major, k -> new ArrayList<>()).add(cf.className());
            for (Map.Entry<Integer, List<String>> e : above.entrySet()) {
                findings.add(new Finding("error", "class-version", "class-file-too-new", u.label, e.getValue().get(0), null,
                        "class file " + e.getKey() + " (Java " + UpgradeKit.javaOf(e.getKey()) + ")",
                        Ui.plural(e.getValue().size(), "class", "classes") + " compiled for Java " + UpgradeKit.javaOf(e.getKey()) + " cannot load on Java " + target,
                        "compile with --release " + target + " or run on Java " + UpgradeKit.javaOf(e.getKey())));
            }
        } else {
            int max = jar.maxClassMajor();
            if (max > targetMajor) {
                String first = null;
                for (ClassFile cf : jar.classes()) if (cf.major == max) { first = cf.className(); break; }
                findings.add(new Finding("error", "class-version", "class-file-too-new", u.label, first, null,
                        u.label + " class file " + max + " (Java " + UpgradeKit.javaOf(max) + ")",
                        "compiled for Java " + UpgradeKit.javaOf(max) + ": UnsupportedClassVersionError on Java " + target,
                        "use an older version that supports Java " + target + " (sm-maven safe " + (u.node == null ? u.label.substring(0, u.label.lastIndexOf(':')) : u.node.ga()) + " --release " + target + ")"));
            }
        }
        // ---- Multi-Release JARs
        if (jar.multiRelease()) {
            Set<Integer> overlays = new TreeSet<>();
            for (String e : jar.entryNames()) {
                if (!e.startsWith("META-INF/versions/")) continue;
                String rest = e.substring(18);
                int slash = rest.indexOf('/');
                if (slash > 0) try { overlays.add(Integer.parseInt(rest.substring(0, slash))); } catch (NumberFormatException ignored) {}
            }
            int used = 0;
            for (int v : overlays) if (v <= target) used = Math.max(used, v);
            Finding f = new Finding("info", "multi-release", "multi-release-jar", u.label, null, null, u.label + " is a Multi-Release JAR",
                    "overlays for Java " + overlays + "; on Java " + target + " " + (used == 0 ? "only the base classes are used" : "the Java " + used + " overlay is used"), null);
            findings.add(f);
            for (String e : jar.entryNames()) {
                if (!e.startsWith("META-INF/versions/") || !e.endsWith(".class")) continue;
                String rest = e.substring(18);
                int slash = rest.indexOf('/');
                int v;
                try { v = Integer.parseInt(rest.substring(0, slash)); } catch (NumberFormatException | StringIndexOutOfBoundsException x) { continue; }
                ClassFile cf = jar.classFile(e);
                if (cf != null && cf.major > UpgradeKit.majorFor(v)) {
                    findings.add(new Finding("warning", "multi-release", "overlay-class-too-new", u.label, cf.className(), null, "META-INF/versions/" + v,
                            "overlay class compiled for Java " + UpgradeKit.javaOf(cf.major) + " in the Java " + v + " folder", "report it to the library"));
                    break;
                }
            }
        }
        // ---- javax packages provided by this JAR (artifact still on the javax namespace)
        if (!u.project) {
            Map<String, Integer> javaxPkgs = new LinkedHashMap<>();
            for (ClassFile cf : jar.classes()) {
                Map.Entry<String, String[]> j = jakartaFor(cf.name);
                if (j != null) javaxPkgs.merge(j.getKey(), 1, Integer::sum);
            }
            for (Map.Entry<String, Integer> e : javaxPkgs.entrySet()) {
                String[] j = JAKARTA.get(e.getKey());
                Finding f = new Finding("warning", "jakarta", "javax-artifact", u.label, null, null, u.label + " provides " + e.getKey().replace('/', '.').replaceAll("\\.$", ""),
                        "javax namespace; Jakarta EE 9+ uses " + j[0], "replace it with " + j[1]);
                f.replacement = Json.obj("artifact", j[1], "package", j[0], "knownVersion", j[2]);
                findings.add(f);
                jakartaNeeded.putIfAbsent(j[1], Json.obj("javax", e.getKey().replace('/', '.').replaceAll("\\.$", ""), "jakarta", j[0], "artifact", j[1]));
            }
        }
        // ---- references
        for (ClassFile cf : jar.classes()) {
            String me = cf.className();
            // Per rule: referenced members of the matching types / the matching members.
            Map<String, Set<String>> hits = new LinkedHashMap<>();
            Map<String, Rule> ruleOf = new LinkedHashMap<>();
            Map<String, Set<String>> jakartaHits = new LinkedHashMap<>();
            Map<String, Set<String>> internalHits = new LinkedHashMap<>();
            for (String ref : cf.referencedClasses) {
                if (ref.equals(cf.name)) continue;
                boolean provided = definedBy.containsKey(ref);
                String providedBy = definedBy.get(ref);
                for (Rule r : RULES) {
                    if (r.memberRule() || !r.matchesType(ref)) continue;
                    String key = r.id + "|" + r.match + "|" + (provided ? providedBy : "");
                    ruleOf.put(key, r);
                    hits.computeIfAbsent(key, k -> new LinkedHashSet<>()).addAll(membersOf(cf, ref));
                }
                Map.Entry<String, String[]> jk = jakartaFor(ref);
                if (jk != null && !(provided && u.label.equals(providedBy))) jakartaHits.computeIfAbsent(jk.getKey(), k -> new LinkedHashSet<>()).addAll(membersOf(cf, ref));
                if (!provided && encapsulated(ref)) internalHits.computeIfAbsent(ref, k -> new LinkedHashSet<>()).addAll(membersOf(cf, ref));
                if (ref.equals("sun/misc/Unsafe") && !provided) internalHits.computeIfAbsent(ref, k -> new LinkedHashSet<>()).addAll(membersOf(cf, ref));
            }
            for (ClassFile.Ref ref : cf.references) {
                for (Rule r : RULES) {
                    if (!r.memberRule()) continue;
                    String[] om = r.match.split("#");
                    if (!ref.owner.equals(om[0]) || !ref.name.equals(om[1])) continue;
                    String key = r.id + "|" + r.match + "|";
                    ruleOf.put(key, r);
                    hits.computeIfAbsent(key, k -> new LinkedHashSet<>()).add(simple(ref.owner) + "." + ClassFile.prettyDescriptor(ref.name, ref.descriptor));
                }
            }
            // Object.finalize overrides.
            for (ClassFile.Member m : cf.methods) {
                if (m.name.equals("finalize") && m.descriptor.equals("()V") && !m.isStatic() && target >= 18) {
                    findings.add(new Finding("warning", "deprecated", "finalization", u.label, me, "finalize()", "Object.finalize override",
                            "finalization is deprecated for removal since Java 18 (JEP 421)", "use try-with-resources or java.lang.ref.Cleaner"));
                }
            }
            // A member hit (System.getSecurityManager) already covers the type in its descriptor (SecurityManager).
            Set<String> memberRuleIds = new LinkedHashSet<>();
            for (String k : hits.keySet()) if (ruleOf.get(k).memberRule()) memberRuleIds.add(ruleOf.get(k).id);
            hits.keySet().removeIf(k -> !ruleOf.get(k).memberRule() && memberRuleIds.contains(ruleOf.get(k).id));
            for (Map.Entry<String, Set<String>> e : hits.entrySet()) {
                Rule r = ruleOf.get(e.getKey());
                String providedBy = e.getKey().substring(e.getKey().lastIndexOf('|') + 1);
                String level = r.level(target);
                if (level == null) continue;
                String member = e.getValue().isEmpty() ? null : String.join(", ", e.getValue());
                if (!providedBy.isEmpty()) {
                    // A dependency provides the removed API, so it still links; only the jakarta finding matters.
                    if (!u.project) continue;
                    findings.add(new Finding("info", "removed-api", r.id, u.label, me, member, r.what,
                            r.errorText + "; provided here by " + providedBy, null));
                    continue;
                }
                boolean removal = level.equals("error");
                String cat = removal ? "removed-api" : "deprecated";
                findings.add(new Finding(level, cat, r.id, u.label, me, member, r.what, removal ? r.errorText : r.warnText, r.fix));
            }
            for (Map.Entry<String, Set<String>> e : internalHits.entrySet()) {
                String ref = e.getKey();
                String member = e.getValue().isEmpty() ? null : String.join(", ", e.getValue());
                if (ref.equals("sun/misc/Unsafe")) {
                    boolean memory = false;
                    for (String m : e.getValue()) if (m.matches("Unsafe\\.(get|put|allocate|reallocate|free|copy|set|compareAndSwap|compareAndExchange|arrayBase|arrayIndex|objectField|staticField).*")) memory = true;
                    String detail = "internal API (module jdk.unsupported)";
                    if (memory && target >= 24) detail += "; memory-access methods print a warning since Java 24 (JEP 498) and will be removed";
                    else if (memory && target >= 23) detail += "; memory-access methods are deprecated for removal since Java 23 (JEP 471)";
                    else detail += "; its memory-access methods are deprecated for removal (Java 23+)";
                    findings.add(new Finding("warning", "encapsulated", "sun-misc-unsafe", u.label, me, member, "sun.misc.Unsafe", detail,
                            "use VarHandle (java.lang.invoke) and the Foreign Function & Memory API (java.lang.foreign)"));
                    continue;
                }
                String level = target >= 17 ? "error" : target >= 9 ? "warning" : null;
                if (level == null) continue;
                findings.add(new Finding(level, "encapsulated", "jdk-internal", u.label, me, member, ref.replace('/', '.'),
                        target >= 17 ? "strongly encapsulated since Java 17 (JEP 403): IllegalAccessError at run time" : "internal JDK API; illegal-access warnings since Java 9",
                        "use the supported API, or --add-exports/--add-opens as a stop-gap"));
            }
            for (Map.Entry<String, Set<String>> e : jakartaHits.entrySet()) {
                String[] j = JAKARTA.get(e.getKey());
                String javax = e.getKey().endsWith("/") ? e.getKey().replace('/', '.').replaceAll("\\.$", "") : e.getKey().replace('/', '.');
                String member = e.getValue().isEmpty() ? null : String.join(", ", e.getValue());
                Finding f = new Finding("warning", "jakarta", "javax-usage", u.label, me, member, javax,
                        "Jakarta EE 9+ renamed it to " + j[0] + (e.getKey().endsWith("/") ? ".*" : ""), "change the imports to " + j[0] + " and depend on " + j[1]);
                f.replacement = Json.obj("artifact", j[1], "package", j[0], "knownVersion", j[2]);
                findings.add(f);
                jakartaNeeded.putIfAbsent(j[1], Json.obj("javax", javax, "jakarta", j[0], "artifact", j[1]));
            }
        }
    }

    /** Members of a type a class refers to, e.g. "DatatypeConverter.printBase64Binary(byte[])"; the type itself when no member is used. */
    private static Set<String> membersOf(ClassFile cf, String owner) {
        Set<String> out = new LinkedHashSet<>();
        for (ClassFile.Ref r : cf.references) {
            if (!r.owner.equals(owner)) continue;
            out.add(simple(owner) + "." + (r.kind == 'F' ? r.name : ClassFile.prettyDescriptor(r.name, r.descriptor)));
        }
        if (out.isEmpty()) out.add(owner.replace('/', '.'));
        return out;
    }

    private static String simple(String internal) {
        int s = internal.lastIndexOf('/');
        return s < 0 ? internal : internal.substring(s + 1);
    }

    private static String newestOr(Ctx ctx, String ga, String known) {
        String[] p = ga.split(":");
        try {
            List<String> vs = ctx.versions(p[0], p[1], true);
            if (!vs.isEmpty()) return vs.get(vs.size() - 1);
        } catch (HttpException e) {
            ctx.ui.debug("versions of " + ga + ": " + e.getMessage());
        }
        return known;
    }
}
