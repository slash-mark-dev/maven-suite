# Developer guide: implementing a Maven Suite tool

`sm-maven` is a zero-dependency Java 17 CLI (package `in.slashmark.maven`). The core engine is done and
tested; each tool is one class in `src/main/java/in/slashmark/maven/tools/` (stubs exist for all 25).

## Build and test

```bash
./build.sh test                                   # compile (-Xlint:all -Werror: NO warnings allowed) + unit + all e2e tests
java -cp build/classes:build/test in.slashmark.maven.e2e.RunE2E ThreatTests   # one e2e group only (after ./build.sh test compiled it)
```

The workspace has no internet access. Everything is tested against `src/test/java/in/slashmark/maven/mock/MockServer.java`,
a local stand-in for Maven Central, Central search, OSV, CISA KEV, FIRST EPSS, deps.dev, GitHub and javadoc.io,
backed by a generated repository (`FixtureData.java`, `Fixtures.java`). Read `FixtureData.java` to see exactly what exists.

## Tool contract

```java
public final class Foo extends Command {
    name()/title()/group()/summary()   // keep the values already in the stub
    help()                             // "Usage: sm-maven foo [args] [options]\n\n<description>\n\nOptions:\n  ...\n\nExamples:\n  ..."
                                       // (Main appends Command.COMMON_OPTIONS automatically; Watcher.HELP for watch tools)
    flags()                            // boolean options of this tool (so "--flag value" is not parsed as "--flag=value")
    run(Ctx ctx, Args args)            // returns Exit.OK (0) / Exit.ISSUES (1, problems found) ; throw UsageException for bad usage (2);
                                       // let HttpException/IOException propagate (3)
}
```

* Human output: `ctx.ui` (title/section/table/good/warn/fail/note/line, colours, `Ui.Table`). All of it is silent under `--json`.
* JSON: build `Map`/`List` structures (`Json.obj(...)`) and call `ctx.ui.emitJson(doc)` exactly once per run
  (watch tools: once per cycle, handled by `Watcher`). Keep JSON field names camelCase and stable.
* Progress for slow steps: `ctx.ui.progress("...")` + `ctx.ui.progressDone()` (stderr, TTY only).
* Every tool must work on the local project (`-f path/to/pom.xml`, default current folder) and, where it makes sense,
  on published coordinates given as the first positional (`g:a:v`, or `g:a` = latest release): use `ctx.target(args, 0)`.
* Never print secrets (passwords, tokens, webhook URLs).
* Unknown/unused options produce a warning automatically: read every option you support via `args.*`.

## What the core gives you (read the sources, they are documented)

| Need | Use |
|---|---|
| Project + modules, effective POMs | `ctx.project()` -> `Project` (modules, `Module.model.pom`, `classesDir()`), `ModelBuilder.Model` |
| Resolved dependency graphs (Maven-exact mediation) | `ctx.target(args, i)` -> `Target.graphs` / `Target.dependencies(scopes)`; `Graph.resolved()`, `Graph.conflicts`, `Graph.tree()`, `DepNode` (scope, depth, `pathString()`, `premanagedVersion`, `range`, `relocatedFrom`, `declaredLine`) |
| Re-resolve with changes | `ctx.resolver.resolve(model, opts)` with `Resolver.Options.pins / directOverrides / extraDirect` |
| Versions, ordering, ranges | `MavenVersion` (Maven-exact ordering, `isPreRelease`, `jumpTo`), `VersionRange`, `ctx.versions(g, a, stableOnly)` |
| Repository access | `ctx.repos.metadata(g,a)`, `ctx.repos.fetch(gav, classifier, ext)` (pom/jar/asc/sha1...), `ctx.repos.pom(gav)`, `ctx.jar(gav)` |
| Effective POM of any artifact | `ctx.models.buildRemote(gav)` (parents, BOMs, licenses, scm) |
| Vulnerabilities | `ctx.vulnerabilities(gavs)` (OSV), `analysis.Risk.assess(ctx, nodes, exploitData)` (+ KEV, EPSS, priority P1-P4, fix version) |
| Exploit data | `ctx.kev.catalog()`, `ctx.epss.scores(cves)` |
| Licenses | `analysis.Licenses.of(pom)` -> SPDX ids, `Licenses.category`, `bestOf`, `matches(spdx, patterns)` |
| Release timestamps / search | `ctx.search.versions(g,a,rows)`, `.version(g,a,v)`, `.group(g,rows)`, `.artifact(a,rows)` |
| deps.dev | `ctx.depsDev.versions(ga)`, `.version(ga,v)` (licenses, advisories, source repo), `.dependents(ga,v)`, `.project(id)` (OpenSSF Scorecard) |
| GitHub | `GitHub.repoFromUrl(url)`, `ctx.github.repo/releases/commitsSince/orgRepos/findFiles/file` |
| Bytecode | `bytecode.Jar` (entries, manifest, classes, native libs, nested jars, services, embedded pom.properties), `ClassFile`, `ApiDiff` (`Api.of(jar)`, `diff`, `Usage.of(consumerJars)`, `impacts`) |
| Watch tools | `watch.Watcher.run(ctx, args, tool, scope, noun, cycle, printer)` (state, `--watch`, `--interval`, alerts, NDJSON) |
| Alerts | `ctx.alerts()` (`watch.Alerts`: Slack, Teams, Discord, webhook with HMAC, e-mail SMTP, file) |
| Live mode | `ctx.live(0)` disables caching of metadata/advisory/search responses (Watcher does it in `--watch`) |
| Parallel HTTP | `ctx.http.parallel(list, fn)` / `parallelOrNull` |

## The fixture project (planted problems) — `tests/fixture-project`

Multi-module `com.acme.shop:shop-parent:3.2.0` with modules `app` (shop-app) and `lib` (shop-lib). The harness compiles
their sources into `target/classes`. Resolved trees (exactly what Maven resolves):

* **shop-app**: shop-lib (reactor) ; log4j-core 2.14.1 (CVE-2021-44228 critical + KEV + EPSS 0.94, 3 more log4j CVEs) ;
  jackson-databind **2.9.10.1** wins over 2.18.2 requested by acme-utils (silent downgrade, CVE-2020-36518) ;
  acme-core **1.0.0** wins over 1.1.0 (downgrade) ; acme-utils 1.2.0 ; javax.xml.bind:jaxb-api 2.3.1 ;
  commons-logging 1.2 **and** jcl-over-slf4j 1.7.36 (both contain `org.apache.commons.logging.Log`/`LogFactory`, different bytes) ;
  mysql:mysql-connector-java:8.0.33 **relocated** to com.mysql:mysql-connector-j:8.0.33 (runtime) ;
  com.acme:acme-fat:1.0.0 (shades log4j-core 2.14.1 classes + its pom.properties) ;
  org.example:widgets:1.0.0 (Apache-2.0; 2.0.0 is **BUSL-1.1**) ; org.example:ranged:[1.0,2.0) -> 1.1.0.
* **shop-lib**: guava 31.1-jre (2 CVEs, fixed 32.0.0-android) ; spring-beans 5.3.17 (CVE-2022-22965 critical + KEV) ;
  com.acme:acme-agent:1.0.0 (**1.0.1 released 1 day ago**: new signing key, Premain-Class, native .so, Runtime.exec + URLClassLoader to an IP) ;
  org.example:gpl-lib:1.0 (GPL-3.0-only) ; log4j-api 2.17.1 (test).
* App code (`App.java`) calls `Client.connect(String)` (removed in acme-core 2.0.0), extends `Config` (final in 2.0.0),
  implements `Handler` (new abstract method in 2.0.0), uses `javax.xml.bind.DatatypeConverter`, `System.getSecurityManager()`,
  `sun.misc.Unsafe`. acme-core 2.0.0 is compiled for Java 17 (class major 61); everything else for Java 8.
* Look-alike namespace `com.acrne` (imitates `com.acme`) and publicly claimed internal namespace `com.acme.internal` exist on "Central".
* GitHub: apache/logging-log4j2, FasterXML/jackson-databind, google/guava, spring-projects/spring-framework (active),
  acme-corp/acme-core (quiet), acme-corp/acme-utils (**archived**, no commits), acme-corp/acme-agent; org `slash-mark-dev` has
  repos api-service (pom.xml with log4j 2.14.1) and web-portal (spring-beans 6.1.14 + guava 33.4.8-jre).
* deps.dev: dependents counts and Scorecards for the main projects (see `FixtureData`).

Mock-only extras: `/mirror/maven2` (250 ms latency), `/flaky/maven2` (503), `/secure/maven2` (needs basic auth
`deploy:s3cret`), `/hooks/<name>` webhook sink (`h.hookLog()`, `h.clearHooks()`; `/hooks/fail...` returns 500),
`POST /_admin/publish` (`{"gav":"g:a:v","deps":[...],"license":"MIT","key":"...","daysAgo":0}`) and
`POST /_admin/advisory` (an OSV record) via `h.post(path, body)` to change "live" data between runs.

## Tests

Write `src/test/java/in/slashmark/maven/e2e/<Group>Tests.java` with `public static void run(Harness h)`.
Use `h.onProject("tool", args...)` (adds `-f <fixture pom>`), `h.run(...)`, `h.runWith(envMap, ...)`,
`Result.json()` / `jsonLines()` and `h.check(name, condition, detailForFailure)`. Assert real behaviour: exit codes, the
planted findings (by id/coordinates), JSON fields, output formats, edge cases (bad args -> 2, unknown artifact).
Each tool needs at least ~8 meaningful checks. Pass `result` as the detail so failures are debuggable.

Do not edit other tools, `Harness`, `RunE2E`, `Fixtures` or `FixtureData`. Prefer runtime changes through the admin
endpoints. If a core class has a real bug that blocks you, make the smallest fix and list it in your final report.
