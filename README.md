# Slash Mark Maven Suite

**Java Package Intelligence Suite.** Explore, analyze and manage Maven artifacts from your terminal: 25 real-time tools in one zero-dependency command, `sm-maven`.

```bash
curl -LO https://repo1.maven.org/maven2/in/slashmark/maven-suite/1.0.0/maven-suite-1.0.0.jar
java -jar maven-suite-1.0.0.jar help
```

- **Real time.** Every tool works on live data from Maven Central, OSV, CISA KEV, FIRST EPSS, deps.dev (Open Source Insights) and GitHub, at the moment you run it.
- **Watch mode.** Watch tools remember what they saw, so cron, CI or `--watch` report only what is new. They can alert Slack, Microsoft Teams, Discord, webhooks (HMAC-signed) and e-mail.
- **Maven-exact.** Version ordering and dependency mediation are tested against Maven's own libraries (see [Accuracy](#accuracy)).
- **Zero dependencies.** One 600 KB JAR that runs on Java 17 or newer, with nothing to add to your build.
- **`--json` on every tool** for scripts and CI. Exit codes: `0` ok · `1` issues found · `2` usage error · `3` network/runtime error.
- Reads your `settings.xml` for mirrors, private repositories and credentials, and works on **Windows, macOS and Linux**.

## Install

```bash
# 1. Download the JAR (Maven Central or GitHub Releases) and run it
java -jar maven-suite-1.0.0.jar help

# 2. Or with JBang, without downloading anything yourself
jbang in.slashmark:maven-suite:1.0.0 help

# 3. Or put the bin/ launcher on your PATH (Linux/macOS: bin/sm-maven, Windows: bin\sm-maven.cmd)
#    next to sm-maven.jar, then:
sm-maven help
```

Every tool takes a **project** (`-f path/to/pom.xml`, default: the current folder, multi-module builds included) or **published coordinates** (`groupId:artifactId[:version]`; no version means the latest release).

## The 25 tools

### Live threat intelligence
| Tool | Command | Example |
|---|---|---|
| Live CVE Watch | `cve-watch` | `sm-maven cve-watch --watch --interval 15m --min-severity high` |
| Zero-Day Impact Scanner | `impact` | `sm-maven impact CVE-2021-44228` |
| Exploit Prioritizer | `prioritize` | `sm-maven prioritize --min-priority P2 --fail-on P1` |
| Malicious Release Guard | `release-guard` | `sm-maven release-guard --releases 3 --threshold 30` |
| Namespace Takeover Watch | `takeover` | `sm-maven takeover --group in.slashmark --internal in.slashmark.platform` |

### Release intelligence
| Tool | Command | Example |
|---|---|---|
| Release Radar | `radar` | `sm-maven radar --transitive --since 30d` |
| Project Pulse | `pulse` | `sm-maven pulse --transitive --fail-on medium` |
| Breaking Change Forecaster | `breakcheck` | `sm-maven breakcheck com.google.guava:guava --deps` |
| Ecosystem Adoption Tracker | `adoption` | `sm-maven adoption com.google.guava:guava:31.1-jre --versions 5` |
| Relocation & Retirement Alerts | `relocations` | `sm-maven relocations --fail-on any` |

### Live dependency analysis
| Tool | Command | Example |
|---|---|---|
| Live Dependency Graph | `graph` | `sm-maven graph --format html --vulns -o deps.html` |
| Blast Radius Analyzer | `blast` | `sm-maven blast org.apache.logging.log4j:log4j-core:2.14.1 --deep` |
| Transitive Drift Monitor | `drift` | `sm-maven drift --watch --interval 1h` |
| Conflict Resolution Simulator | `resolve` | `sm-maven resolve --pin com.fasterxml.jackson.core:jackson-databind:2.18.2` |
| Classpath Collision Detector | `classpath` | `sm-maven classpath --scope compile,runtime` |

### Upgrade intelligence
| Tool | Command | Example |
|---|---|---|
| Upgrade Simulator | `simulate` | `sm-maven simulate org.apache.logging.log4j:log4j-core:2.24.3` |
| Safe Version Finder | `safe` | `sm-maven safe` · `sm-maven safe org.example:widgets --allow BUSL-1.1` |
| JDK & Jakarta Readiness Scanner | `jdk` | `sm-maven jdk --target 25` |

### Live compliance
| Tool | Command | Example |
|---|---|---|
| License Change Alert | `license-watch` | `sm-maven license-watch --deny 'GPL-*,AGPL-*,BUSL-1.1'` |
| Live SBOM + VEX | `sbom` | `sm-maven sbom --format spdx -o bom.spdx.json` |
| CI Policy Gate | `gate` | `sm-maven gate --fail-on high --kev --epss 0.5 --format github` |

### Operations
| Tool | Command | Example |
|---|---|---|
| Repository Health Monitor | `repo-status` | `sm-maven repo-status -r corp=https://nexus.example.com/repository/maven-releases` |
| Publish Tracker | `publish-track` | `sm-maven publish-track in.slashmark:my-lib:1.4.0 --wait` |
| Multi-Repo Live Dashboard | `dashboard` | `sm-maven dashboard --org slash-mark-dev --html -o risk.html` |
| Alert Hub | `alerts` | `sm-maven alerts add team-slack --type slack --url https://hooks.slack.com/services/…` |

Every tool has detailed help: `sm-maven <tool> --help`.

## Highlights

- **`impact CVE-…`** answers "are we affected?" the moment a zero-day is published: every path to the vulnerable artifact in every module, copies shaded into fat JARs, and the smallest fix.
- **`prioritize`** ranks findings by real-world exploitation (CISA KEV, FIRST EPSS probability, CVSS, and whether the dependency is direct and on the runtime classpath) into P1–P4, instead of a flat list of CVEs.
- **`release-guard`** inspects each new release before you take it. It flags a new PGP signing key, newly added Java agents (`Premain-Class`), native libraries, `Runtime.exec` or class-loader tricks, and hard-coded IP addresses.
- **`breakcheck`** and **`simulate`** read the bytecode of your compiled classes and of the new version. They report only the API breaks your code actually hits, plus class-file level, licence and vulnerability changes, with a SAFE, REVIEW or BREAKING verdict.
- **`safe`** finds, per dependency, the newest version with no known vulnerabilities, no API breaks for your code, an acceptable licence and a supported JDK. It then re-resolves the whole build with those pins to prove the result, and prints the exact `<dependency>` to paste.
- **`resolve`** explains every "nearest wins" conflict (including silent downgrades) and simulates `--pin`s before you edit the POM.
- **`sbom`** writes CycloneDX 1.5 or SPDX 2.3 with hashes, licences, live vulnerabilities and VEX exploitability status.
- **`gate`** turns all of the above into one CI policy, with output for GitHub annotations, SARIF and JUnit, and accepted risks that carry an expiry date.

## CI example (GitHub Actions)

```yaml
- uses: actions/setup-java@v4
  with: { distribution: temurin, java-version: 21 }
- run: curl -sLO https://repo1.maven.org/maven2/in/slashmark/maven-suite/1.0.0/maven-suite-1.0.0.jar
- run: java -jar maven-suite-1.0.0.jar gate --fail-on high --kev --deny-license 'GPL-*,AGPL-*' --format github
- run: java -jar maven-suite-1.0.0.jar sbom -o bom.cdx.json
- run: java -jar maven-suite-1.0.0.jar cve-watch --fail-on new
```

For continuous monitoring, run watch tools on a schedule (cron or a scheduled CI job) after `sm-maven alerts add …`. Only new findings are sent.

## Configuration

| Variable | Purpose |
|---|---|
| `GITHUB_TOKEN` | Higher GitHub rate limits (`pulse`, `release-guard`, `dashboard`, `publish-track`) |
| `SM_MAVEN_CENTRAL` | Repository to read artifacts from (default `https://repo1.maven.org/maven2`); mirrors in `settings.xml` are also honoured |
| `SM_MAVEN_SEARCH`, `SM_MAVEN_OSV`, `SM_MAVEN_KEV`, `SM_MAVEN_EPSS`, `SM_MAVEN_DEPSDEV`, `SM_MAVEN_GITHUB` | Point a data source at a mirror or proxy |
| `SM_MAVEN_SETTINGS` / `--settings` | `settings.xml` to use (default `~/.m2/settings.xml`) |
| `SM_MAVEN_SLACK_WEBHOOK`, `SM_MAVEN_TEAMS_WEBHOOK`, `SM_MAVEN_DISCORD_WEBHOOK`, `SM_MAVEN_WEBHOOK` (+ `SM_MAVEN_WEBHOOK_SECRET`) | Alert channels from the environment (handy in CI) |
| `SM_MAVEN_HOME`, `SM_MAVEN_CACHE`, `SM_MAVEN_CONFIG` | State, response cache and configuration folders (default `~/.sm-maven`) |
| `NO_COLOR` / `--no-color` | Plain output |
| `HTTPS_PROXY` | Standard proxy support |

Secrets (passwords, tokens, webhook URLs) are never printed. Credentials from `settings.xml` are only sent to the repository they belong to.

## Accuracy

`./build.sh diff` compares sm-maven with Maven's own libraries (Maven 3.9 / maven-resolver 1.9):

- **Version ordering and ranges:** 1,156,040 comparisons and 1,807 range checks against `maven-artifact`, with 0 mismatches.
- **Dependency resolution:** 2,000 randomly generated projects (parents, BOM imports, property interpolation, ranges, scopes, optional dependencies, exclusions, cycles) produced 31,557 resolved dependencies. All but one are identical to Maven in version, scope and tree position. The one exception is in a heavily cyclic graph where Maven's own order depends on JVM identity hashes (see [tests/resolver](tests/resolver/README.md)).

## Development

```bash
./build.sh            # compile (warnings are errors) and build build/sm-maven.jar
./build.sh test       # + 364 end-to-end checks of all 25 tools against local mocks of every data source
./build.sh diff       # + differential tests against Maven (needs Maven 3.9 installed)
mvn -B verify         # the Maven build used for releases
```

## License

MIT © [Slash Mark IT Solutions](https://slashmark.in). Need specialized Java development or Maven build engineering? Contact mukesh@slashmark.in.
