# Changelog

## 1.0.0 — 2026-10-25

First release: 25 real-time tools in one zero-dependency CLI, `sm-maven` (Java 17+).

- **Live threat intelligence:** `cve-watch`, `impact`, `prioritize`, `release-guard`, `takeover`
- **Release intelligence:** `radar`, `pulse`, `breakcheck`, `adoption`, `relocations`
- **Live dependency analysis:** `graph`, `blast`, `drift`, `resolve`, `classpath`
- **Upgrade intelligence:** `simulate`, `safe`, `jdk`
- **Live compliance:** `license-watch`, `sbom`, `gate`
- **Operations:** `repo-status`, `publish-track`, `dashboard`, `alerts`
- Live data from Maven Central, OSV, CISA KEV, FIRST EPSS, deps.dev and GitHub.
- Watch mode with persistent state, plus alerts to Slack, Microsoft Teams, Discord, signed webhooks and e-mail.
- Maven-exact version ordering and dependency mediation, verified against Maven 3.9 / maven-resolver 1.9.
