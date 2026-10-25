# Resolver differential test

`./build.sh diff` checks sm-maven against Maven's own libraries (needs Maven 3.9 installed; `MAVEN_HOME`, default `/opt/maven`):

* **Versions** — `VersionDiff` compares version ordering and range matching with `maven-artifact` (over 1.1 million comparisons).
* **Resolution** — `gen.py` writes a random repository (parents, property interpolation, BOM imports, duplicate
  management entries, version ranges, scopes, optional dependencies, exclusions and dependency cycles). For every
  generated project, `ResolverDiff` resolves the dependency tree with maven-resolver 1.9 (exactly as `mvn` does) and with
  sm-maven, then compares the selected artifacts, versions, scopes, optional flags and tree position.

Results at release (5 seeds × 400 projects): 2,000 projects, 31,557 resolved dependencies, **1 mismatch**. The mismatch is
in a heavily cyclic graph (cycle probability 0.15), where Maven's conflict-group ordering depends on Java identity hash codes
(`ConflictIdSorter` keeps groups in a `HashSet`). It can't be reproduced exactly outside Maven's JVM and doesn't
occur in acyclic graphs.

Run more seeds: `RESOLVER_SEEDS="1:0.1 2:0.1 3:0.25" ./build.sh diff`
