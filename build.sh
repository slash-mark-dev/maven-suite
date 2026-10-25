#!/usr/bin/env bash
# Builds sm-maven without Maven (zero dependencies): compiles, packages build/sm-maven.jar, runs tests.
#   ./build.sh          compile + jar
#   ./build.sh test     + unit tests + end-to-end tests against the local mock services
#   ./build.sh diff     + differential tests against Maven's own libraries (needs Maven installed)
set -euo pipefail
cd "$(dirname "$0")"
VERSION=1.0.0
rm -rf build/classes build/test && mkdir -p build/classes build/test
javac --release 17 -encoding UTF-8 -Xlint:all -Xlint:-serial -Werror -d build/classes $(find src/main/java -name '*.java')
mkdir -p build/classes/META-INF && printf 'Main-Class: in.slashmark.maven.Main\nImplementation-Title: sm-maven\nImplementation-Version: %s\nImplementation-Vendor: Slash Mark IT Solutions\n' "$VERSION" > build/manifest.txt
jar --create --file build/sm-maven.jar --manifest build/manifest.txt -C build/classes .
echo "built build/sm-maven.jar"
if [[ "${1:-}" == "test" || "${1:-}" == "diff" ]]; then
  javac --release 17 -encoding UTF-8 -cp build/classes -d build/test $(find src/test/java -name '*.java' -not -path '*/diff/*')
  java -cp build/classes:build/test in.slashmark.maven.unit.RunUnit
  java -cp build/classes:build/test in.slashmark.maven.e2e.RunE2E
fi
if [[ "${1:-}" == "diff" ]]; then
  MVN_LIB="${MAVEN_HOME:-/opt/maven}/lib"
  CP="build/classes:$(ls "$MVN_LIB"/*.jar | tr '\n' ':')"
  javac --release 17 -cp "$CP" -d build/test src/test/java/in/slashmark/maven/diff/*.java
  java -cp "build/test:$CP" in.slashmark.maven.diff.VersionDiff
  # Resolver: random repositories (POMs, parents, BOMs, ranges, exclusions, cycles) resolved by Maven and by sm-maven.
  for spec in ${RESOLVER_SEEDS:-7:0.08 99:0.2 2024:0.3}; do
    seed=${spec%%:*}; cyc=${spec##*:}; fx=$(mktemp -d)
    python3 tests/resolver/gen.py "$fx" "$seed" 400 "$cyc" > /dev/null
    python3 -m http.server 18799 --bind 127.0.0.1 --directory "$fx/repo" > /dev/null 2>&1 & srv=$!
    sleep 1
    echo -n "resolver seed $seed: "
    java -cp "build/test:$CP" in.slashmark.maven.diff.ResolverDiff "$fx" http://127.0.0.1:18799 || status=1
    kill $srv; wait $srv 2>/dev/null || true
  done
  exit ${status:-0}
fi
