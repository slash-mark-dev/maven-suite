#!/usr/bin/env python3
"""Generates a random Maven repository (POMs + metadata) and root projects for differential
resolver testing against Maven's own resolver. Usage: gen.py <outdir> <seed> <roots>"""
import os, random, sys

out, seed, nroots = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
CYCLE_P = float(sys.argv[4]) if len(sys.argv) > 4 else 0.08
R = random.Random(seed)
repo = os.path.join(out, "repo")
roots_dir = os.path.join(out, "roots")
os.makedirs(repo, exist_ok=True); os.makedirs(roots_dir, exist_ok=True)

GROUPS = ["org.alpha", "org.beta", "com.gamma"]
ARTS = []  # (g, a, [versions])
for i in range(40):
    g = GROUPS[i % 3]; a = "lib%02d" % i
    nv = R.choice([1, 1, 2, 3])
    vs = sorted(R.sample(["1.0", "1.1", "1.2", "2.0", "2.1-beta", "2.1", "3.0", "1.0.1", "10.0"], nv),
                key=lambda v: [int(x) if x.isdigit() else 0 for x in v.replace("-beta", ".0").split(".")])
    ARTS.append((g, a, vs))
PARENTS = []
for i in range(4):
    PARENTS.append(("org.parent", "parent%d" % i, "1.0"))
BOMS = [("org.bom", "bom%d" % i, "1.0") for i in range(3)]

def scope():
    x = R.random()
    if x < 0.62: return None
    if x < 0.77: return "runtime"
    if x < 0.87: return "test"
    if x < 0.95: return "provided"
    return "compile"

def dep_xml(g, a, v, sc=None, opt=False, excl=None, typ=None):
    s = "    <dependency><groupId>%s</groupId><artifactId>%s</artifactId>" % (g, a)
    if v is not None: s += "<version>%s</version>" % v
    if typ: s += "<type>%s</type>" % typ
    if sc: s += "<scope>%s</scope>" % sc
    if opt: s += "<optional>true</optional>"
    if excl:
        s += "<exclusions>" + "".join("<exclusion><groupId>%s</groupId><artifactId>%s</artifactId></exclusion>" % e for e in excl) + "</exclusions>"
    return s + "</dependency>\n"

def pick_version(vs, allow_range=True):
    if allow_range and R.random() < 0.05 and len(vs) > 1:
        return "[%s,)" % vs[0]
    return R.choice(vs)

def rand_deps(min_idx, n, props, allow_cycles):
    xml = ""
    for _ in range(n):
        j = R.randrange(0, len(ARTS)) if allow_cycles and R.random() < CYCLE_P else R.randrange(min_idx, len(ARTS)) if min_idx < len(ARTS) else None
        if j is None: break
        g, a, vs = ARTS[j]
        v = pick_version(vs)
        if props is not None and R.random() < 0.15:
            pn = "v.%s" % a
            props[pn] = v
            v = "${%s}" % pn
        excl = None
        if R.random() < 0.12:
            k = R.randrange(0, len(ARTS))
            excl = [(ARTS[k][0], ARTS[k][1])] if R.random() < 0.8 else [("*", "*")]
        xml += dep_xml(g, a, v, scope(), R.random() < 0.1, excl)
    return xml

def write_pom(g, a, v, body, packaging="jar"):
    d = os.path.join(repo, *g.split("."), a, v)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "%s-%s.pom" % (a, v)), "w") as f:
        f.write('<?xml version="1.0"?>\n<project><modelVersion>4.0.0</modelVersion>\n%s</project>\n' % body)
    open(os.path.join(d, "%s-%s.jar" % (a, v)), "wb").close()

def mgmt(n):
    xml = ""
    for _ in range(n):
        g, a, vs = R.choice(ARTS)
        sc = R.choice([None, None, None, "runtime", "compile", "provided", "test"])
        excl = None
        if R.random() < 0.15:
            k = R.choice(ARTS); excl = [(k[0], k[1])]
        xml += dep_xml(g, a, R.choice(vs), sc, False, excl)
    return xml

# parents: properties, dependencyManagement and inherited dependencies
for (g, a, v) in PARENTS:
    props = {}
    deps = rand_deps(20, R.randint(0, 2), props, False)
    body = "<groupId>%s</groupId><artifactId>%s</artifactId><version>%s</version><packaging>pom</packaging>\n" % (g, a, v)
    body += "<properties>" + "".join("<%s>%s</%s>" % (k, val, k) for k, val in props.items()) + "<shared.ver>1.0</shared.ver></properties>\n"
    body += "<dependencyManagement><dependencies>\n" + mgmt(R.randint(0, 3)) + "</dependencies></dependencyManagement>\n"
    body += "<dependencies>\n" + deps + "</dependencies>\n"
    write_pom(g, a, v, body, "pom")
for (g, a, v) in BOMS:
    body = "<groupId>%s</groupId><artifactId>%s</artifactId><version>%s</version><packaging>pom</packaging>\n" % (g, a, v)
    body += "<dependencyManagement><dependencies>\n" + mgmt(R.randint(2, 6)) + "</dependencies></dependencyManagement>\n"
    write_pom(g, a, v, body, "pom")

for idx, (g, a, vs) in enumerate(ARTS):
    for v in vs:
        props = {}
        body = ""
        if R.random() < 0.3:
            pg, pa, pv = R.choice(PARENTS)
            body += "<parent><groupId>%s</groupId><artifactId>%s</artifactId><version>%s</version><relativePath/></parent>\n" % (pg, pa, pv)
        body += "<groupId>%s</groupId><artifactId>%s</artifactId><version>%s</version>\n" % (g, a, v)
        deps = rand_deps(idx + 1, R.randint(0, 4), props, True)
        if props:
            body += "<properties>" + "".join("<%s>%s</%s>" % (k, val, k) for k, val in props.items()) + "</properties>\n"
        if R.random() < 0.15:
            body += "<dependencyManagement><dependencies>\n" + mgmt(R.randint(1, 3)) + "</dependencies></dependencyManagement>\n"
        body += "<dependencies>\n" + deps + "</dependencies>\n"
        write_pom(g, a, v, body)
    # metadata
    d = os.path.join(repo, *g.split("."), a)
    with open(os.path.join(d, "maven-metadata.xml"), "w") as f:
        f.write("<metadata><groupId>%s</groupId><artifactId>%s</artifactId><versioning><latest>%s</latest><release>%s</release><versions>%s</versions><lastUpdated>20260101000000</lastUpdated></versioning></metadata>"
                % (g, a, vs[-1], vs[-1], "".join("<version>%s</version>" % x for x in vs)))

# relocation: lib39 1.0.0-reloc relocated to lib38
g, a, vs = ARTS[38]
write_pom("org.old", "moved", "1.0", "<groupId>org.old</groupId><artifactId>moved</artifactId><version>1.0</version><distributionManagement><relocation><groupId>%s</groupId><artifactId>%s</artifactId><version>%s</version></relocation></distributionManagement>" % (g, a, vs[0]))

for r in range(nroots):
    props = {}
    body = ""
    if R.random() < 0.3:
        pg, pa, pv = R.choice(PARENTS)
        body += "<parent><groupId>%s</groupId><artifactId>%s</artifactId><version>%s</version><relativePath/></parent>\n" % (pg, pa, pv)
    body += "<groupId>org.root</groupId><artifactId>root%d</artifactId><version>1.0</version>\n" % r
    deps = rand_deps(0, R.randint(2, 7), props, False)
    if R.random() < 0.1: deps += dep_xml("org.old", "moved", "1.0")
    if props:
        body += "<properties>" + "".join("<%s>%s</%s>" % (k, val, k) for k, val in props.items()) + "</properties>\n"
    dm = ""
    if R.random() < 0.5: dm += mgmt(R.randint(1, 4))
    if R.random() < 0.3:
        bg, ba, bv = R.choice(BOMS)
        dm += "    <dependency><groupId>%s</groupId><artifactId>%s</artifactId><version>%s</version><type>pom</type><scope>import</scope></dependency>\n" % (bg, ba, bv)
    if dm: body += "<dependencyManagement><dependencies>\n" + dm + "</dependencies></dependencyManagement>\n"
    body += "<dependencies>\n" + deps + "</dependencies>\n"
    write_pom("org.root", "root%d" % r, "1.0", body)
    with open(os.path.join(roots_dir, "root%d.txt" % r), "w") as f: f.write("org.root:root%d:1.0" % r)
print("ok", len(ARTS), nroots)
