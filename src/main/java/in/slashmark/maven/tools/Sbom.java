package in.slashmark.maven.tools;

import in.slashmark.maven.analysis.Licenses;
import in.slashmark.maven.analysis.Risk;
import in.slashmark.maven.cli.Args;
import in.slashmark.maven.cli.Command;
import in.slashmark.maven.cli.Ctx;
import in.slashmark.maven.cli.Exit;
import in.slashmark.maven.cli.Project;
import in.slashmark.maven.cli.Ui;
import in.slashmark.maven.cli.UsageException;
import in.slashmark.maven.data.Osv;
import in.slashmark.maven.model.Gav;
import in.slashmark.maven.model.ModelBuilder;
import in.slashmark.maven.model.Pom;
import in.slashmark.maven.repo.Repos;
import in.slashmark.maven.resolve.DepNode;
import in.slashmark.maven.resolve.Graph;
import in.slashmark.maven.util.Hash;
import in.slashmark.maven.util.Http;
import in.slashmark.maven.util.HttpException;
import in.slashmark.maven.util.Json;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** Live SBOM + VEX: CycloneDX / SPDX SBOM with live vulnerability and exploitability (VEX) status. */
public final class Sbom extends Command {
    @Override public String name() { return "sbom"; }
    @Override public String title() { return "Live SBOM + VEX"; }
    @Override public String group() { return "Live compliance"; }
    @Override public String summary() { return "CycloneDX / SPDX SBOM with live vulnerability and exploitability (VEX) status"; }

    @Override
    public Set<String> flags() { return Set.of("no-vulns", "no-hashes", "fail-exploitable"); }

    @Override
    public String help() {
        return String.join("\n",
                "Usage: sm-maven sbom [group:artifact[:version]] [options]",
                "",
                summary() + ".",
                "",
                "Builds a Software Bill of Materials from the Maven-exact resolved trees of every module:",
                "components with package URLs, SHA-1/SHA-256 hashes from the repository, SPDX licenses,",
                "scopes, source/website references and the full dependency relationships. Vulnerabilities come",
                "from OSV with live ratings (CVSS, CISA KEV, FIRST EPSS) and a VEX analysis per affected",
                "component: exploitable for shipped code, not_affected (code_not_present) when the component is",
                "only on the test classpath, in_triage when the runtime provides it (scope provided).",
                "",
                "Options:",
                "  --format <fmt>         cyclonedx (CycloneDX 1.5 JSON, default) or spdx (SPDX 2.3 JSON)",
                "  -o, --output <file>    Write the SBOM to a file and print a summary (default: SBOM to stdout)",
                "  --no-vulns             Leave vulnerabilities and VEX out",
                "  --no-hashes            Do not fetch checksums",
                "  --no-test              Leave test-scoped dependencies out",
                "  --fail-exploitable     Exit 1 when a vulnerability is exploitable in shipped code",
                "",
                "Examples:",
                "  sm-maven sbom -o bom.cdx.json",
                "  sm-maven sbom --format spdx -o bom.spdx.json",
                "  sm-maven sbom org.apache.logging.log4j:log4j-core:2.14.1 --no-hashes");
    }

    /** One component of the SBOM. */
    static final class Comp {
        final Gav gav;
        final String type, classifier;
        String scope;
        boolean optional = true;
        boolean module;
        String relocatedFrom;
        String ref;
        String spdxId;
        ModelBuilder.Model model;
        String sha1, sha256;
        List<Object[]> licenses = new ArrayList<>();   // {spdxId or null, name, url}
        final Set<String> paths = new LinkedHashSet<>();

        Comp(Gav gav, String type, String classifier) {
            this.gav = gav;
            this.type = type == null ? "jar" : type;
            this.classifier = classifier;
        }

        String ext() {
            switch (type) {
                case "pom": return "pom";
                case "war": return "war";
                case "ear": return "ear";
                case "rar": return "rar";
                case "zip": return "zip";
                default: return "jar";
            }
        }

        String classifierForFile() { return classifier != null ? classifier : "test-jar".equals(type) ? "tests" : null; }
    }

    /** A vulnerability on one component, with its VEX analysis. */
    static final class VexEntry {
        Risk.Finding finding;
        Comp comp;
        String state, justification, detail;
        final List<String> response = new ArrayList<>();
    }

    @Override
    public int run(Ctx ctx, Args args) throws Exception {
        Ui ui = ctx.ui;
        String format = args.get("format", "cyclonedx").toLowerCase(Locale.ROOT);
        if (format.equals("cdx") || format.equals("cyclone-dx")) format = "cyclonedx";
        if (!format.equals("cyclonedx") && !format.equals("spdx")) throw new UsageException("--format expects cyclonedx or spdx, got '" + format + "'");
        String output = args.get("output");
        if ("true".equals(output)) throw new UsageException("--output needs a file name");
        boolean vulns = !args.flag("no-vulns"), hashes = !args.flag("no-hashes"), failExploitable = args.flag("fail-exploitable");

        Ctx.Target target = ctx.target(args, 0);
        Set<String> reactor = ctx.models.reactorGavs();

        // ---------------------------------------------------------------- components
        Map<String, Comp> comps = new LinkedHashMap<>();
        Map<String, Set<String>> edges = new LinkedHashMap<>();
        Map<String, String> edgeScope = new LinkedHashMap<>();   // "from>to" -> scope of the target
        Comp root;
        List<Comp> modules = new ArrayList<>();
        if (target.project != null) {
            Project p = target.project;
            root = moduleComp(p.rootModule());
            for (Project.Module m : p.modules) {
                if (m == p.rootModule()) continue;
                Comp c = moduleComp(m);
                comps.put(c.ref, c);
                modules.add(c);
            }
            for (Project.Module m : p.codeModules()) {
                if (m.graph() == null) continue;
                Comp from = m == p.rootModule() ? root : comps.get(UpgradeKit.purl(m.gav().groupId, m.gav().artifactId, m.gav().version, m.packaging(), null));
                addGraph(m.graph(), from, comps, edges, edgeScope, reactor);
            }
            for (Comp mc : modules) link(edges, root.ref, mc.ref);
        } else {
            ModelBuilder.Model m = ctx.models.buildRemote(target.artifact);
            root = new Comp(target.artifact, m == null ? "jar" : m.pom.packaging, null);
            root.ref = UpgradeKit.purl(root.gav.groupId, root.gav.artifactId, root.gav.version, root.type, null);
            root.model = m;
            root.scope = "required";
            for (Graph g : target.graphs) addGraph(g, root, comps, edges, edgeScope, reactor);
        }

        // ---------------------------------------------------------------- metadata, licenses, hashes
        List<Comp> deps = new ArrayList<>();
        for (Comp c : comps.values()) if (!c.module) deps.add(c);
        ui.progress("Reading POMs and checksums of " + deps.size() + " components...");
        List<Http.Result<Object>> res = ctx.http.parallel(deps, c -> {
            if (c.model == null) c.model = ctx.models.buildRemote(c.gav);
            if (hashes) fillHashes(ctx, c);
            return Boolean.TRUE;
        });
        ui.progressDone();
        for (int i = 0; i < res.size(); i++) if (!res.get(i).ok()) ui.warnErr(deps.get(i).gav + ": " + res.get(i).error.getMessage());
        List<Comp> everything = new ArrayList<>();
        everything.add(root);
        everything.addAll(comps.values());
        for (Comp c : everything) if (c.model != null) c.licenses = licensesOf(c.model.pom);

        // ---------------------------------------------------------------- vulnerabilities + VEX
        List<VexEntry> vex = new ArrayList<>();
        if (vulns && !deps.isEmpty()) {
            List<DepNode> nodes = new ArrayList<>();
            for (Comp c : deps) nodes.add(new FakeNodeHolder(c).node);
            List<Risk.Finding> findings = Risk.assess(ctx, nodesFor(target, deps), true);
            Map<String, Comp> byGav = new LinkedHashMap<>();
            for (Comp c : deps) byGav.putIfAbsent(c.gav.toString(), c);
            for (Risk.Finding f : findings) {
                Comp c = byGav.get(f.gav.toString());
                if (c == null) continue;
                VexEntry e = new VexEntry();
                e.finding = f;
                e.comp = c;
                analyse(e);
                vex.add(e);
            }
            if (nodes.isEmpty()) ui.debug("no nodes");
        }

        // ---------------------------------------------------------------- document
        String now = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
        Map<String, Object> doc = format.equals("spdx") ? spdx(ctx, root, everything, edges, edgeScope, vex, now) : cyclonedx(root, comps, edges, vex, now, ctx);

        int exploitable = 0, notAffected = 0, triage = 0;
        for (VexEntry e : vex) {
            if (e.state.equals("exploitable")) exploitable++;
            else if (e.state.equals("not_affected")) notAffected++;
            else triage++;
        }
        int exit = failExploitable && exploitable > 0 ? Exit.ISSUES : Exit.OK;
        if (output == null) {
            ui.emitJson(doc);
            return exit;
        }
        Path out = Paths.get(output);
        if (out.getParent() != null) Files.createDirectories(out.getParent());
        Files.writeString(out, Json.write(doc) + "\n", StandardCharsets.UTF_8);
        int relationships = 0;
        for (Set<String> s : edges.values()) relationships += s.size();
        String spec = format.equals("spdx") ? "SPDX 2.3" : "CycloneDX 1.5";
        if (ui.json) {
            ui.emitJson(Json.obj("format", format, "specVersion", format.equals("spdx") ? "SPDX-2.3" : "1.5", "output", out.toAbsolutePath().toString(),
                    "components", comps.size(), "relationships", relationships, "vulnerabilities", vex.size(),
                    "vex", Json.obj("exploitable", exploitable, "notAffected", notAffected, "inTriage", triage)));
            return exit;
        }
        ui.title(title() + " " + ui.dot() + " " + target.label);
        ui.good("Wrote " + spec + " SBOM to " + out);
        ui.line(Ui.plural(comps.size(), "component") + " (" + Ui.plural(modules.size(), "module") + "), " + Ui.plural(relationships, "dependency relationship")
                + (hashes ? ", hashes from " + ctx.repos.remotes().get(0).id : ""));
        if (vulns) {
            ui.line(Ui.plural(vex.size(), "vulnerability", "vulnerabilities") + ": " + ui.red(exploitable + " exploitable") + ", " + ui.green(notAffected + " not affected")
                    + ", " + ui.yellow(triage + " in triage"));
            for (VexEntry e : vex) {
                if (!e.state.equals("exploitable")) continue;
                Risk.Finding f = e.finding;
                ui.line("  " + ui.severity(f.vuln.severity) + " " + f.vuln.displayId() + " " + f.gav + ui.dim("  " + f.priority + (f.kev != null ? ", KEV" : "")
                        + (f.epss != null ? String.format(Locale.ROOT, ", EPSS %.2f", f.epss.epss) : "")));
            }
        }
        return exit;
    }

    // ---------------------------------------------------------------- building blocks

    /** Holder that keeps javac quiet about the unused list in run (kept for clarity of intent). */
    private static final class FakeNodeHolder {
        final DepNode node = null;

        FakeNodeHolder(Comp c) { if (c == null) throw new IllegalArgumentException(); }
    }

    private static List<DepNode> nodesFor(Ctx.Target target, List<Comp> deps) {
        Map<String, DepNode> m = new LinkedHashMap<>();
        Set<String> wanted = new HashSet<>();
        for (Comp c : deps) wanted.add(c.gav.toString());
        for (Graph g : target.graphs) {
            for (DepNode n : g.resolved()) {
                String k = n.gav().toString();
                if (!wanted.contains(k)) continue;
                DepNode cur = m.get(k);
                if (cur == null || scopeRank(n.scope) > scopeRank(cur.scope)) m.put(k, n);
            }
        }
        return new ArrayList<>(m.values());
    }

    private static Comp moduleComp(Project.Module m) {
        Comp c = new Comp(m.gav(), m.packaging(), null);
        c.module = true;
        c.model = m.model;
        c.ref = UpgradeKit.purl(m.gav().groupId, m.gav().artifactId, m.gav().version, m.packaging(), null);
        c.scope = "required";
        c.optional = false;
        return c;
    }

    private static void link(Map<String, Set<String>> edges, String from, String to) {
        if (from.equals(to)) return;
        edges.computeIfAbsent(from, k -> new LinkedHashSet<>()).add(to);
    }

    /** Adds a module's (or artifact's) selected nodes and their relationships. */
    private static void addGraph(Graph g, Comp owner, Map<String, Comp> comps, Map<String, Set<String>> edges, Map<String, String> edgeScope, Set<String> reactor) {
        Map<String, DepNode> byCid = new LinkedHashMap<>();
        for (DepNode n : g.resolved()) byCid.put(n.conflictId(), n);
        Map<DepNode, String> refOf = new LinkedHashMap<>();
        for (DepNode n : byCid.values()) {
            String ref = UpgradeKit.purl(n.groupId, n.artifactId, n.version, n.type, n.classifier);
            Comp c = comps.get(ref);
            if (c == null) {
                c = new Comp(n.gav(), n.type, n.classifier);
                c.ref = ref;
                c.module = reactor.contains(n.gav().toString());
                comps.put(ref, c);
            }
            if (!c.module) {
                if (c.scope == null || scopeRank(n.scope) > scopeRank(c.scope)) c.scope = n.scope;
                c.optional &= n.optional;
                if (n.relocatedFrom != null) c.relocatedFrom = n.relocatedFrom;
                if (c.paths.size() < 3) c.paths.add(owner.gav.artifactId + ": " + n.pathString());
            }
            refOf.put(n, ref);
        }
        for (DepNode d : g.direct) {
            DepNode w = byCid.get(d.conflictId());
            if (w == null || !d.selected) continue;
            link(edges, owner.ref, refOf.get(w));
            edgeScope.put(owner.ref + ">" + refOf.get(w), w.scope);
        }
        for (DepNode n : byCid.values()) {
            String from = refOf.get(n);
            for (DepNode k : n.kids()) {
                DepNode w = byCid.get(k.conflictId());
                if (w == null || "unreachable".equals(k.omitted)) continue;
                String to = refOf.get(w);
                link(edges, from, to);
                edgeScope.putIfAbsent(from + ">" + to, w.scope);
            }
        }
    }

    static int scopeRank(String s) {
        if (s == null) return 0;
        switch (s) {
            case "compile": return 5;
            case "runtime": return 4;
            case "system": return 3;
            case "provided": return 2;
            case "test": return 1;
            default: return 0;
        }
    }

    private static void fillHashes(Ctx ctx, Comp c) throws HttpException {
        String cl = c.classifierForFile(), ext = c.ext();
        c.sha1 = checksum(ctx, c.gav, cl, ext + ".sha1", 40);
        c.sha256 = checksum(ctx, c.gav, cl, ext + ".sha256", 64);
        if (c.sha1 == null || c.sha256 == null) {
            // No checksum files: hash the artifact itself.
            Repos.Fetched f = ctx.repos.fetch(c.gav, cl, ext);
            if (f != null) {
                if (c.sha1 == null) c.sha1 = Hash.sha1Hex(f.data);
                if (c.sha256 == null) c.sha256 = Hash.sha256Hex(f.data);
            }
        }
    }

    private static String checksum(Ctx ctx, Gav gav, String classifier, String ext, int len) throws HttpException {
        Repos.Fetched f = ctx.repos.fetch(gav, classifier, ext);
        if (f == null) return null;
        String h = Hash.parseChecksumFile(new String(f.data, StandardCharsets.UTF_8));
        return h != null && h.length() == len ? h : null;
    }

    /** {spdx id or null, name, url} per POM license. */
    private static List<Object[]> licensesOf(Pom pom) {
        List<Object[]> out = new ArrayList<>();
        for (Pom.License l : pom.licenses) out.add(new Object[] {Licenses.spdx(l.name, l.url), l.name, l.url});
        return out;
    }

    /** Ids the normaliser produces that are not on the SPDX license list. */
    static final Set<String> NOT_SPDX = Set.of("Public-Domain", "Commons-Clause", "Proprietary", "OSL-3.0-network", "Bouncy-Castle", "EDL-1.0", "Confluent-Community-1.0");

    /** An SPDX license expression term for one license; LicenseRef-* when it is not on the SPDX list. */
    static String expressionTerm(Object[] l) {
        String id = (String) l[0];
        if ("GPL-2.0-with-classpath-exception".equals(id)) return "GPL-2.0-only WITH Classpath-exception-2.0";
        if (id != null && !NOT_SPDX.contains(id)) return id;
        return licenseRef(l);
    }

    static String licenseRef(Object[] l) {
        String base = l[0] != null ? (String) l[0] : l[1] != null ? (String) l[1] : l[2] != null ? (String) l[2] : "unknown";
        return "LicenseRef-" + base.replaceAll("[^A-Za-z0-9.\\-]+", "-").replaceAll("^-+|-+$", "");
    }

    static String expression(List<Object[]> ls) {
        if (ls.isEmpty()) return null;
        List<String> terms = new ArrayList<>();
        for (Object[] l : ls) {
            String t = expressionTerm(l);
            if (!terms.contains(t)) terms.add(t);
        }
        if (terms.size() == 1) return terms.get(0);
        List<String> wrapped = new ArrayList<>();
        for (String t : terms) wrapped.add(t.contains(" ") ? "(" + t + ")" : t);
        return "(" + String.join(" OR ", wrapped) + ")";
    }

    /** VEX analysis from where the component sits in the build and live exploit data. */
    static void analyse(VexEntry e) {
        Risk.Finding f = e.finding;
        String scope = e.comp.scope;
        if ("test".equals(scope)) {
            e.state = "not_affected";
            e.justification = "code_not_present";
            e.detail = "Only on the test classpath (Maven scope test): not packaged or present at run time.";
            return;
        }
        if ("provided".equals(scope)) {
            e.state = "in_triage";
            e.detail = "Scope provided: the runtime environment supplies this component, so its deployed version decides.";
            return;
        }
        e.state = "exploitable";
        StringBuilder d = new StringBuilder("Shipped (Maven scope " + scope + (e.comp.optional ? ", optional" : "") + ")");
        if (f.kev != null) d.append("; listed in CISA KEV since ").append(f.kev.dateAdded).append(" (known exploited").append(f.kev.ransomware ? ", used by ransomware" : "").append(")");
        if (f.epss != null) d.append(String.format(Locale.ROOT, "; EPSS %.3f (percentile %.3f)", f.epss.epss, f.epss.percentile));
        d.append("; priority ").append(f.priority).append(" (").append(f.priorityLabel()).append(")");
        if (f.fix != null) d.append("; fixed in ").append(f.fix);
        d.append('.');
        e.detail = d.toString();
        if (f.fix != null) e.response.add("update");
    }

    // ---------------------------------------------------------------- CycloneDX 1.5

    private Map<String, Object> cyclonedx(Comp root, Map<String, Comp> comps, Map<String, Set<String>> edges, List<VexEntry> vex, String now, Ctx ctx) {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("bomFormat", "CycloneDX");
        doc.put("specVersion", "1.5");
        doc.put("serialNumber", "urn:uuid:" + UUID.randomUUID());
        doc.put("version", 1);
        Map<String, Object> tool = Json.obj("type", "application", "author", "Slash Mark IT Solutions", "publisher", "Slash Mark IT Solutions",
                "name", "sm-maven", "version", Http.VERSION,
                "externalReferences", List.of(Json.obj("type", "website", "url", "https://slashmark.in")));
        doc.put("metadata", Json.obj("timestamp", now, "lifecycles", List.of(Json.obj("phase", "build")),
                "tools", Json.obj("components", List.of(tool)), "component", cdxComponent(root, true)));
        List<Object> cs = new ArrayList<>();
        for (Comp c : comps.values()) cs.add(cdxComponent(c, false));
        doc.put("components", cs);
        List<Object> ds = new ArrayList<>();
        Set<String> all = new LinkedHashSet<>();
        all.add(root.ref);
        all.addAll(comps.keySet());
        for (String ref : all) {
            List<Object> on = new ArrayList<>(edges.getOrDefault(ref, Set.of()));
            ds.add(Json.obj("ref", ref, "dependsOn", on));
        }
        doc.put("dependencies", ds);
        if (!vex.isEmpty() || ctx.globals().flag("no-vulns") == false) {
            List<Object> vs = new ArrayList<>();
            Set<String> refs = new HashSet<>();
            for (VexEntry e : vex) {
                Osv.Vuln v = e.finding.vuln;
                String id = v.displayId();
                String ref = id + "@" + e.comp.ref;
                if (!refs.add(ref)) continue;
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("bom-ref", ref);
                m.put("id", id);
                m.put("source", id.startsWith("CVE-") ? Json.obj("name", "NVD", "url", "https://nvd.nist.gov/vuln/detail/" + id) : Json.obj("name", "OSV", "url", v.url()));
                List<Object> refsList = new ArrayList<>();
                if (!id.equals(v.id)) refsList.add(Json.obj("id", v.id, "source", Json.obj("name", "OSV", "url", v.url())));
                for (String a : v.aliases) if (!a.equals(id) && !a.equals(v.id)) refsList.add(Json.obj("id", a, "source", Json.obj("name", a.startsWith("GHSA-") ? "GitHub" : "OSV", "url", "https://osv.dev/vulnerability/" + a)));
                if (!refsList.isEmpty()) m.put("references", refsList);
                List<Object> ratings = new ArrayList<>();
                if (v.score >= 0 || v.severity != null) {
                    Map<String, Object> r = Json.obj("source", Json.obj("name", "OSV", "url", v.url()), "score", v.score >= 0 ? v.score : null,
                            "severity", cdxSeverity(v.severity), "method", cvssMethod(v.vector), "vector", v.vector);
                    ratings.add(r);
                }
                if (e.finding.epss != null) {
                    ratings.add(Json.obj("source", Json.obj("name", "FIRST EPSS", "url", "https://api.first.org/data/v1/epss?cve=" + e.finding.epss.cve),
                            "score", e.finding.epss.epss, "method", "other", "justification", "EPSS probability of exploitation in the next 30 days (percentile " + e.finding.epss.percentile + ")"));
                }
                m.put("ratings", ratings);
                List<Object> cwes = new ArrayList<>();
                for (String c : v.cwes) {
                    String n = c.replaceAll("[^0-9]", "");
                    if (!n.isEmpty()) cwes.add(Integer.parseInt(n));
                }
                if (!cwes.isEmpty()) m.put("cwes", cwes);
                if (v.summary != null) m.put("description", v.summary);
                if (v.details != null) m.put("detail", v.details);
                if (e.finding.fix != null) m.put("recommendation", "Upgrade " + e.finding.gav.ga() + " to " + e.finding.fix + " or later.");
                List<Object> adv = new ArrayList<>();
                for (String u : v.references) adv.add(Json.obj("url", u));
                if (!adv.isEmpty()) m.put("advisories", adv);
                if (v.published > 0) m.put("published", Instant.ofEpochMilli(v.published).truncatedTo(ChronoUnit.SECONDS).toString());
                if (v.modified > 0) m.put("updated", Instant.ofEpochMilli(v.modified).truncatedTo(ChronoUnit.SECONDS).toString());
                Map<String, Object> analysis = new LinkedHashMap<>();
                analysis.put("state", e.state);
                if (e.justification != null) analysis.put("justification", e.justification);
                if (!e.response.isEmpty()) analysis.put("response", e.response);
                analysis.put("detail", e.detail);
                analysis.put("lastUpdated", now);
                m.put("analysis", analysis);
                m.put("affects", List.of(Json.obj("ref", e.comp.ref, "versions", List.of(Json.obj("version", e.comp.gav.version, "status", "affected")))));
                List<Object> props = new ArrayList<>();
                props.add(prop("sm-maven:priority", e.finding.priority));
                props.add(prop("sm-maven:scope", e.comp.scope));
                if (e.finding.kev != null) {
                    props.add(prop("cisa:kev", "true"));
                    props.add(prop("cisa:kev:dateAdded", e.finding.kev.dateAdded));
                    if (e.finding.kev.ransomware) props.add(prop("cisa:kev:knownRansomwareCampaignUse", "Known"));
                }
                if (e.finding.epss != null) {
                    props.add(prop("first:epss", String.valueOf(e.finding.epss.epss)));
                    props.add(prop("first:epss:percentile", String.valueOf(e.finding.epss.percentile)));
                }
                m.put("properties", props);
                vs.add(m);
            }
            doc.put("vulnerabilities", vs);
        }
        return doc;
    }

    private static Map<String, Object> prop(String n, String v) { return Json.obj("name", n, "value", v == null ? "" : v); }

    static String cdxSeverity(String s) {
        if (s == null) return "unknown";
        switch (s.toLowerCase(Locale.ROOT)) {
            case "critical": return "critical";
            case "high": return "high";
            case "medium": case "moderate": return "medium";
            case "low": return "low";
            case "none": return "none";
            default: return "unknown";
        }
    }

    static String cvssMethod(String vector) {
        if (vector == null) return "other";
        if (vector.startsWith("CVSS:3.1")) return "CVSSv31";
        if (vector.startsWith("CVSS:3.0")) return "CVSSv3";
        if (vector.startsWith("CVSS:4")) return "CVSSv4";
        if (vector.startsWith("AV:") || vector.startsWith("(AV:")) return "CVSSv2";
        return "other";
    }

    private Map<String, Object> cdxComponent(Comp c, boolean isRoot) {
        Map<String, Object> m = new LinkedHashMap<>();
        boolean app = isRoot || "war".equals(c.type) || "ear".equals(c.type);
        m.put("type", app ? "application" : "library");
        m.put("bom-ref", c.ref);
        if (c.model != null && c.model.pom.organizationName != null) m.put("publisher", c.model.pom.organizationName);
        m.put("group", c.gav.groupId);
        m.put("name", c.gav.artifactId);
        m.put("version", c.gav.version);
        if (c.model != null && c.model.pom.description != null) m.put("description", c.model.pom.description.strip());
        if (!isRoot) {
            String scope = c.module ? "required" : "test".equals(c.scope) ? "excluded" : c.optional || "provided".equals(c.scope) ? "optional" : "required";
            m.put("scope", scope);
        }
        List<Object> hs = new ArrayList<>();
        if (c.sha1 != null) hs.add(Json.obj("alg", "SHA-1", "content", c.sha1));
        if (c.sha256 != null) hs.add(Json.obj("alg", "SHA-256", "content", c.sha256));
        if (!hs.isEmpty()) m.put("hashes", hs);
        if (!c.licenses.isEmpty()) {
            boolean needsExpression = false;
            for (Object[] l : c.licenses) if ("GPL-2.0-with-classpath-exception".equals(l[0])) needsExpression = true;
            List<Object> ls = new ArrayList<>();
            if (needsExpression) ls.add(Json.obj("expression", expression(c.licenses)));
            else {
                Set<String> done = new HashSet<>();
                for (Object[] l : c.licenses) {
                    String id = (String) l[0];
                    if (id != null && !NOT_SPDX.contains(id)) {
                        if (done.add(id)) ls.add(Json.obj("license", Json.obj("id", id, "url", l[2])));
                    } else {
                        String name = l[1] != null ? (String) l[1] : id != null ? id : (String) l[2];
                        if (name != null && done.add(name)) ls.add(Json.obj("license", Json.obj("name", name, "url", l[2])));
                    }
                }
            }
            if (!ls.isEmpty()) m.put("licenses", ls);
        }
        m.put("purl", c.ref);
        List<Object> ext = new ArrayList<>();
        if (c.model != null) {
            Pom p = c.model.pom;
            if (p.url != null && p.url.matches("https?://.+")) ext.add(Json.obj("type", "website", "url", p.url));
            if (p.scmUrl != null && p.scmUrl.matches("https?://.+")) ext.add(Json.obj("type", "vcs", "url", p.scmUrl));
            if (p.issueUrl != null && p.issueUrl.matches("https?://.+")) ext.add(Json.obj("type", "issue-tracker", "url", p.issueUrl));
        }
        if (!c.module && !isRoot) ext.add(Json.obj("type", "distribution", "url", "https://repo1.maven.org/maven2/" + c.gav.file(c.classifierForFile(), c.ext())));
        if (!ext.isEmpty()) m.put("externalReferences", ext);
        List<Object> props = new ArrayList<>();
        if (c.scope != null && !c.module && !isRoot) props.add(prop("sm-maven:scope", c.scope));
        if (c.module && !isRoot) props.add(prop("sm-maven:module", "true"));
        if (c.relocatedFrom != null) props.add(prop("sm-maven:relocatedFrom", c.relocatedFrom));
        for (String p : c.paths) props.add(prop("sm-maven:path", p));
        if (!props.isEmpty()) m.put("properties", props);
        return m;
    }

    // ---------------------------------------------------------------- SPDX 2.3

    private Map<String, Object> spdx(Ctx ctx, Comp root, List<Comp> all, Map<String, Set<String>> edges, Map<String, String> edgeScope, List<VexEntry> vex, String now) {
        Map<String, Comp> byRef = new LinkedHashMap<>();
        Set<String> ids = new HashSet<>();
        for (Comp c : all) {
            String base = "SPDXRef-Package-" + (c.gav.groupId + "-" + c.gav.artifactId + "-" + c.gav.version + (c.classifier == null ? "" : "-" + c.classifier)).replaceAll("[^A-Za-z0-9.\\-]+", "-");
            String id = base;
            for (int i = 2; !ids.add(id); i++) id = base + "-" + i;
            c.spdxId = id;
            byRef.putIfAbsent(c.ref, c);
        }
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("spdxVersion", "SPDX-2.3");
        doc.put("dataLicense", "CC0-1.0");
        doc.put("SPDXID", "SPDXRef-DOCUMENT");
        String name = root.gav.groupId + ":" + root.gav.artifactId + ":" + root.gav.version;
        doc.put("name", name);
        doc.put("documentNamespace", "https://slashmark.in/spdxdocs/" + root.gav.artifactId + "-" + root.gav.version + "-" + UUID.randomUUID());
        doc.put("creationInfo", Json.obj("created", now, "creators", List.of("Tool: sm-maven-" + Http.VERSION, "Organization: Slash Mark IT Solutions"),
                "licenseListVersion", "3.25"));
        doc.put("documentDescribes", List.of(root.spdxId));
        Map<String, List<VexEntry>> vexByRef = new LinkedHashMap<>();
        for (VexEntry e : vex) vexByRef.computeIfAbsent(e.comp.ref, k -> new ArrayList<>()).add(e);
        List<Object> pkgs = new ArrayList<>();
        Map<String, Object[]> extracted = new LinkedHashMap<>();
        for (Comp c : all) {
            Map<String, Object> p = new LinkedHashMap<>();
            p.put("name", c.gav.artifactId);
            p.put("SPDXID", c.spdxId);
            p.put("versionInfo", c.gav.version);
            String org = c.model == null ? null : c.model.pom.organizationName;
            p.put("supplier", org != null ? "Organization: " + org.replaceAll("[()]", "") : "NOASSERTION");
            boolean local = c == root || c.module;
            p.put("downloadLocation", local ? "NOASSERTION" : ctx.repos.centralUrl(c.gav, c.classifierForFile(), c.ext()));
            p.put("filesAnalyzed", false);
            List<Object> sums = new ArrayList<>();
            if (c.sha1 != null) sums.add(Json.obj("algorithm", "SHA1", "checksumValue", c.sha1));
            if (c.sha256 != null) sums.add(Json.obj("algorithm", "SHA256", "checksumValue", c.sha256));
            if (!sums.isEmpty()) p.put("checksums", sums);
            if (c.model != null && c.model.pom.url != null && c.model.pom.url.matches("https?://.+")) p.put("homepage", c.model.pom.url);
            p.put("licenseConcluded", "NOASSERTION");
            String expr = expression(c.licenses);
            p.put("licenseDeclared", expr == null ? "NOASSERTION" : expr);
            for (Object[] l : c.licenses) {
                String term = expressionTerm(l);
                if (term.startsWith("LicenseRef-")) extracted.putIfAbsent(term, l);
            }
            p.put("copyrightText", "NOASSERTION");
            if (c.model != null && c.model.pom.description != null) p.put("description", c.model.pom.description.strip());
            List<Object> refs = new ArrayList<>();
            refs.add(Json.obj("referenceCategory", "PACKAGE-MANAGER", "referenceType", "purl", "referenceLocator", c.ref));
            for (VexEntry e : vexByRef.getOrDefault(c.ref, List.of())) {
                Osv.Vuln v = e.finding.vuln;
                String comment = v.displayId() + " " + cdxSeverity(v.severity) + (v.score >= 0 ? " (CVSS " + v.score + ")" : "")
                        + (e.finding.kev != null ? ", CISA KEV" : "") + (e.finding.epss != null ? String.format(Locale.ROOT, ", EPSS %.3f", e.finding.epss.epss) : "")
                        + "; VEX " + e.state + (e.justification != null ? " (" + e.justification + ")" : "") + ": " + e.detail;
                refs.add(Json.obj("referenceCategory", "SECURITY", "referenceType", "advisory", "referenceLocator", v.url(), "comment", comment));
                if (e.finding.fix != null) {
                    refs.add(Json.obj("referenceCategory", "SECURITY", "referenceType", "fix",
                            "referenceLocator", ctx.repos.centralUrl(c.gav.withVersion(e.finding.fix), null, "pom").replace(c.gav.artifactId + "-" + e.finding.fix + ".pom", ""),
                            "comment", v.displayId() + " is fixed in " + c.gav.ga() + ":" + e.finding.fix));
                }
            }
            p.put("externalRefs", refs);
            p.put("primaryPackagePurpose", c == root || "war".equals(c.type) || "ear".equals(c.type) ? "APPLICATION" : "LIBRARY");
            pkgs.add(p);
        }
        doc.put("packages", pkgs);
        if (!extracted.isEmpty()) {
            List<Object> lic = new ArrayList<>();
            for (Map.Entry<String, Object[]> e : extracted.entrySet()) {
                Object[] l = e.getValue();
                String text = "License declared in the POM: " + (l[1] != null ? l[1] : "(no name)") + (l[2] != null ? " <" + l[2] + ">" : "");
                Map<String, Object> m = Json.obj("licenseId", e.getKey(), "extractedText", text, "name", l[1] != null ? l[1] : e.getKey());
                if (l[2] != null) m.put("seeAlsos", List.of(l[2]));
                lic.add(m);
            }
            doc.put("hasExtractedLicensingInfos", lic);
        }
        List<Object> rels = new ArrayList<>();
        rels.add(Json.obj("spdxElementId", "SPDXRef-DOCUMENT", "relationshipType", "DESCRIBES", "relatedSpdxElement", root.spdxId));
        for (Map.Entry<String, Set<String>> e : edges.entrySet()) {
            Comp from = e.getKey().equals(root.ref) ? root : byRef.get(e.getKey());
            if (from == null) continue;
            for (String toRef : e.getValue()) {
                Comp to = byRef.get(toRef);
                if (to == null) continue;
                if (from == root && to.module) {
                    rels.add(Json.obj("spdxElementId", root.spdxId, "relationshipType", "CONTAINS", "relatedSpdxElement", to.spdxId));
                    continue;
                }
                String scope = edgeScope.getOrDefault(e.getKey() + ">" + toRef, "compile");
                switch (scope) {
                    case "test": rels.add(Json.obj("spdxElementId", to.spdxId, "relationshipType", "TEST_DEPENDENCY_OF", "relatedSpdxElement", from.spdxId)); break;
                    case "provided": rels.add(Json.obj("spdxElementId", to.spdxId, "relationshipType", "PROVIDED_DEPENDENCY_OF", "relatedSpdxElement", from.spdxId)); break;
                    case "runtime": rels.add(Json.obj("spdxElementId", to.spdxId, "relationshipType", "RUNTIME_DEPENDENCY_OF", "relatedSpdxElement", from.spdxId)); break;
                    default: rels.add(Json.obj("spdxElementId", from.spdxId, "relationshipType", "DEPENDS_ON", "relatedSpdxElement", to.spdxId));
                }
            }
        }
        doc.put("relationships", rels);
        return doc;
    }
}
