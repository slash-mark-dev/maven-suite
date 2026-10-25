#!/usr/bin/env python3
"""
Generates the "Maven Suite" section for the Digital Ecosystem page on slashmark.in.
  python3 website/build.py  ->  website/maven-suite.html (paste-in section) + website/preview.html (standalone page)
"""
import html, os

VERSION = "1.0.0"
INSTALL = f"jbang app install --name sm-maven in.slashmark:maven-suite:{VERSION}"
CENTRAL = "https://central.sonatype.com/artifact/in.slashmark/maven-suite"

CATS = [
    ("threat", "Threat intelligence", "Threat"),
    ("release", "Release intelligence", "Release"),
    ("deps", "Dependency analysis", "Dependencies"),
    ("upgrade", "Upgrade intelligence", "Upgrade"),
    ("compliance", "Live compliance", "Compliance"),
    ("ops", "Operations", "Operations"),
]

# (title, description, example command, category)
TOOLS = [
    ("Live CVE Watch", "Watches your whole dependency tree and alerts the moment a new advisory affects it.",
     "sm-maven cve-watch --watch --interval 15m", "threat"),
    ("Zero-Day Impact Scanner", "Enter a CVE and see every affected path in every module, plus the smallest fix.",
     "sm-maven impact CVE-2021-44228", "threat"),
    ("Exploit Prioritizer", "Ranks vulnerabilities by live CISA KEV status and EPSS exploit probability, not just CVSS.",
     "sm-maven prioritize --top 10", "threat"),
    ("Malicious Release Guard", "Flags risky new releases: changed signing key, new Java agents, native code, process execution.",
     "sm-maven release-guard", "threat"),
    ("Namespace Takeover Watch", "Detects look-alike groupIds and dependency-confusion risks for your namespaces.",
     "sm-maven takeover --group com.example", "threat"),
    ("Release Radar", "Live feed of new versions across your direct and transitive dependencies.",
     "sm-maven radar --transitive --since 30d", "release"),
    ("Project Pulse", "Live release cadence, commit activity and abandonment risk for every dependency.",
     "sm-maven pulse --transitive", "release"),
    ("Breaking Change Forecaster", "Checks a new release against the APIs your compiled code actually calls.",
     "sm-maven breakcheck com.google.guava:guava", "release"),
    ("Ecosystem Adoption Tracker", "Shows how many dependents have already moved to each version.",
     "sm-maven adoption com.fasterxml.jackson.core:jackson-databind", "release"),
    ("Relocation & Retirement Alerts", "Finds relocated, retired and abandoned artifacts with their successors.",
     "sm-maven relocations", "release"),
    ("Live Dependency Graph", "Resolves the graph live from Maven Central as a tree, DOT, Mermaid or interactive HTML.",
     "sm-maven graph --format html --vulns -o deps.html", "deps"),
    ("Blast Radius Analyzer", "Who depends on an artifact across Maven Central, and every path to it in your project.",
     "sm-maven blast org.apache.logging.log4j:log4j-core", "deps"),
    ("Transitive Drift Monitor", "Snapshots resolved versions and alerts when a hidden transitive version changes.",
     "sm-maven drift", "deps"),
    ("Conflict Resolution Simulator", "Explains every nearest-wins conflict and simulates pins before you edit the POM.",
     "sm-maven resolve", "deps"),
    ("Classpath Collision Detector", "Duplicate classes, split packages and shaded copies on the runtime classpath.",
     "sm-maven classpath", "deps"),
    ("Upgrade Simulator", "Resolves the upgraded tree first and checks conflicts, vulnerabilities and API breaks.",
     "sm-maven simulate org.apache.logging.log4j:log4j-core:2.24.3", "upgrade"),
    ("Safe Version Finder", "Newest version with no known CVEs, no API breaks for your code, same license and your JDK.",
     "sm-maven safe", "upgrade"),
    ("JDK & Jakarta Readiness Scanner", "Removed JDK APIs, class-file levels and javax-to-jakarta needs for a target Java.",
     "sm-maven jdk --target 21", "upgrade"),
    ("License Change Alert", "Catches relicensing in new releases and enforces your license policy.",
     "sm-maven license-watch", "compliance"),
    ("Live SBOM + VEX", "CycloneDX or SPDX SBOM with live vulnerability and exploitability status.",
     "sm-maven sbom -o bom.cdx.json", "compliance"),
    ("CI Policy Gate", "Fails builds on live risk data: severity, KEV, EPSS, licenses, age and health.",
     "sm-maven gate --fail-on high --kev", "compliance"),
    ("Repository Health Monitor", "Live status, latency, auth and freshness of Central, mirrors, Nexus and Artifactory.",
     "sm-maven repo-status", "ops"),
    ("Publish Tracker", "Follows your release through Central sync, the search index and javadoc.io.",
     "sm-maven publish-track in.slashmark:maven-suite:1.0.0 --wait", "ops"),
    ("Multi-Repo Live Dashboard", "One live risk view across every Maven repository in your GitHub organisation.",
     "sm-maven dashboard --org slash-mark-dev", "ops"),
    ("Alert Hub", "Sends findings from every watch tool to Slack, Teams, Discord, webhooks and e-mail.",
     "sm-maven alerts test", "ops"),
]

CSS = """
.smv{--smv-bg:#020617;--smv-card:#0b1224;--smv-line:#1e293b;--smv-fg:#e2e8f0;--smv-mut:#94a3b8;--smv-acc:#f97316;--smv-acc2:#22d3ee;--smv-code:#030712;color:var(--smv-fg);font-family:Inter,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;line-height:1.5}
.smv *{box-sizing:border-box}
.smv-hero{text-align:center;max-width:820px;margin:0 auto 28px}
.smv-eyebrow{display:inline-block;font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:var(--smv-acc2);border:1px solid var(--smv-line);border-radius:99px;padding:4px 12px;margin-bottom:14px}
.smv-hero h2{font-size:clamp(28px,4vw,40px);margin:0 0 10px;line-height:1.15}
.smv-hero h2 span{background:linear-gradient(90deg,var(--smv-acc),var(--smv-acc2));-webkit-background-clip:text;background-clip:text;color:transparent}
.smv-hero p{color:var(--smv-mut);font-size:17px;margin:0 0 18px}
.smv-install{display:flex;align-items:center;gap:10px;max-width:640px;margin:0 auto 8px;background:var(--smv-code);border:1px solid var(--smv-line);border-radius:12px;padding:10px 12px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:14px;text-align:left}
.smv-install code{flex:1;overflow-x:auto;white-space:nowrap;color:#a5f3fc}
.smv-alt{color:var(--smv-mut);font-size:13px;margin:0 0 14px}
.smv-alt code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px;color:#cbd5e1}
.smv-pills{display:flex;flex-wrap:wrap;justify-content:center;gap:8px;padding:0;margin:0;list-style:none}
.smv-pill{font-size:12px;color:var(--smv-mut);border:1px solid var(--smv-line);border-radius:99px;padding:3px 10px}
.smv-tabs{display:flex;flex-wrap:wrap;justify-content:center;gap:8px;margin:22px 0 20px}
.smv-tab{background:transparent;border:1px solid var(--smv-line);color:var(--smv-mut);border-radius:99px;padding:6px 14px;font-size:13px;cursor:pointer;font-family:inherit}
.smv-tab[aria-pressed="true"],.smv-tab:hover{color:#fff;border-color:var(--smv-acc);background:rgba(249,115,22,.15)}
.smv-tab:focus-visible,.smv-copy:focus-visible,.smv-btn:focus-visible{outline:2px solid var(--smv-acc2);outline-offset:2px}
.smv-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:14px}
.smv-card{background:var(--smv-card);border:1px solid var(--smv-line);border-radius:14px;padding:16px;display:flex;flex-direction:column;gap:10px;transition:border-color .2s,transform .2s;min-width:0}
.smv-card:hover{border-color:var(--smv-acc);transform:translateY(-2px)}
.smv-card[hidden]{display:none}
.smv-top{display:flex;justify-content:space-between;align-items:center;gap:8px}
.smv-num{font-size:12px;color:var(--smv-mut);font-family:ui-monospace,Menlo,Consolas,monospace}
.smv-cat{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--smv-acc2)}
.smv-live{font-size:10px;font-weight:600;letter-spacing:.06em;color:#4ade80;border:1px solid rgba(74,222,128,.35);border-radius:99px;padding:1px 7px;margin-left:6px}
.smv-card h3{margin:0;font-size:16px;line-height:1.3}
.smv-card p{margin:0;color:var(--smv-mut);font-size:14px;flex:1}
.smv-code{display:flex;align-items:center;gap:8px;background:var(--smv-code);border:1px solid var(--smv-line);border-radius:8px;padding:7px 8px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px;min-width:0}
.smv-code .p{color:var(--smv-acc)}
.smv-code code{flex:1;overflow-x:auto;white-space:nowrap;color:#e2e8f0;scrollbar-width:thin}
.smv-copy{flex:none;background:#1e293b;color:#cbd5e1;border:0;border-radius:6px;font-size:11px;padding:4px 8px;cursor:pointer;font-family:inherit}
.smv-copy:hover{background:var(--smv-acc);color:#fff}
.smv-foot{text-align:center;margin-top:18px;color:var(--smv-mut);font-size:14px}
.smv-foot a{color:var(--smv-acc2)}
.smv-cta{margin-top:34px;border:1px solid var(--smv-line);border-radius:18px;padding:28px 22px;background:radial-gradient(circle at 15% 0%,rgba(249,115,22,.20),transparent 55%),radial-gradient(circle at 90% 100%,rgba(34,211,238,.14),transparent 50%),var(--smv-card);display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:18px}
.smv-cta h3{margin:0 0 6px;font-size:22px}
.smv-cta p{margin:0;color:var(--smv-mut);max-width:560px}
.smv-btn{display:inline-block;background:linear-gradient(90deg,var(--smv-acc),#ef4444);color:#fff;text-decoration:none;font-weight:600;border-radius:10px;padding:11px 20px;white-space:nowrap}
.smv-btn:hover{filter:brightness(1.1)}
.smv-sr{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
@media (max-width:520px){.smv-grid{grid-template-columns:1fr}.smv-cta{flex-direction:column;align-items:flex-start}}
@media (prefers-reduced-motion:reduce){.smv-card{transition:none}.smv-card:hover{transform:none}}
""".strip()

# Tools whose primary mode is continuous watching (marked LIVE on the card).
WATCHERS = {"cve-watch", "takeover", "radar", "drift", "license-watch", "relocations", "repo-status", "publish-track", "release-guard"}

SCRIPT = """
(function(){var root=document.getElementById('maven-suite');if(!root)return;
var status=root.querySelector('.smv-status');
root.querySelectorAll('.smv-tab').forEach(function(t){t.addEventListener('click',function(){var c=t.getAttribute('data-cat'),n=0;
root.querySelectorAll('.smv-tab').forEach(function(x){x.setAttribute('aria-pressed',x===t?'true':'false')});
root.querySelectorAll('.smv-card').forEach(function(card){var show=c==='all'||card.getAttribute('data-cat')===c;card.hidden=!show;if(show)n++});
if(status)status.textContent=n+' tools shown';});});
root.querySelectorAll('.smv-copy').forEach(function(b){b.addEventListener('click',function(){var t=b.parentNode.querySelector('code').textContent;
var done=function(){var o=b.textContent;b.textContent='Copied';if(status)status.textContent='Command copied';setTimeout(function(){b.textContent=o},1200)};
if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(t).then(done)}else{var a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();try{document.execCommand('copy');done()}catch(e){}a.remove()}});});})();
""".strip()


def e(s):
    return html.escape(s, quote=True)


def section():
    label = {k: short for k, _, short in CATS}
    out = ["<!-- ===== Slash Mark Digital Ecosystem: Maven Suite (25 tools) ===== -->", "<style>", CSS, "</style>",
           '<section class="smv" id="maven-suite" aria-labelledby="smv-title">',
           '  <div class="smv-hero">',
           '    <span class="smv-eyebrow">Digital Ecosystem</span>',
           '    <h2 id="smv-title"><span>Maven Suite</span></h2>',
           '    <p>Java Package Intelligence Suite. Explore, analyze, and manage Maven artifacts with our specialized toolset, on live data, in real time.</p>',
           f'    <div class="smv-install"><code>{e(INSTALL)}</code><button class="smv-copy" type="button" aria-label="Copy install command">Copy</button></div>',
           f'    <p class="smv-alt">or download the JAR and run <code>java -jar maven-suite-{VERSION}.jar help</code></p>',
           '    <ul class="smv-pills" aria-label="Highlights">'
           '<li class="smv-pill">25 tools · one command</li>'
           '<li class="smv-pill">Live: Maven Central, OSV, CISA KEV, EPSS, deps.dev, GitHub</li>'
           '<li class="smv-pill">Watch mode + Slack/Teams/Discord/e-mail alerts</li>'
           '<li class="smv-pill">Maven-exact resolution</li>'
           '<li class="smv-pill">JSON output &amp; CI exit codes</li>'
           '<li class="smv-pill">Java 17+ · zero dependencies · MIT</li></ul>',
           '  </div>']
    tabs = [f'<button class="smv-tab" type="button" data-cat="all" aria-pressed="true">All {len(TOOLS)}</button>']
    for key, name, _ in CATS:
        tabs.append(f'<button class="smv-tab" type="button" data-cat="{key}" aria-pressed="false">{e(name)}</button>')
    out.append('  <div class="smv-tabs" role="group" aria-label="Filter tools">' + "".join(tabs) + "</div>")
    out.append('  <p class="smv-status smv-sr" role="status" aria-live="polite"></p>')
    out.append('  <div class="smv-grid">')
    for i, (title, desc, cmd, cat) in enumerate(TOOLS, 1):
        name = cmd.split()[1]
        live = '<span class="smv-live" title="Runs continuously with --watch">LIVE</span>' if name in WATCHERS else ""
        out += [f'      <article class="smv-card" data-cat="{cat}">',
                f'        <div class="smv-top"><span class="smv-num">{i:02d}</span><span class="smv-cat">{e(label[cat])}{live}</span></div>',
                f'        <h3>{e(title)}</h3>',
                f'        <p>{e(desc)}</p>',
                f'        <div class="smv-code"><span class="p" aria-hidden="true">$</span><code>{e(cmd)}</code>'
                f'<button class="smv-copy" type="button" aria-label="Copy command: {e(cmd)}">Copy</button></div>',
                '      </article>']
    out += ['  </div>',
            f'  <p class="smv-foot">Run <code>sm-maven &lt;tool&gt; --help</code> for every option · <a href="{CENTRAL}" target="_blank" rel="noopener">View on Maven Central →</a></p>',
            '  <div class="smv-cta">',
            '    <div>',
            '      <h3>Enterprise Java Solutions</h3>',
            '      <p>Need specialized Java development, Maven build engineering or software supply-chain security? Our team of Java experts is here to help.</p>',
            '    </div>',
            '    <a class="smv-btn" href="mailto:mukesh@slashmark.in?subject=Enterprise%20Java%20Solutions">Talk to our Java experts</a>',
            '  </div>',
            '</section>',
            '<script>', SCRIPT, '</script>',
            '<!-- ===== end Maven Suite ===== -->']
    return "\n".join(out) + "\n"


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    s = section()
    open(os.path.join(here, "maven-suite.html"), "w", encoding="utf-8").write(s)
    page = ('<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>Maven Suite</title><style>body{margin:0;background:#020617;padding:48px 16px}</style></head><body>\n'
            + s + "</body></html>\n")
    open(os.path.join(here, "preview.html"), "w", encoding="utf-8").write(page)
    print(f"website/maven-suite.html: {len(TOOLS)} tools, {len(s)} bytes")


if __name__ == "__main__":
    main()
