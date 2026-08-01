/**
 * EASM Scanner Orchestrator
 * Runs the configured modules against a target and emits ScanEvents
 * that both the CLI and the WebSocket service can consume.
 */
import { EventEmitter } from "events";
import { runDns } from "./dns";
import { runSubdomains } from "./subdomains";
import { runPorts } from "./ports";
import { runHttp } from "./http";
import { runTls } from "./tls";
import { runTech } from "./tech";
import { runBanners } from "./banners";
import { runVulns } from "./vulns";
import { runThreatIntel } from "./threatintel";
import { runEmailSec } from "./emailsec";
import { runOpenDirs } from "./opendirs";
import { runFirewall } from "./firewall";
import { runSubTakeover } from "./subtakeover";
import { runCloudEnum } from "./cloudenum";
import { runScreenshots } from "./screenshots";
import { runJsAnalyze } from "./jsanalyze";
import { runApi } from "./api";
import { runInject } from "./inject";
import { runWebDav } from "./webdav";
import { runSslTests } from "./ssltests";
import { runCrawl } from "./crawl";
import { runRecon } from "./recon";
import { runSpider } from "./spider";
import { runWayback } from "./wayback";
import { runHostHeader } from "./hostheader";
import { runAuth } from "./auth";
import { runCsrf } from "./csrf";
import { runDeserialization } from "./deserialization";
import { runSmuggling } from "./smuggling";
import { runCache } from "./cache";
import type {
  ModuleId,
  ScanConfig,
  ScanEvent,
  ScanLog,
  LogLevel,
  ScanSummary,
  DnsResult,
  SubdomainResult,
  PortResult,
  HttpResult,
  TlsResult,
  TechResult,
  BannerResult,
  VulnResult,
  ThreatIntelResult,
  EmailSecResult,
  OpenDirResult,
  FirewallResult,
  SubTakeoverResult,
  CloudEnumResult,
  ScreenshotResult,
  JsAnalyzeResult,
  ApiResult,
  InjectResult,
  WebDavResult,
  SslTestsResult,
  CrawlResult,
  ReconResult,
  SpiderResult,
  WaybackResult,
  HostHeaderResult,
  AuthResult,
  CsrfResult,
  DeserializationResult,
  SmugglingResult,
  CacheResult,
} from "./types";

export const ALL_MODULES: ModuleId[] = [
  "dns",
  "subdomains",
  "ports",
  "http",
  "tls",
  "tech",
  "banners",
  "vulns",
  "threatintel",
  "emailsec",
  "opendirs",
  "firewall",
  "subtakeover",
  "cloudenum",
  "screenshots",
  "jsanalyze",
  "api",
  "inject",
  "webdav",
  "ssltests",
  "crawl",
  "recon",
  "spider",
  "wayback",
  "hostheader",
  "auth",
  "csrf",
  "deserialization",
  "smuggling",
  "cache",
];

export const DEFAULT_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433,
  1521, 1723, 2049, 2375, 2376, 3000, 3306, 3389, 5000, 5432, 5900, 5984, 6379,
  6443, 8000, 8080, 8443, 8888, 9000, 9042, 9090, 9200, 9300, 11211, 15672, 27017,
];

export function normalizeTarget(input: string): string {
  let t = input.trim();
  t = t.replace(/^[a-zA-Z]+:\/\//, "");
  t = t.split("/")[0];
  t = t.split(":")[0];
  return t.toLowerCase();
}

export function defaultConfig(target: string): ScanConfig {
  return {
    target: normalizeTarget(target),
    modules: [...ALL_MODULES],
    ports: [...DEFAULT_PORTS],
    timeout: 4000,
    concurrency: 50,
    enumerateSubdomains: true,
    maxSubdomains: 40,
  };
}

export interface ScanResults {
  dns?: DnsResult;
  subdomains?: SubdomainResult;
  ports?: PortResult;
  http?: HttpResult;
  tls?: TlsResult;
  tech?: TechResult;
  banners?: BannerResult;
  vulns?: VulnResult;
  threatintel?: ThreatIntelResult;
  emailsec?: EmailSecResult;
  opendirs?: OpenDirResult;
  firewall?: FirewallResult;
  subtakeover?: SubTakeoverResult;
  cloudenum?: CloudEnumResult;
  screenshots?: ScreenshotResult;
  jsanalyze?: JsAnalyzeResult;
  api?: ApiResult;
  inject?: InjectResult;
  webdav?: WebDavResult;
  ssltests?: SslTestsResult;
  crawl?: CrawlResult;
  recon?: ReconResult;
  spider?: SpiderResult;
  wayback?: WaybackResult;
  hostheader?: HostHeaderResult;
  auth?: AuthResult;
  csrf?: CsrfResult;
  deserialization?: DeserializationResult;
  smuggling?: SmugglingResult;
  cache?: CacheResult;
}

export class EasmScanner extends EventEmitter {
  config: ScanConfig;
  results: ScanResults = {};
  private startTs = 0;

  constructor(config: ScanConfig) {
    super();
    this.config = config;
  }

  private emitEvent(ev: ScanEvent) {
    this.emit("event", ev);
  }

  private log(level: LogLevel, message: string, module?: ModuleId) {
    const log: ScanLog = { level, message, module, ts: Date.now() };
    this.emitEvent({ type: "log", log });
  }

  private async runModule<T>(
    module: ModuleId,
    fn: (log: (m: string) => void) => Promise<T>,
    store: (r: T) => void
  ): Promise<T | undefined> {
    const start = Date.now();
    this.emitEvent({ type: "module:start", module, ts: start });
    const log = (m: string) => this.log("info", m, module);
    try {
      const r = await fn(log);
      store(r);
      this.emitEvent({ type: "result", module, data: r, ts: Date.now() });
      this.emitEvent({ type: "module:end", module, ts: Date.now(), duration: Date.now() - start });
      return r;
    } catch (e: any) {
      this.log("error", `Module ${module} failed: ${e?.message || e}`, module);
      this.emitEvent({ type: "module:end", module, ts: Date.now(), duration: Date.now() - start });
      return undefined;
    }
  }

  async run(): Promise<ScanResults> {
    const { target, modules } = this.config;
    this.startTs = Date.now();

    this.emitEvent({
      type: "banner",
      target,
      modules,
      ts: this.startTs,
    });
    this.log("info", `Target: ${target}`);
    this.log("info", `Modules: ${modules.join(", ")}`);
    this.log("info", `Ports: ${this.config.ports.length} | Timeout: ${this.config.timeout}ms | Concurrency: ${this.config.concurrency}`);

    const want = (m: ModuleId) => modules.length === 0 || modules.includes(m);

    // 1. DNS
    let resolvedIp = "";
    if (want("dns")) {
      const dnsRes = await this.runModule(
        "dns",
        (log) => runDns(target, log),
        (r) => (this.results.dns = r)
      );
      if (dnsRes) {
        const a = dnsRes.records.find((x) => x.type === "A");
        if (a) {
          resolvedIp = a.value;
          this.log("success", `Resolved ${target} -> ${a.value}`, "dns");
        } else {
          this.log("warn", `No A record for ${target}; some modules will be limited.`, "dns");
        }
      }
    }

    // 2. Subdomains
    let hostsToProbe = [target];
    if (want("subdomains") && this.config.enumerateSubdomains) {
      const subRes = await this.runModule(
        "subdomains",
        (log) => runSubdomains(target, this.config.concurrency, this.config.maxSubdomains, log),
        (r) => (this.results.subdomains = r)
      );
      if (subRes) {
        hostsToProbe = [target, ...subRes.subdomains.map((s) => s.hostname)];
      }
    }

    // 3. Threat intelligence (Shodan DNS, c99, VirusTotal, SecurityTrails)
    if (want("threatintel")) {
      await this.runModule(
        "threatintel",
        (log) => runThreatIntel(target, log),
        (r) => (this.results.threatintel = r)
      );
    }

    // 4. Ports (scan the apex target host)
    let openPorts: number[] = [];
    if (want("ports")) {
      const portHost = resolvedIp || target;
      const portRes = await this.runModule(
        "ports",
        (log) =>
          runPorts(portHost, this.config.ports, this.config.timeout, this.config.concurrency, log, (c, t) => {
            this.emitEvent({ type: "progress", module: "ports", current: c, total: t, ts: Date.now() });
          }),
        (r) => (this.results.ports = r)
      );
      if (portRes) openPorts = portRes.ports.map((p) => p.port);
    }

    // 5. HTTP probing across discovered hosts
    let httpUrls: string[] = [];
    if (want("http")) {
      const httpRes = await this.runModule(
        "http",
        (log) => runHttp(hostsToProbe, log),
        (r) => (this.results.http = r)
      );
      if (httpRes) httpUrls = httpRes.hosts.map((h) => h.url);
    }

    // 6. TLS on HTTPS hosts (or all hosts if http didn't run)
    if (want("tls")) {
      const tlsHosts =
        httpUrls.filter((u) => u.startsWith("https://")).map((u) => u.replace(/^https:\/\//, ""));
      const candidates = tlsHosts.length ? tlsHosts : hostsToProbe.slice(0, 8);
      await this.runModule(
        "tls",
        (log) => runTls(candidates, log),
        (r) => (this.results.tls = r)
      );
    }

    // 7. Technology fingerprinting on HTTP hosts
    if (want("tech")) {
      const targets = httpUrls.length ? httpUrls : hostsToProbe.slice(0, 5).flatMap((h) => [`https://${h}`, `http://${h}`]);
      await this.runModule(
        "tech",
        (log) => runTech(targets.slice(0, 12), log),
        (r) => (this.results.tech = r)
      );
    }

    // 8. Banner grabbing on open ports
    if (want("banners")) {
      await this.runModule(
        "banners",
        (log) => runBanners(resolvedIp || target, openPorts, log),
        (r) => (this.results.banners = r)
      );
    }

    // 9. Vulnerability checks on HTTP hosts
    if (want("vulns")) {
      const targets = httpUrls.length ? httpUrls : hostsToProbe.slice(0, 5).flatMap((h) => [`https://${h}`, `http://${h}`]);
      await this.runModule(
        "vulns",
        (log) => runVulns(targets.slice(0, 12), log),
        (r) => (this.results.vulns = r)
      );
    }

    // 10. Email security (SPF / DMARC / DKIM / MX)
    if (want("emailsec")) {
      await this.runModule(
        "emailsec",
        (log) => runEmailSec(target, log),
        (r) => (this.results.emailsec = r)
      );
    }

    // 11. Open directories & exposed files
    if (want("opendirs")) {
      const dirsTargets = httpUrls.length ? httpUrls : hostsToProbe.slice(0, 3).flatMap((h) => [`https://${h}`, `http://${h}`]);
      await this.runModule(
        "opendirs",
        (log) => runOpenDirs(dirsTargets[0] || `https://${target}`, log),
        (r) => (this.results.opendirs = r)
      );
    }

    // 12. Firewall / WAF detection + bypass payloads + attack surface
    if (want("firewall")) {
      const fwTargets = httpUrls.length ? httpUrls : hostsToProbe.slice(0, 3).flatMap((h) => [`https://${h}`, `http://${h}`]);
      await this.runModule(
        "firewall",
        (log) => runFirewall(fwTargets.slice(0, 8), log),
        (r) => (this.results.firewall = r)
      );
    }

    // 13. Subdomain takeover detection
    if (want("subtakeover")) {
      const takeHosts = hostsToProbe.slice(0, 80);
      await this.runModule(
        "subtakeover",
        (log) => runSubTakeover(takeHosts, log),
        (r) => (this.results.subtakeover = r)
      );
    }

    // 14. Cloud asset enumeration (S3/Azure/GCP/GitHub)
    if (want("cloudenum")) {
      await this.runModule(
        "cloudenum",
        (log) => runCloudEnum(target, log),
        (r) => (this.results.cloudenum = r)
      );
    }

    // 15. Deep HTTP fingerprinting (screenshots/favicon/redirect/security headers)
    if (want("screenshots")) {
      const ssTargets = httpUrls.length ? httpUrls : hostsToProbe.slice(0, 5).flatMap((h) => [`https://${h}`, `http://${h}`]);
      await this.runModule(
        "screenshots",
        (log) => runScreenshots(ssTargets.slice(0, 10), log),
        (r) => (this.results.screenshots = r)
      );
    }

    // 16. JavaScript analysis (secrets, endpoints, cloud keys)
    if (want("jsanalyze")) {
      const jsTargets = httpUrls.length ? httpUrls : hostsToProbe.slice(0, 3).flatMap((h) => [`https://${h}`, `http://${h}`]);
      await this.runModule(
        "jsanalyze",
        (log) => runJsAnalyze(jsTargets.slice(0, 5), log),
        (r) => (this.results.jsanalyze = r)
      );
    }

    // 17. API discovery (endpoints, GraphQL, Swagger, versioned APIs)
    if (want("api")) {
      const apiTargets = httpUrls.length ? httpUrls : hostsToProbe.slice(0, 3).flatMap((h) => [`https://${h}`, `http://${h}`]);
      await this.runModule(
        "api",
        (log) => runApi(apiTargets.slice(0, 5), log),
        (r) => (this.results.api = r)
      );
    }

    // 18. Injection point detection (SQLi/NoSQLi/SSTI/cmdi/XSS/LDAP/XPath/open redirect)
    if (want("inject")) {
      const injTargets = httpUrls.length ? httpUrls : hostsToProbe.slice(0, 3).flatMap((h) => [`https://${h}`, `http://${h}`]);
      await this.runModule(
        "inject",
        (log) => runInject(injTargets.slice(0, 5), log),
        (r) => (this.results.inject = r)
      );
    }

    // 19. WebDAV probing (PROPFIND/MKCOL/PUT for file upload)
    if (want("webdav")) {
      const wdTargets = httpUrls.length ? httpUrls : hostsToProbe.slice(0, 3).flatMap((h) => [`https://${h}`, `http://${h}`]);
      await this.runModule(
        "webdav",
        (log) => runWebDav(wdTargets.slice(0, 6), log),
        (r) => (this.results.webdav = r)
      );
    }

    // 20. Advanced SSL/TLS tests (protocols, ciphers, vulnerabilities)
    if (want("ssltests")) {
      const sslHosts = hostsToProbe.filter((h) => h.includes(".")).slice(0, 8);
      await this.runModule(
        "ssltests",
        (log) => runSslTests(sslHosts, log),
        (r) => (this.results.ssltests = r)
      );
    }

    // 21. Web crawler (spider internal links, extract emails/phones/files)
    if (want("crawl")) {
      const crawlUrl = httpUrls[0] || `https://${target}`;
      await this.runModule(
        "crawl",
        (log) => runCrawl(crawlUrl, 2, 25, log),
        (r) => (this.results.crawl = r)
      );
    }

    // 22. Recon (WHOIS / ASN / GeoIP)
    if (want("recon")) {
      await this.runModule(
        "recon",
        (log) => runRecon(target, resolvedIp, log),
        (r) => (this.results.recon = r)
      );
    }

    // 23. Advanced spider (forms, hidden inputs, comments, meta, structured data)
    if (want("spider")) {
      const spiderUrl = httpUrls[0] || `https://${target}`;
      await this.runModule(
        "spider",
        (log) => runSpider(spiderUrl, 2, 20, log),
        (r) => (this.results.spider = r)
      );
    }

    // 24. Wayback Machine (historical URLs, deleted pages, archived paths)
    if (want("wayback")) {
      await this.runModule(
        "wayback",
        (log) => runWayback(target, log),
        (r) => (this.results.wayback = r)
      );
    }

    // 25. Host header injection / SSRF / CRLF
    if (want("hostheader")) {
      const hhTargets = httpUrls.length ? httpUrls : hostsToProbe.slice(0, 3).flatMap((h) => [`https://${h}`, `http://${h}`]);
      await this.runModule(
        "hostheader",
        (log) => runHostHeader(hhTargets.slice(0, 5), log),
        (r) => (this.results.hostheader = r)
      );
    }

    // 26. Auth bypass (default creds, JWT none-alg, weak secret, session fixation)
    if (want("auth")) {
      const authTargets = httpUrls.length ? httpUrls : hostsToProbe.slice(0, 3).flatMap((h) => [`https://${h}`, `http://${h}`]);
      await this.runModule(
        "auth",
        (log) => runAuth(authTargets.slice(0, 5), log),
        (r) => (this.results.auth = r)
      );
    }

    // 27. CSRF token validation
    if (want("csrf")) {
      const csrfTargets = httpUrls.length ? httpUrls : hostsToProbe.slice(0, 3).flatMap((h) => [`https://${h}`, `http://${h}`]);
      await this.runModule(
        "csrf",
        (log) => runCsrf(csrfTargets.slice(0, 5), log),
        (r) => (this.results.csrf = r)
      );
    }

    // 28. Deserialization (Java/PHP/Python/YAML/Fastjson)
    if (want("deserialization")) {
      const deserTargets = httpUrls.length ? httpUrls : hostsToProbe.slice(0, 3).flatMap((h) => [`https://${h}`, `http://${h}`]);
      await this.runModule(
        "deserialization",
        (log) => runDeserialization(deserTargets.slice(0, 5), log),
        (r) => (this.results.deserialization = r)
      );
    }

    // 29. HTTP request smuggling (CL.TE / TE.CL / TE.TE)
    if (want("smuggling")) {
      const smugTargets = httpUrls.length ? httpUrls : hostsToProbe.slice(0, 2).flatMap((h) => [`https://${h}`, `http://${h}`]);
      await this.runModule(
        "smuggling",
        (log) => runSmuggling(smugTargets.slice(0, 4), log),
        (r) => (this.results.smuggling = r)
      );
    }

    // 30. Cache poisoning / web cache deception
    if (want("cache")) {
      const cacheTargets = httpUrls.length ? httpUrls : hostsToProbe.slice(0, 3).flatMap((h) => [`https://${h}`, `http://${h}`]);
      await this.runModule(
        "cache",
        (log) => runCache(cacheTargets.slice(0, 5), log),
        (r) => (this.results.cache = r)
      );
    }

    const summary = this.buildSummary();
    this.emitEvent({ type: "done", summary, ts: Date.now() });
    return this.results;
  }

  private buildSummary(): ScanSummary {
    const finishedAt = Date.now();
    const findings = {
      subdomains: this.results.subdomains?.subdomains.length || 0,
      openPorts: this.results.ports?.ports.length || 0,
      httpServices: this.results.http?.hosts.length || 0,
      dnsRecords: this.results.dns?.records.length || 0,
      tlsCerts: this.results.tls?.certs.length || 0,
      technologies:
        this.results.tech?.hosts.reduce((a, h) => a + h.technologies.length, 0) || 0,
      banners: this.results.banners?.banners.length || 0,
      vulnerabilities:
        this.results.vulns?.hosts.reduce((a, h) => a + h.findings.length, 0) || 0,
      threatIntelSources: this.results.threatintel
        ? ([this.results.threatintel.sources.shodan,
            this.results.threatintel.sources.c99,
            this.results.threatintel.sources.virustotal,
            this.results.threatintel.sources.securitytrails].filter((s) => s.ok).length)
        : 0,
      threatIntelSubdomains: this.results.threatintel?.aggregated.subdomains.length || 0,
      emailSecIssues: this.results.emailsec?.findings.length || 0,
      openDirs: (this.results.opendirs?.directories.length || 0) + (this.results.opendirs?.exposedFiles.length || 0),
      firewallsDetected: this.results.firewall?.hosts.reduce((a, h) => a + h.detected.length, 0) || 0,
      bypassPayloads: this.results.firewall?.bypassPayloads.length || 0,
      attackSurfacePaths: this.results.firewall?.attackSurface.reduce((a, s) => a + s.paths.length, 0) || 0,
      takeoverVulnerable: this.results.subtakeover?.vulnerable.length || 0,
      cloudAssets: (this.results.cloudenum?.buckets.length || 0) + (this.results.cloudenum?.repos.length || 0),
      httpFingerprints: this.results.screenshots?.hosts.length || 0,
      jsSecrets: this.results.jsanalyze?.files.reduce((a, f) => a + f.secrets.length, 0) || 0,
      jsEndpoints: this.results.jsanalyze?.files.reduce((a, f) => a + f.endpoints.length, 0) || 0,
      apiEndpoints: (this.results.api?.endpoints.length || 0) + (this.results.api?.graphql.length || 0) + (this.results.api?.swagger.length || 0),
      injectPoints: this.results.inject?.hosts.reduce((a, h) => a + h.points.length, 0) || 0,
      webdavEnabled: this.results.webdav?.hosts.filter((h) => h.enabled).length || 0,
      sslIssues: this.results.ssltests?.hosts.reduce((a, h) => a + h.issues.length, 0) || 0,
      crawledPages: this.results.crawl?.pages.length || 0,
      crawledLinks: (this.results.crawl?.internalLinks.length || 0) + (this.results.crawl?.externalLinks.length || 0),
      reconRecords: (this.results.recon?.whois.registrar ? 1 : 0) + (this.results.recon?.asn.asn ? 1 : 0) + (this.results.recon?.geo.city ? 1 : 0) + (this.results.recon?.reverseDns.length || 0),
      spiderPages: this.results.spider?.pages.length || 0,
      spiderForms: this.results.spider?.allForms.length || 0,
      waybackUrls: this.results.wayback?.totalUrls || 0,
      hostHeaderIssues: this.results.hostheader?.hosts.reduce((a, h) => a + h.findings.length, 0) || 0,
      authIssues: this.results.auth?.hosts.reduce((a, h) => a + h.findings.length, 0) || 0,
      csrfIssues: this.results.csrf?.hosts.reduce((a, h) => a + h.findings.length, 0) || 0,
      deserIssues: this.results.deserialization?.hosts.reduce((a, h) => a + h.findings.length, 0) || 0,
      smugglingIssues: this.results.smuggling?.hosts.reduce((a, h) => a + h.findings.length, 0) || 0,
      cacheIssues: this.results.cache?.hosts.reduce((a, h) => a + h.findings.length, 0) || 0,
    };
    const counts: Record<string, number> = {};
    for (const [k, v] of Object.entries(findings)) counts[k] = v;

    return {
      target: this.config.target,
      startedAt: this.startTs,
      finishedAt,
      durationMs: finishedAt - this.startTs,
      modulesRan: this.config.modules,
      counts,
      findings,
    };
  }
}
