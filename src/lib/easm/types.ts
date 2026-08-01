/**
 * EASM - External Attack Surface Management
 * Shared type definitions for the scanning engine.
 */

export type ModuleId =
  | "dns"
  | "subdomains"
  | "ports"
  | "http"
  | "tls"
  | "tech"
  | "banners"
  | "vulns"
  | "threatintel"
  | "emailsec"
  | "opendirs"
  | "firewall"
  | "subtakeover"
  | "cloudenum"
  | "screenshots"
  | "jsanalyze"
  | "api"
  | "inject"
  | "webdav"
  | "ssltests"
  | "crawl"
  | "recon"
  | "spider"
  | "wayback"
  | "hostheader"
  | "auth"
  | "csrf"
  | "deserialization"
  | "smuggling"
  | "cache";

export interface ScanConfig {
  /** Target domain or host, e.g. "example.com" */
  target: string;
  /** Which modules to run. Empty = all modules. */
  modules: ModuleId[];
  /** Ports to scan (TCP connect scan). */
  ports: number[];
  /** Per-host connect timeout in ms. */
  timeout: number;
  /** Concurrency for port/subdomain scanning. */
  concurrency: number;
  /** Whether to enumerate subdomains. */
  enumerateSubdomains: boolean;
  /** Max subdomains to resolve/keep. */
  maxSubdomains: number;
}

export type LogLevel = "info" | "success" | "warn" | "error" | "debug";

/** A line of terminal output produced by the scanner. */
export interface ScanLog {
  level: LogLevel;
  message: string;
  /** Optional module that produced the line. */
  module?: ModuleId;
  ts: number;
}

export type ScanEvent =
  | { type: "banner"; target: string; modules: ModuleId[]; ts: number }
  | { type: "module:start"; module: ModuleId; ts: number }
  | { type: "module:end"; module: ModuleId; ts: number; duration: number }
  | { type: "log"; log: ScanLog }
  | { type: "result"; module: ModuleId; data: unknown; ts: number }
  | { type: "progress"; module: ModuleId; current: number; total: number; ts: number }
  | { type: "done"; summary: ScanSummary; ts: number };

export interface ScanSummary {
  target: string;
  startedAt: number;
  finishedAt: number;
  durationMs: number;
  modulesRan: ModuleId[];
  counts: Record<string, number>;
  findings: {
    subdomains: number;
    openPorts: number;
    httpServices: number;
    dnsRecords: number;
    tlsCerts: number;
    technologies: number;
    banners: number;
    vulnerabilities: number;
    threatIntelSources: number;
    threatIntelSubdomains: number;
    emailSecIssues: number;
    openDirs: number;
    firewallsDetected: number;
    bypassPayloads: number;
    attackSurfacePaths: number;
    takeoverVulnerable: number;
    cloudAssets: number;
    httpFingerprints: number;
    jsSecrets: number;
    jsEndpoints: number;
    apiEndpoints: number;
    injectPoints: number;
    webdavEnabled: number;
    sslIssues: number;
    crawledPages: number;
    crawledLinks: number;
    reconRecords: number;
    spiderPages: number;
    spiderForms: number;
    waybackUrls: number;
    hostHeaderIssues: number;
    authIssues: number;
    csrfIssues: number;
    deserIssues: number;
    smugglingIssues: number;
    cacheIssues: number;
  };
}

// ---- Threat-Intelligence result shape ----

export interface ThreatIntelSource {
  name: string;
  ok: boolean;
  error?: string;
  subdomains?: string[];
  records?: { type: string; value: string }[];
  resolvedIps?: string[];
  reputation?: number;
  categories?: string[];
  analysisStats?: {
    harmless: number;
    malicious: number;
    suspicious: number;
    undetected: number;
  };
  ipHistory?: { ip: string; firstSeen: string; lastSeen: string }[];
  tags?: string[];
}

export interface ThreatIntelResult {
  sources: {
    shodan: ThreatIntelSource;
    c99: ThreatIntelSource;
    virustotal: ThreatIntelSource;
    securitytrails: ThreatIntelSource;
  };
  aggregated: {
    subdomains: string[];
    resolvedIps: string[];
    reputation: number | null;
    maliciousVotes: number | null;
    categories: string[];
    totalRecords: number;
  };
}

// ---- Per-module result shapes ----

export interface DnsResult {
  records: {
    type: string;
    name: string;
    value: string;
    ttl?: number;
  }[];
  resolvers: string[];
}

export interface SubdomainResult {
  subdomains: {
    hostname: string;
    ip: string;
    source: string;
  }[];
}

export interface PortResult {
  ports: {
    port: number;
    service: string;
    state: "open" | "closed" | "filtered";
    banner?: string;
    protocol: "tcp" | "udp";
  }[];
  osGuess: {
    ttl: number | null;
    os: string;
    confidence: string;
  } | null;
}

export interface HttpResult {
  hosts: {
    url: string;
    status: number;
    title: string;
    server: string;
    redirect: string;
    https: boolean;
    ip: string;
  }[];
}

export interface TlsResult {
  certs: {
    host: string;
    subject: string;
    issuer: string;
    validFrom: string;
    validTo: string;
    daysRemaining: number;
    serialNumber: string;
    signatureAlgorithm: string;
    san: string[];
    selfSigned: boolean;
  }[];
}

export interface TechResult {
  hosts: {
    url: string;
    technologies: { name: string; confidence: string }[];
  }[];
}

export interface BannerResult {
  banners: {
    host: string;
    port: number;
    service: string;
    banner: string;
  }[];
}

export interface VulnResult {
  hosts: {
    url: string;
    findings: {
      id: string;
      severity: "high" | "medium" | "low" | "info";
      title: string;
      detail: string;
    }[];
  }[];
}

// ---- Email Security result shape ----

export interface EmailSecResult {
  domain: string;
  spf: {
    present: boolean;
    record?: string;
    policy?: "all" | "~all" | "-all" | "+all" | "?all" | "none";
    dnsLookups?: number;
    issues: string[];
  };
  dmarc: {
    present: boolean;
    record?: string;
    policy?: "none" | "quarantine" | "reject" | "missing";
    pct?: number;
    rua?: string;
    issues: string[];
  };
  dkim: {
    selectorsChecked: string[];
    found: { selector: string; record: string }[];
    issues: string[];
  };
  mx: {
    servers: { exchange: string; priority: number }[];
    providers: string[];
    issues: string[];
  };
  findings: {
    id: string;
    severity: "high" | "medium" | "low" | "info";
    title: string;
    detail: string;
  }[];
}

// ---- Open Directories result shape ----

export interface OpenDirResult {
  directories: {
    url: string;
    server: string;
    listingType: string;
    sample: string[];
  }[];
  exposedFiles: {
    url: string;
    status: number;
    size: number;
    type: string;
  }[];
}

// ---- Firewall / WAF detection result shape ----

export interface FirewallResult {
  hosts: {
    url: string;
    detected: {
      name: string;
      confidence: "high" | "medium" | "low";
      evidence: string[];
    }[];
    blockStatus: number | null;
    blockSignatures: string[];
    methods: string[];
    cors: {
      enabled: boolean;
      origin: string;
      credentials: boolean;
      wildcard: boolean;
      reflected: boolean;
    };
  }[];
  bypassPayloads: {
    waf: string;
    category: string;
    payloads: string[];
    note: string;
  }[];
  attackSurface: {
    source: string;
    paths: string[];
  }[];
}

// ---- Subdomain Takeover result shape ----

export interface SubTakeoverResult {
  checked: number;
  vulnerable: {
    hostname: string;
    cname: string;
    service: string;
    fingerprint: string;
    severity: "high" | "medium" | "low";
  }[];
}

// ---- Cloud Asset Enumeration result shape ----

export interface CloudEnumResult {
  buckets: {
    provider: string;
    name: string;
    url: string;
    exists: boolean;
    public: boolean;
    listing: boolean;
    sample: string[];
    region?: string;
  }[];
  repos: {
    provider: string;
    name: string;
    url: string;
    exists: boolean;
    private: boolean;
  }[];
}

// ---- HTTP Screenshots / Deep Fingerprint result shape ----

export interface ScreenshotResult {
  hosts: {
    url: string;
    title: string;
    statusCode: number;
    redirectChain: { url: string; status: number }[];
    faviconHash: string | null;
    faviconMmh: string | null;
    server: string;
    poweredBy: string;
    securityHeaders: {
      hsts: boolean;
      csp: boolean;
      xfo: boolean;
      xcto: boolean;
      referrer: boolean;
    };
    cookies: { name: string; secure: boolean; httpOnly: boolean; sameSite: string }[];
    forms: number;
    inputs: number;
    jsFiles: number;
    externalLinks: number;
    https: boolean;
    hstsMaxAge: number | null;
    tlsIssuer: string;
  }[];
}

// ---- JavaScript Analysis result shape ----

export interface JsAnalyzeResult {
  files: {
    url: string;
    size: number;
    secrets: { type: string; value: string; line: number }[];
    endpoints: string[];
    cloudKeys: { provider: string; key: string }[];
    internalUrls: string[];
    comments: string[];
  }[];
}

// ---- API Discovery result shape ----

export interface ApiResult {
  endpoints: {
    url: string;
    method: string;
    source: string;
    params: string[];
  }[];
  graphql: {
    url: string;
    introspection: boolean;
    types: string[];
    queries: string[];
  }[];
  swagger: {
    url: string;
    version: string;
    title: string;
    paths: number;
  }[];
  versionedApis: { version: string; url: string; status: number }[];
}

// ---- Injection Point Detection result shape ----

export interface InjectResult {
  hosts: {
    url: string;
    points: {
      type: "sqli" | "nosqli" | "ssti" | "cmdi" | "xss" | "ldap" | "xpath" | "openredirect";
      param: string;
      method: string;
      payload: string;
      evidence: string;
      severity: "high" | "medium" | "low";
    }[];
  }[];
}

// ---- WebDAV Probing result shape ----

export interface WebDavResult {
  hosts: {
    url: string;
    enabled: boolean;
    methods: string[];
    writable: boolean;
    propfindDepth: boolean;
    authRequired: boolean;
    uploads: { path: string; success: boolean; status: number }[];
  }[];
}

// ---- Advanced SSL/TLS Tests result shape ----

export interface SslTestsResult {
  hosts: {
    host: string;
    protocols: { name: string; enabled: boolean; insecure: boolean }[];
    ciphers: { name: string; strength: "strong" | "weak" | "insecure" }[];
    cipherCount: number;
    weakCiphers: number;
    issues: {
      id: string;
      severity: "high" | "medium" | "low" | "info";
      title: string;
      detail: string;
    }[];
    certChainLength: number;
    ocspStapling: boolean;
    hsts: boolean;
    ticketRotation: boolean;
  }[];
}

// ---- Web Crawler result shape ----

export interface CrawlResult {
  pages: {
    url: string;
    status: number;
    title: string;
    depth: number;
    links: number;
    forms: number;
    params: string[];
  }[];
  internalLinks: string[];
  externalLinks: string[];
  emails: string[];
  phones: string[];
  files: string[];
}

// ---- Recon (WHOIS / ASN / GeoIP) result shape ----

export interface ReconResult {
  whois: {
    registrar?: string;
    createdDate?: string;
    updatedDate?: string;
    expiryDate?: string;
    nameServers?: string[];
    registrantOrg?: string;
    registrantCountry?: string;
    raw?: string;
  };
  asn: {
    asn?: string;
    org?: string;
    network?: string;
    route?: string;
  };
  geo: {
    ip: string;
    country?: string;
    region?: string;
    city?: string;
    lat?: number;
    lon?: number;
    isp?: string;
    org?: string;
  };
  reverseDns: string[];
}

// ---- Advanced Spider result shape ----

export interface SpiderResult {
  pages: {
    url: string;
    status: number;
    title: string;
    depth: number;
    forms: SpiderForm[];
    hiddenInputs: { name: string; value: string }[];
    comments: string[];
    metaTags: { name: string; content: string }[];
    structuredData: string[];
    jsFiles: string[];
    inlineScripts: number;
  }[];
  allForms: SpiderForm[];
  allParams: string[];
  sitemapUrls: string[];
}

export interface SpiderForm {
  action: string;
  method: string;
  inputs: { name: string; type: string; value: string }[];
}

// ---- Wayback Machine result shape ----

export interface WaybackResult {
  totalUrls: number;
  urls: { url: string; timestamp: string; status: number }[];
  archivedPaths: string[];
  deletedPages: { url: string; lastSeen: string }[];
  fileTypes: { ext: string; count: number }[];
}

// ---- Host Header Injection / SSRF result shape ----

export interface HostHeaderResult {
  hosts: {
    url: string;
    findings: {
      id: string;
      severity: "high" | "medium" | "low" | "info";
      title: string;
      detail: string;
      evidence: string;
    }[];
  }[];
  ssrfTestPoints: { param: string; url: string; note: string }[];
  crlfTests: { url: string; injected: boolean; evidence: string }[];
}

// ---- Auth Bypass result shape ----

export interface AuthResult {
  hosts: {
    url: string;
    findings: {
      id: string;
      severity: "high" | "medium" | "low" | "info";
      title: string;
      detail: string;
    }[];
  }[];
  defaultCreds: { url: string; panel: string; tested: number; success: boolean }[];
  jwtTests: { url: string; noneAlgAccepted: boolean; weakSecret: boolean; detail: string }[];
}

// ---- CSRF result shape ----

export interface CsrfResult {
  hosts: {
    url: string;
    forms: {
      action: string;
      method: string;
      hasCsrfToken: boolean;
      tokenField?: string;
      vulnerable: boolean;
      reason: string;
    }[];
    findings: {
      id: string;
      severity: "high" | "medium" | "low" | "info";
      title: string;
      detail: string;
    }[];
  }[];
}

// ---- Deserialization result shape ----

export interface DeserializationResult {
  hosts: {
    url: string;
    endpoints: {
      param: string;
      method: string;
      payload: string;
      technique: string;
      response: string;
      suspicious: boolean;
    }[];
    findings: {
      id: string;
      severity: "high" | "medium" | "low" | "info";
      title: string;
      detail: string;
    }[];
  }[];
}

// ---- HTTP Request Smuggling result shape ----

export interface SmugglingResult {
  hosts: {
    url: string;
    tests: {
      technique: "CL.TE" | "TE.CL" | "TE.TE" | "CL.CL";
      payload: string;
      timingAnomaly: boolean;
      responseDiff: boolean;
      detail: string;
    }[];
    findings: {
      id: string;
      severity: "high" | "medium" | "low" | "info";
      title: string;
      detail: string;
    }[];
  }[];
}

// ---- Cache Poisoning / Deception result shape ----

export interface CacheResult {
  hosts: {
    url: string;
    unkeyedHeaders: { header: string; reflected: boolean; evidence: string }[];
    cachePoisoning: { url: string; header: string; value: string; poisoned: boolean; evidence: string }[];
    webCacheDeception: { url: string; path: string; cached: boolean; evidence: string }[];
    findings: {
      id: string;
      severity: "high" | "medium" | "low" | "info";
      title: string;
      detail: string;
    }[];
  }[];
}
