/**
 * Open Directories Module
 *
 * Probes a large list of common paths for directory-listing responses
 * (Apache/Nginx autoindex, IIS, Python http.server) and exposed
 * sensitive files. Reports each finding with sample contents.
 */
import type { OpenDirResult } from "./types";

const DIRECTORY_PATHS = [
  "/", "/files/", "/uploads/", "/upload/", "/backup/", "/backups/",
  "/data/", "/public/", "/static/", "/assets/", "/docs/", "/documents/",
  "/downloads/", "/download/", "/dl/", "/tmp/", "/temp/", "/var/",
  "/logs/", "/images/", "/img/", "/media/", "/share/", "/shared/",
  "/pub/", "/ftp/", "/home/", "/srv/", "/etc/", "/config/",
  "/db/", "/database/", "/sql/", "/dump/", "/archive/", "/archives/",
  "/old/", "/new/", "/test/", "/testing/", "/dev/", "/staging/",
  "/stage/", "/dist/", "/build/", "/node_modules/", "/vendor/",
  "/storage/", "/private/", "/secret/", "/secrets/", "/certs/",
  "/keys/", "/cache/", "/sessions/", "/upload/files/", "/sites/",
  "/content/", "/uploads/images/", "/media/uploads/", "/files/backup/",
  "/.well-known/", "/static/files/", "/assets/files/", "/public/files/",
  "/var/log/", "/var/www/", "/usr/", "/opt/", "/web/", "/www/",
  "/cgi-bin/", "/manager/", "/admin/files/", "/reports/", "/report/",
  "/exports/", "/import/", "/resources/", "/resource/", "/lib/",
  "/libs/", "/src/", "/source/", "/sources/", "/conf/", "/cfg/",
  "/api/files/", "/api/uploads/", "/v1/files/", "/cdn/", "/edge/",
  "/backup-db/", "/mysql/", "/postgres/", "/redis/", "/mongo/",
  "/snapshots/", "/git/", "/svn/", "/hg/", "/bzr/",
];

const SENSITIVE_FILES = [
  "/.env", "/.env.local", "/.env.production", "/.env.development",
  "/.git/config", "/.git/HEAD", "/.git/index", "/.gitignore",
  "/.svn/entries", "/.svn/wc.db", "/.hg/store", "/.bzr/README",
  "/.DS_Store", "/.htaccess", "/.htpasswd", "/web.config",
  "/wp-config.php", "/wp-config.php.bak", "/config.php", "/config.php.bak",
  "/configuration.php", "/settings.py", "/settings.php", "/config.json",
  "/config.yml", "/config.yaml", "/application.yml", "/application.properties",
  "/database.yml", "/credentials.json", "/secrets.json", "/secrets.yml",
  "/id_rsa", "/id_dsa", "/.ssh/id_rsa", "/.ssh/authorized_keys",
  "/backup.sql", "/db.sql", "/dump.sql", "/database.sql",
  "/backup.zip", "/backup.tar.gz", "/backup.tar", "/site.zip",
  "/archive.zip", "/www.zip", "/web.zip", "/html.zip",
  "/package.json", "/composer.json", "/requirements.txt", "/Gemfile.lock",
  "/Dockerfile", "/docker-compose.yml", "/docker-compose.yaml",
  "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml",
  "/server-status", "/server-info", "/phpinfo.php", "/info.php",
  "/.aws/credentials", "/.aws/config", "/.docker/config.json",
];

interface ProbeResult {
  url: string;
  status: number;
  server: string;
  contentType: string;
  body: string;
  size: number;
}

async function probe(
  url: string,
  timeoutMs = 6000
): Promise<ProbeResult | null> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: ctrl.signal,
      redirect: "manual",
      headers: { "User-Agent": "easm-scanner/1.0" },
    });
    const server = res.headers.get("server") || "";
    const ct = res.headers.get("content-type") || "";
    let body = "";
    if (ct.includes("text") || ct.includes("xml") || ct.includes("json") || ct === "") {
      try {
        body = await res.text();
      } catch {
        body = "";
      }
    }
    return { url, status: res.status, server, contentType: ct, body, size: body.length };
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

function detectListing(body: string): string | null {
  const b = body.toLowerCase();
  if (/<title>index of \//i.test(body)) return "Apache autoindex";
  if (/<title>index of/i.test(body)) return "Apache autoindex";
  if (/directory listing for\//i.test(body)) return "Python http.server";
  if (/<h1>directory listing for/i.test(body)) return "Python http.server";
  if (/>\/var\/www\/html</i.test(body)) return "Apache autoindex";
  if (/class=".*?directory"/i.test(body) && /href="\.\.\/"/i.test(body)) return "Nginx autoindex";
  if (/<a href="\.\.\/">parent directory<\/a>/i.test(body)) return "IIS / generic listing";
  if (/<pre>.*<a href/i.test(body) && /href="\.\//i.test(body) && /last modified/i.test(body)) return "Generic listing";
  if (/<title>\/.*<\/title>/i.test(body) && /<a href/i.test(body) && /href="\.\.\/"/i.test(body)) return "Nginx autoindex";
  return null;
}

function extractSample(body: string): string[] {
  const links = new Set<string>();
  const re = /href="([^"]+)"/gi;
  let m: RegExpExecArray | null;
  let count = 0;
  while ((m = re.exec(body)) !== null && count < 8) {
    const href = m[1];
    if (href === "../" || href === ".." || href === "/" || href.startsWith("?") || href.startsWith("#")) continue;
    links.add(href);
    count++;
  }
  return Array.from(links);
}

export async function runOpenDirs(
  baseUrl: string,
  log: (msg: string) => void
): Promise<OpenDirResult> {
  const base = baseUrl.replace(/\/$/, "");
  const directories: OpenDirResult["directories"] = [];
  const exposedFiles: OpenDirResult["exposedFiles"] = [];

  log(`Probing ${DIRECTORY_PATHS.length} common directory paths on ${base} ...`);
  let dirDone = 0;
  for (const path of DIRECTORY_PATHS) {
    const res = await probe(`${base}${path}`);
    dirDone++;
    if (dirDone % 12 === 0) log(`  ... ${dirDone}/${DIRECTORY_PATHS.length} paths checked`);
    if (!res || res.status !== 200) continue;
    const listing = detectListing(res.body);
    if (listing) {
      const sample = extractSample(res.body);
      directories.push({
        url: res.url,
        server: res.server || "unknown",
        listingType: listing,
        sample,
      });
      log(`  [+] OPEN DIR: ${res.url} (${listing})${sample.length ? " — " + sample.slice(0, 3).join(", ") : ""}`);
    }
  }

  log(`Probing ${SENSITIVE_FILES.length} sensitive files on ${base} ...`);
  let fileDone = 0;
  for (const path of SENSITIVE_FILES) {
    const res = await probe(`${base}${path}`);
    fileDone++;
    if (fileDone % 12 === 0) log(`  ... ${fileDone}/${SENSITIVE_FILES.length} files checked`);
    if (!res) continue;
    // Treat 200 as exposed; some config files return 200 with real content.
    if (res.status === 200) {
      // Filter out generic 200 app pages (e.g. SPA index.html) by size & content-type heuristics.
      const looksLikeHtml = res.contentType.includes("text/html") && /<html|<!doctype/i.test(res.body);
      const isConfigFile = /\.(env|json|yml|yaml|sql|zip|tar|gz|bak|properties|conf|cfg|txt|php|py|rb|key|pem|rsa|config|credentials)$/i.test(path) || /\.(git|svn|hg|bzr|ssh|aws|docker)/i.test(path);
      if (looksLikeHtml && !isConfigFile && path !== "/robots.txt" && path !== "/sitemap.xml") continue;
      const type = path.split(".").pop() || "unknown";
      exposedFiles.push({
        url: res.url,
        status: res.status,
        size: res.size,
        type,
      });
      log(`  [+] EXPOSED FILE: ${res.url} (${res.size} bytes, ${type})`);
    }
  }

  log(
    `Open directory scan complete: ${directories.length} open dir(s), ${exposedFiles.length} exposed file(s).`
  );
  return { directories, exposedFiles };
}
