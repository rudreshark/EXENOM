/**
 * Cloud Asset Enumeration Module
 *
 * Discovers cloud assets (storage buckets, repos) related to a target domain
 * by probing candidate names derived from the domain and common permutations.
 *
 * Providers probed:
 *   - AWS S3            (s3.amazonaws.com, s3.us-east-1.amazonaws.com)
 *   - Azure Blob        (blob.core.windows.net)
 *   - GCP Storage       (storage.googleapis.com)
 *   - DigitalOcean Spaces (nyc3.digitaloceanspaces.com)
 *   - Aliyun OSS        (oss-cn-hangzhou.aliyuncs.com)
 *   - GitHub repos      (github.com + api.github.com/orgs)
 *
 * Only Node built-ins (fetch) are used — no external packages.
 */
import type { CloudEnumResult } from "./types";

const UA = "easm-scanner/1.0";
const TIMEOUT_MS = 6000;

/** Permutations applied to the apex to generate candidate bucket/repo names. */
const SUFFIXES = [
  "",
  "-backup",
  "-dev",
  "-staging",
  "-prod",
  "-test",
  "-logs",
  "-data",
  "-media",
  "-assets",
  "-uploads",
  "-files",
  "-static",
  "2",
  "-backups",
];

/** Extract the apex (registrable label) from a domain, e.g. "sub.example.com" -> "example". */
function apexOf(domain: string): string {
  const clean = domain
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/^www\./, "")
    .split("/")[0]
    .trim();
  const parts = clean.split(".");
  // Last two labels are the registrable apex (best-effort; ignores exotic TLDs).
  if (parts.length >= 2) {
    return parts[parts.length - 2];
  }
  return parts[0] || clean;
}

/** fetch with a hard timeout via AbortController; returns response or null. */
async function fetchWithTimeout(
  url: string,
  opts: RequestInit = {},
  timeoutMs = TIMEOUT_MS
): Promise<Response | null> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, {
      ...opts,
      signal: ctrl.signal,
      headers: {
        "User-Agent": UA,
        Accept: "*/*",
        ...(opts.headers || {}),
      },
    });
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

/** Extract the first N <Key> values from an S3/GCP ListBucketResult XML body. */
function parseSampleKeys(xml: string, max = 5): string[] {
  const keys: string[] = [];
  const re = /<Key>([\s\S]*?)<\/Key>/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(xml)) !== null && keys.length < max) {
    keys.push(m[1].trim());
  }
  return keys;
}

/** Extract region from S3 XML (e.g. <Region>us-east-1</Region>) if present. */
function parseRegion(xml: string): string | undefined {
  const m = xml.match(/<Region>([\s\S]*?)<\/Region>/i);
  return m ? m[1].trim() : undefined;
}

// ---- Provider probes ----

async function probeS3(
  name: string,
  host: string,
  region?: string
): Promise<CloudEnumResult["buckets"][number] | null> {
  const url = `https://${host}`;
  const res = await fetchWithTimeout(url);
  if (!res) return null;

  // 404 NoSuchBucket => bucket doesn't exist
  if (res.status === 404) {
    let body = "";
    try {
      body = await res.text();
    } catch {
      /* ignore */
    }
    if (body.includes("NoSuchBucket") || body.includes("Not Found")) {
      return null;
    }
    // Some S3 regions return 404 with no XML for missing buckets — also treat as not-existing.
    return null;
  }

  // Bucket exists. Now check whether it allows public listing.
  let body = "";
  try {
    body = await res.text();
  } catch {
    /* ignore body read errors */
  }

  const listing = body.includes("<ListBucketResult");
  const sample = listing ? parseSampleKeys(body) : [];

  return {
    provider: "AWS S3",
    name,
    url,
    exists: true,
    public: listing,
    listing,
    sample,
    region: region || (listing ? parseRegion(body) : undefined),
  };
}

async function probeAzure(name: string): Promise<CloudEnumResult["buckets"][number] | null> {
  const url = `https://${name}.blob.core.windows.net`;
  const res = await fetchWithTimeout(url);
  if (!res) return null;

  let body = "";
  try {
    body = await res.text();
  } catch {
    /* ignore */
  }

  // Azure returns 404 with "ContainerNotFound" in the body when the account
  // doesn't exist (yes, it's a confusingly-named error). A real account that
  // exists but has no public container returns 400 with "InvalidQueryParameterValue"
  // or a different error, or 200 with an Enumeration result.
  if (res.status === 404 && body.includes("ContainerNotFound")) {
    return null;
  }

  // If we got any other response, the storage account likely exists.
  // Public access is signaled by an Enumeration result, or by BlobNotFound
  // (which means a container is public but the blob path doesn't exist).
  const listing = body.includes("EnumerationResult") || body.includes("<Blobs>");
  const blobNotFound = body.includes("BlobNotFound");
  const isPublic = listing || blobNotFound;
  const sample: string[] = [];
  if (listing) {
    const re = /<Name>([\s\S]*?)<\/Name>/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(body)) !== null && sample.length < 5) {
      sample.push(m[1].trim());
    }
  }

  return {
    provider: "Azure Blob",
    name,
    url,
    exists: true,
    public: isPublic,
    listing,
    sample,
  };
}

async function probeGCP(name: string): Promise<CloudEnumResult["buckets"][number] | null> {
  const url = `https://storage.googleapis.com/${name}`;
  const res = await fetchWithTimeout(url);
  if (!res) return null;

  let body = "";
  try {
    body = await res.text();
  } catch {
    /* ignore */
  }

  // GCP returns 404 with NoSuchBucket when the bucket doesn't exist.
  if (res.status === 404 && body.includes("NoSuchBucket")) {
    return null;
  }
  // A plain 404 with no XML body is also "doesn't exist" for storage.googleapis.com.
  if (res.status === 404 && !body.includes("ListBucketResult")) {
    return null;
  }

  const listing = body.includes("<ListBucketResult");
  const sample = listing ? parseSampleKeys(body) : [];

  return {
    provider: "GCP Storage",
    name,
    url,
    exists: true,
    public: listing,
    listing,
    sample,
  };
}

async function probeDO(name: string): Promise<CloudEnumResult["buckets"][number] | null> {
  const url = `https://${name}.nyc3.digitaloceanspaces.com`;
  const res = await fetchWithTimeout(url);
  if (!res) return null;

  let body = "";
  try {
    body = await res.text();
  } catch {
    /* ignore */
  }

  // DO Spaces is S3-compatible: 404 NoSuchBucket => doesn't exist.
  if (res.status === 404 && (body.includes("NoSuchBucket") || body.includes("AllAccessDisabled"))) {
    return null;
  }
  if (res.status === 404 && !body.includes("ListBucketResult")) {
    return null;
  }

  const listing = body.includes("<ListBucketResult");
  const sample = listing ? parseSampleKeys(body) : [];

  return {
    provider: "DigitalOcean Spaces",
    name,
    url,
    exists: true,
    public: listing,
    listing,
    sample,
    region: "nyc3",
  };
}

async function probeAliyun(name: string): Promise<CloudEnumResult["buckets"][number] | null> {
  const url = `https://${name}.oss-cn-hangzhou.aliyuncs.com`;
  const res = await fetchWithTimeout(url);
  if (!res) return null;

  let body = "";
  try {
    body = await res.text();
  } catch {
    /* ignore */
  }

  // Aliyun returns 404 with NoSuchBucket when the bucket doesn't exist.
  if (res.status === 404 && (body.includes("NoSuchBucket") || body.includes("InvalidBucketName"))) {
    return null;
  }
  if (res.status === 404 && !body.includes("ListBucketResult")) {
    return null;
  }

  const listing = body.includes("<ListBucketResult");
  const sample = listing ? parseSampleKeys(body) : [];

  return {
    provider: "Aliyun OSS",
    name,
    url,
    exists: true,
    public: listing,
    listing,
    sample,
    region: "oss-cn-hangzhou",
  };
}

// ---- GitHub repo probes ----

async function probeGithubPage(name: string): Promise<CloudEnumResult["repos"][number] | null> {
  const url = `https://github.com/${name}`;
  const res = await fetchWithTimeout(url);
  if (!res) return null;
  // 200 => public repo/page exists. 404 => doesn't exist OR private repo.
  // Either way we can't tell, so we mark exists=false.
  if (res.status !== 200) return null;

  // Confirm we actually landed on a repo page and not GitHub's 404 SPA
  // (which sometimes returns 200 with a "not found" body). Look for repo markers.
  let body = "";
  try {
    body = await res.text();
  } catch {
    /* ignore */
  }
  if (body.includes('data-pjax="#js-repo-pjax-container"') || body.includes('<title>') && body.toLowerCase().includes(name.toLowerCase())) {
    return {
      provider: "GitHub",
      name,
      url,
      exists: true,
      private: false,
    };
  }
  // Soft-confirm: if 200 and no explicit "Page not found" / 404 text, accept it.
  if (!body.includes("Page not found") && !body.includes("404")) {
    return {
      provider: "GitHub",
      name,
      url,
      exists: true,
      private: false,
    };
  }
  return null;
}

async function probeGithubOrgRepos(
  apex: string,
  log: (msg: string) => void
): Promise<CloudEnumResult["repos"][number][]> {
  const url = `https://api.github.com/orgs/${apex}/repos`;
  const res = await fetchWithTimeout(url, {
    headers: { Accept: "application/vnd.github+json" },
  });
  if (!res || res.status !== 200) return [];

  let data: unknown;
  try {
    data = await res.json();
  } catch {
    return [];
  }
  if (!Array.isArray(data)) return [];

  const out: CloudEnumResult["repos"][number][] = [];
  for (const repo of data.slice(0, 3)) {
    const r = repo as { name?: string; full_name?: string; html_url?: string; private?: boolean };
    const name = r.full_name || `${apex}/${r.name}`;
    const repoUrl = r.html_url || `https://github.com/${apex}/${r.name}`;
    out.push({
      provider: "GitHub",
      name,
      url: repoUrl,
      exists: true,
      private: !!r.private,
    });
    log(`  [+] GitHub: ${name} ${r.private ? "PRIVATE" : "PUBLIC"}`);
  }
  return out;
}

// ---- Main entry point ----

export async function runCloudEnum(
  domain: string,
  log: (msg: string) => void
): Promise<CloudEnumResult> {
  const apex = apexOf(domain);
  const candidates = SUFFIXES.map((sfx) => `${apex}${sfx}`).filter(
    (n, i, arr) => n && arr.indexOf(n) === i
  );
  const total = candidates.length;

  log(`Cloud enum: apex="${apex}", ${total} candidates`);
  log(`Probing S3 / Azure / GCP / DO / Aliyun + GitHub for ${domain} ...`);

  const result: CloudEnumResult = { buckets: [], repos: [] };

  for (let i = 0; i < candidates.length; i++) {
    const name = candidates[i];
    log(`  probing candidate ${i + 1}/${total}: ${name}`);

    // ---- Storage buckets ----
    // AWS S3 — probe both global and regional endpoints.
    try {
      const s3a = await probeS3(name, `${name}.s3.amazonaws.com`);
      if (s3a) {
        result.buckets.push(s3a);
        log(
          `  [+] AWS S3: ${name} ${s3a.public ? "PUBLIC" : "exists"}${s3a.listing ? " + listing" : ""}`
        );
      }
    } catch {
      /* skip */
    }
    try {
      const s3b = await probeS3(name, `${name}.s3.us-east-1.amazonaws.com`, "us-east-1");
      if (s3b && !result.buckets.some((b) => b.provider === "AWS S3" && b.name === name)) {
        result.buckets.push(s3b);
        log(
          `  [+] AWS S3: ${name} ${s3b.public ? "PUBLIC" : "exists"}${s3b.listing ? " + listing" : ""}`
        );
      }
    } catch {
      /* skip */
    }

    // Azure Blob
    try {
      const az = await probeAzure(name);
      if (az) {
        result.buckets.push(az);
        log(
          `  [+] Azure Blob: ${name} ${az.public ? "PUBLIC" : "exists"}${az.listing ? " + listing" : ""}`
        );
      }
    } catch {
      /* skip */
    }

    // GCP Storage
    try {
      const gcp = await probeGCP(name);
      if (gcp) {
        result.buckets.push(gcp);
        log(
          `  [+] GCP Storage: ${name} ${gcp.public ? "PUBLIC" : "exists"}${gcp.listing ? " + listing" : ""}`
        );
      }
    } catch {
      /* skip */
    }

    // DigitalOcean Spaces
    try {
      const doSp = await probeDO(name);
      if (doSp) {
        result.buckets.push(doSp);
        log(
          `  [+] DigitalOcean Spaces: ${name} ${doSp.public ? "PUBLIC" : "exists"}${doSp.listing ? " + listing" : ""}`
        );
      }
    } catch {
      /* skip */
    }

    // Aliyun OSS
    try {
      const aliyun = await probeAliyun(name);
      if (aliyun) {
        result.buckets.push(aliyun);
        log(
          `  [+] Aliyun OSS: ${name} ${aliyun.public ? "PUBLIC" : "exists"}${aliyun.listing ? " + listing" : ""}`
        );
      }
    } catch {
      /* skip */
    }
  }

  // ---- GitHub repos ----
  log(`Probing GitHub repos for ${domain} / ${apex} ...`);

  // Probe the raw domain (e.g. github.com/example.com — rare but valid org names
  // can contain dots), the apex, and an "<apex>-org" handle.
  const githubHandles = [domain, apex, `${apex}-org`];
  const seenRepos = new Set<string>();
  for (const handle of githubHandles) {
    try {
      const repo = await probeGithubPage(handle);
      if (repo && !seenRepos.has(repo.url)) {
        seenRepos.add(repo.url);
        result.repos.push(repo);
        log(`  [+] GitHub: ${handle} ${repo.private ? "PRIVATE" : "PUBLIC"}`);
      }
    } catch {
      /* skip */
    }
  }

  // GitHub org API — list first 3 repos of the org if it exists.
  try {
    const orgRepos = await probeGithubOrgRepos(apex, log);
    for (const r of orgRepos) {
      if (!seenRepos.has(r.url)) {
        seenRepos.add(r.url);
        result.repos.push(r);
      }
    }
  } catch {
    /* skip */
  }

  log(
    `Cloud enum complete: ${result.buckets.length} bucket(s), ${result.repos.length} repo(s) found.`
  );
  return result;
}
