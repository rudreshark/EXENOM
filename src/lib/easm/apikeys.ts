/**
 * Threat-Intelligence API Keys (multi-key rotation)
 *
 * Every source now accepts MULTIPLE keys so we can round-robin /
 * fallback when one key is rate-limited, expired, or out of credits.
 *
 * Keys can be overridden via environment variables (comma-separated
 * for multi-key sources):
 *   EASM_SHODAN_KEYS        (comma-separated)
 *   EASM_C99_KEYS           (comma-separated)
 *   EASM_VIRUSTOTAL_KEYS    (comma-separated)
 *   EASM_SECURITYTRAILS_KEYS (comma-separated)
 *
 * Legacy single-key env vars still work as a fallback:
 *   EASM_SHODAN_KEY, EASM_VIRUSTOTAL_KEY, EASM_SECURITYTRAILS_KEY
 */
export interface ApiKeys {
  shodan: string[];
  c99: string[];
  virustotal: string[];
  securitytrails: string[];
}

function envList(names: string[], fallback: string[]): string[] {
  for (const name of names) {
    const v = process.env[name];
    if (v) {
      return v
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
    }
  }
  return fallback;
}

export const API_KEYS: ApiKeys = {
  // Shodan — multiple keys supported. The DNS domain endpoint needs
  // membership; rotating keys lets us try several accounts.
  shodan: envList(["EASM_SHODAN_KEYS", "EASM_SHODAN_KEY"], [
    "Y0V0hXiKp4g0BBkhqfsVZNE06zEpSsXe",
    "4f41243847da693a4f356c0486114bc6",
  ]),
  // c99 — already multi-key
  c99: envList(["EASM_C99_KEYS"], [
    "21a270d5f59c9b05813a72bb41707266",
    "ea8f243d9885cf8ce9876a580224fd3c",
    "5bc6ed268ab6488270e496d3183a1a27",
  ]),
  // VirusTotal — multiple keys for higher rate-limit headroom
  virustotal: envList(["EASM_VIRUSTOTAL_KEYS", "EASM_VIRUSTOTAL_KEY"], [
    "bc8ea849bb1e9f568e051c2381a1e801fdaf205edf1d86be28ae72361830fa4c",
    "dd5f0eee2e4a99b71a939bded450b246",
  ]),
  // SecurityTrails
  securitytrails: envList(["EASM_SECURITYTRAILS_KEYS", "EASM_SECURITYTRAILS_KEY"], [
    "d9a05c3fd9a514497713c54b4455d0b0",
  ]),
};

export const INTEL_SOURCE_NAMES = ["shodan", "c99", "virustotal", "securitytrails"] as const;

/**
 * Round-robin key picker — returns the next key in the rotation for a
 * given source. Stateful across calls within a single scan run.
 */
const keyIndex: Record<keyof ApiKeys, number> = {
  shodan: 0,
  c99: 0,
  virustotal: 0,
  securitytrails: 0,
};

export function nextKey(source: keyof ApiKeys): string | null {
  const keys = API_KEYS[source];
  if (!keys || keys.length === 0) return null;
  const k = keys[keyIndex[source] % keys.length];
  keyIndex[source] = (keyIndex[source] + 1) % keys.length;
  return k;
}

/**
 * Try each key for a source until the predicate returns true.
 * Returns the first successful result, or null if all keys fail.
 */
export async function tryKeys<T>(
  source: keyof ApiKeys,
  fn: (key: string) => Promise<T | null>,
  isValid: (r: T | null) => boolean
): Promise<T | null> {
  const keys = API_KEYS[source];
  for (const key of keys) {
    try {
      const r = await fn(key);
      if (isValid(r)) return r;
    } catch {
      /* try next key */
    }
  }
  return null;
}
