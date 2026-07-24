import { isIP } from "node:net";

/**
 * The single home for the NetBird API base-URL trust policy. Any base URL the
 * server is handed is meant to be decided here, so the rules live in exactly one
 * place: the operator's configured NETBIRD_API_URL is checked at startup today,
 * and the untrusted request-supplied URLs (the per-request URL header and the
 * browser-submitted login field) adopt this same check in follow-up work.
 *
 * The policy is an explicit host allowlist. A URL is permitted only when its
 * host is one the operator has vouched for (the canonical public API host by
 * default, plus anything in NETBIRD_ALLOWED_API_HOSTS and the configured
 * NETBIRD_API_URL). Everything else is refused before any outbound request.
 *
 * Beneath the allowlist sits a defence-in-depth floor: a host that is NOT on the
 * allowlist and is a private / loopback / link-local / cloud-metadata IP literal
 * is called out with a specific reason. Because request-supplied URLs are never
 * on the allowlist, this is what turns an SSRF attempt (`http://169.254.169.254`,
 * `http://10.0.0.1`) into an explicit refusal. Explicit allowlist membership
 * wins over the floor: an operator who deliberately points the server at a
 * loopback API for local testing opts in by listing that host.
 *
 * NOTE: this is a synchronous check on the URL's literal host. It does not
 * resolve DNS, so a hostname that resolves to a private address is judged only
 * by the allowlist, not the floor. Connect-time IP pinning is out of scope here.
 */

export type ApiUrlDecision = { allowed: true } | { allowed: false; reason: string };

/**
 * Extract a normalized host (lowercased, IPv6 brackets stripped) from a full
 * URL or a bare `host[:port]` string. Returns null when nothing parseable is
 * present, so callers can drop junk allowlist entries cleanly.
 */
export function hostOf(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) return null;
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  const parsed = tryUrl(withScheme);
  if (!parsed || !parsed.hostname) return null;
  return normalizeHost(parsed.hostname);
}

export function checkApiUrl(url: string, allowedHosts: readonly string[]): ApiUrlDecision {
  const parsed = tryUrl(url.trim());
  if (!parsed || (parsed.protocol !== "http:" && parsed.protocol !== "https:")) {
    return { allowed: false, reason: "must be a valid http(s) URL" };
  }
  const host = normalizeHost(parsed.hostname);
  if (!host) {
    return { allowed: false, reason: "must be a valid http(s) URL" };
  }
  // Explicit operator opt-in wins over the floor below.
  if (allowedHosts.includes(host)) {
    return { allowed: true };
  }
  if (isDeniedIpLiteral(host)) {
    return {
      allowed: false,
      reason: `"${host}" is a private, loopback, link-local, or metadata address and is not on the NetBird API allowlist`,
    };
  }
  return { allowed: false, reason: `host "${host}" is not on the NetBird API allowlist` };
}

function tryUrl(value: string): URL | null {
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

function normalizeHost(hostname: string): string {
  const h = hostname.toLowerCase();
  return h.startsWith("[") && h.endsWith("]") ? h.slice(1, -1) : h;
}

/** True when the host is an IP literal inside a never-routable-to range. */
function isDeniedIpLiteral(host: string): boolean {
  const version = isIP(host);
  if (version === 4) return isDeniedIpv4(host);
  if (version === 6) return isDeniedIpv6(host);
  return false;
}

function isDeniedIpv4(ip: string): boolean {
  const octets = ip.split(".").map((o) => Number.parseInt(o, 10));
  if (octets.length !== 4 || octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) {
    return true; // isIP said v4 but it doesn't parse cleanly — fail closed
  }
  const [a, b] = octets;
  if (a === 0) return true; // 0.0.0.0/8 "this network"
  if (a === 127) return true; // loopback 127.0.0.0/8
  if (a === 10) return true; // RFC1918 10.0.0.0/8
  if (a === 172 && b >= 16 && b <= 31) return true; // RFC1918 172.16.0.0/12
  if (a === 192 && b === 168) return true; // RFC1918 192.168.0.0/16
  if (a === 169 && b === 254) return true; // link-local + cloud metadata 169.254.0.0/16
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64.0.0/10
  return false;
}

function isDeniedIpv6(ip: string): boolean {
  const addr = ip.toLowerCase();
  if (addr === "::1" || addr === "::") return true; // loopback, unspecified
  if (/^fe[89ab]/.test(addr)) return true; // link-local fe80::/10
  if (/^f[cd]/.test(addr)) return true; // unique-local fc00::/7
  const mapped = addr.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (mapped) return isDeniedIpv4(mapped[1]); // IPv4-mapped ::ffff:a.b.c.d
  return false;
}
