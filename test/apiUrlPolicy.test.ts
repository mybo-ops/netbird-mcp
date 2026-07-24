import { describe, it, expect } from "vitest";
import { checkApiUrl, hostOf } from "../src/netbird/apiUrlPolicy.js";

const CLOUD = "api.netbird.io";

describe("hostOf", () => {
  it("extracts the host from a full http(s) URL", () => {
    expect(hostOf("https://api.netbird.io")).toBe("api.netbird.io");
    expect(hostOf("http://nb.corp.example.com:8443/api")).toBe("nb.corp.example.com");
  });

  it("accepts a bare host without a scheme", () => {
    expect(hostOf("nb.corp.example.com")).toBe("nb.corp.example.com");
    expect(hostOf("nb.corp.example.com:8443")).toBe("nb.corp.example.com");
  });

  it("lowercases the host and strips IPv6 brackets", () => {
    expect(hostOf("https://API.NetBird.IO")).toBe("api.netbird.io");
    expect(hostOf("http://[::1]:8080")).toBe("::1");
  });

  it("returns null for empty or unparseable input", () => {
    expect(hostOf("")).toBeNull();
    expect(hostOf("   ")).toBeNull();
    expect(hostOf("http://")).toBeNull();
  });
});

describe("checkApiUrl — allowlist membership", () => {
  it("allows the canonical public host by default", () => {
    expect(checkApiUrl("https://api.netbird.io", [CLOUD])).toEqual({ allowed: true });
  });

  it("allows an operator-configured self-hosted host", () => {
    const allowed = [CLOUD, "nb.corp.example.com"];
    expect(checkApiUrl("https://nb.corp.example.com/api", allowed)).toEqual({ allowed: true });
    expect(checkApiUrl("https://nb.corp.example.com:8443", allowed)).toEqual({ allowed: true });
  });

  it("denies a host that is not on the allowlist", () => {
    const result = checkApiUrl("https://evil.example.com", [CLOUD]);
    expect(result.allowed).toBe(false);
    if (!result.allowed) expect(result.reason).toMatch(/not on the NetBird API allowlist/i);
  });

  it("matches the host case-insensitively", () => {
    expect(checkApiUrl("https://API.NETBIRD.IO", [CLOUD])).toEqual({ allowed: true });
  });
});

describe("checkApiUrl — scheme", () => {
  it("rejects a non-http(s) scheme", () => {
    for (const url of ["ftp://api.netbird.io", "file:///etc/passwd", "gopher://api.netbird.io"]) {
      const result = checkApiUrl(url, [CLOUD]);
      expect(result.allowed).toBe(false);
      if (!result.allowed) expect(result.reason).toMatch(/http\(s\)/i);
    }
  });

  it("rejects an unparseable or scheme-less value", () => {
    for (const url of ["", "api.netbird.io", "not a url"]) {
      expect(checkApiUrl(url, [CLOUD]).allowed).toBe(false);
    }
  });
});

describe("checkApiUrl — private/loopback/link-local/metadata floor", () => {
  // Self-hosting is enabled (a non-default allowlist), yet none of these
  // request-supplied addresses are on it, so all must be denied.
  const selfHosted = [CLOUD, "nb.corp.example.com"];

  it("denies loopback (127.0.0.0/8 and ::1)", () => {
    expect(checkApiUrl("http://127.0.0.1", selfHosted).allowed).toBe(false);
    expect(checkApiUrl("http://127.9.9.9:9000", selfHosted).allowed).toBe(false);
    expect(checkApiUrl("https://[::1]", selfHosted).allowed).toBe(false);
  });

  it("denies RFC1918 private ranges", () => {
    for (const ip of ["10.0.0.5", "172.16.4.4", "172.31.255.1", "192.168.1.1"]) {
      expect(checkApiUrl(`http://${ip}`, selfHosted).allowed).toBe(false);
    }
  });

  it("allows a public RFC1918-adjacent address that is not actually private", () => {
    // 172.15.x and 172.32.x fall OUTSIDE 172.16.0.0/12 — not private.
    expect(checkApiUrl("http://172.15.0.1", [...selfHosted, "172.15.0.1"]).allowed).toBe(true);
  });

  it("denies link-local and the cloud metadata address (169.254.0.0/16)", () => {
    expect(checkApiUrl("http://169.254.169.254", selfHosted).allowed).toBe(false);
    expect(checkApiUrl("http://169.254.0.1/latest/meta-data", selfHosted).allowed).toBe(false);
  });

  it("denies IPv6 unique-local (fc00::/7)", () => {
    expect(checkApiUrl("https://[fc00::1]", selfHosted).allowed).toBe(false);
    expect(checkApiUrl("https://[fd12:3456::1]", selfHosted).allowed).toBe(false);
  });

  it("reports a private-address reason distinct from the generic allowlist miss", () => {
    const result = checkApiUrl("http://169.254.169.254", selfHosted);
    expect(result.allowed).toBe(false);
    if (!result.allowed) expect(result.reason).toMatch(/private|loopback|link-local|metadata/i);
  });

  it("honors an explicit operator opt-in that overrides the floor", () => {
    // An operator who deliberately points the server at a loopback API (local
    // testing / same-host self-host) puts that host on the allowlist; explicit
    // membership wins over the floor.
    expect(checkApiUrl("http://127.0.0.1:8080", ["127.0.0.1"]).allowed).toBe(true);
  });
});
