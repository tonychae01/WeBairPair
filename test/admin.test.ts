import { describe, expect, it } from "vitest";
import {
  createAdminSessionToken,
  isAllowedAdminOrigin,
  passwordsMatch,
  validateAdminSessionToken,
} from "../src/admin";

describe("admin authentication", () => {
  it("requires browser same-origin metadata when Origin is missing or opaque", () => {
    const env = { APP_URL: "https://webairpair.com" };
    for (const origin of [undefined, "null"]) {
      for (const site of [undefined, "cross-site", "same-site", "none", "same-origin"]) {
        const headers = new Headers();
        if (origin) headers.set("origin", origin);
        if (site) headers.set("sec-fetch-site", site);
        const request = new Request("https://webairpair.com/admin/login", { method: "POST", headers });
        expect(isAllowedAdminOrigin(request, env)).toBe(site === "same-origin");
      }
    }
    expect(isAllowedAdminOrigin(new Request("https://webairpair.com/admin/login", {
      method: "POST",
      headers: { origin: "https://evil.example", "sec-fetch-site": "same-origin" },
    }), env)).toBe(false);
  });
  it("accepts a valid signed session before expiry", async () => {
    const now = Date.UTC(2026, 8, 20, 12);
    const token = await createAdminSessionToken("test-session-secret", now);
    expect(await validateAdminSessionToken(token, "test-session-secret", now + 1_000)).toBe(true);
  });

  it("rejects tampered, expired, and incorrectly signed sessions", async () => {
    const now = Date.UTC(2026, 8, 20, 12);
    const token = await createAdminSessionToken("test-session-secret", now);
    const finalCharacter = token.at(-1) === "0" ? "1" : "0";
    expect(await validateAdminSessionToken(`${token.slice(0, -1)}${finalCharacter}`, "test-session-secret", now)).toBe(false);
    expect(await validateAdminSessionToken(token, "different-secret", now)).toBe(false);
    expect(await validateAdminSessionToken(token, "test-session-secret", now + 9 * 60 * 60 * 1_000)).toBe(false);
  });

  it("compares password hashes without accepting near matches", async () => {
    expect(await passwordsMatch("correct horse battery staple", "correct horse battery staple")).toBe(true);
    expect(await passwordsMatch("correct horse battery stap1e", "correct horse battery staple")).toBe(false);
  });

  it("allows loopback origins only for loopback requests and the canonical origin in production", () => {
    const request = (url: string, origin: string) => new Request(url, {
      method: "POST",
      headers: { origin },
    });
    const env = { APP_URL: "https://webairpair.com" };

    expect(isAllowedAdminOrigin(request("http://localhost:8787/admin/login", "http://localhost:8788"), env)).toBe(true);
    expect(isAllowedAdminOrigin(request("http://127.0.0.1:8787/admin/login", "http://127.0.0.1:8787"), env)).toBe(true);
    expect(isAllowedAdminOrigin(request("http://webairpair.com/admin/login", "http://webairpair.com"), env)).toBe(true);
    expect(isAllowedAdminOrigin(request("http://localhost:8787/admin/login", "https://evil.example"), env)).toBe(false);
    expect(isAllowedAdminOrigin(request("https://webairpair.com/admin/login", "https://webairpair.com"), env)).toBe(true);
    expect(isAllowedAdminOrigin(request("https://webairpair.com/admin/login", "http://localhost:8787"), env)).toBe(false);
  });
});
