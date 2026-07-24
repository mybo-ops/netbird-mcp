import { describe, it, expect, afterEach } from "vitest";
import express from "express";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { loginRateLimiter, LOGIN_RATE_LIMIT_MAX } from "../src/oauth/loginRateLimit.js";

let server: Server | undefined;

afterEach(async () => {
  if (server) {
    await new Promise((r) => server!.close(r));
    server = undefined;
  }
});

/** Mount the real limiter on a throwaway route (isolated store) and return its base URL. */
async function startApp(): Promise<string> {
  const app = express();
  app.post("/login", loginRateLimiter(), (_req, res) => {
    res.status(200).send("ok");
  });
  return new Promise((resolve) => {
    server = app.listen(0, "127.0.0.1", () => {
      resolve(`http://127.0.0.1:${(server!.address() as AddressInfo).port}`);
    });
  });
}

describe("loginRateLimiter", () => {
  it("allows requests up to the configured limit, then throttles with 429", async () => {
    const base = await startApp();
    const post = () => fetch(`${base}/login`, { method: "POST" });

    // Every request up to the limit is allowed...
    const allowed: number[] = [];
    for (let i = 0; i < LOGIN_RATE_LIMIT_MAX; i++) allowed.push((await post()).status);
    expect(allowed.every((s) => s === 200)).toBe(true);

    // ...and the next one over the limit is throttled.
    const throttled = await post();
    expect(throttled.status).toBe(429);
    expect(await throttled.text()).toMatch(/too many/i);
  });
});
