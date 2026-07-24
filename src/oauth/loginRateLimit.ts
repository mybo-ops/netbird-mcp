import { rateLimit, type RateLimitRequestHandler } from "express-rate-limit";

/**
 * Rate limiting for the interactive login route (POST /oauth/netbird-login).
 * The SDK's mcpAuthRouter throttles its own /authorize, /token, and /register
 * endpoints; this app-added route needs the same protection so an anonymous
 * caller can't hammer the login form (each submission triggers an outbound PAT
 * verification). Defaults match the SDK's /authorize limiter.
 */

/** 15-minute sliding window, matching the SDK's authorization endpoint. */
export const LOGIN_RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
/** Requests per window per client IP, matching the SDK's authorization endpoint. */
export const LOGIN_RATE_LIMIT_MAX = 100;

/** Build the login rate-limit middleware. Keys per client IP, like the SDK's routes. */
export function loginRateLimiter(): RateLimitRequestHandler {
  return rateLimit({
    windowMs: LOGIN_RATE_LIMIT_WINDOW_MS,
    limit: LOGIN_RATE_LIMIT_MAX,
    standardHeaders: "draft-7",
    legacyHeaders: false,
    message: "Too many login attempts. Please wait a few minutes and try again.",
  });
}
