import { loadServerConfig, type ServerConfig } from "../config.js";

/**
 * Load config for an entrypoint, or fail fast. loadServerConfig throws on an
 * unusable NETBIRD_API_URL, and no logger exists this early in boot, so surface
 * the reason as a clean one-line fatal on stderr and refuse to start. Shared by
 * both entrypoints so the boot-failure behaviour has one implementation.
 */
export function loadConfigOrExit(): ServerConfig {
  try {
    return loadServerConfig();
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`fatal: ${message}\n`);
    process.exit(1);
  }
}
