#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { authFromEnv } from "../auth/fromEnv.js";
import { AuthError } from "../auth/context.js";
import { loadConfigOrExit } from "./loadConfigOrExit.js";
import { createLogger } from "../logger.js";
import { buildServer, SERVER_NAME, SERVER_VERSION } from "../server.js";

/**
 * LOCAL entrypoint. Runs as a subprocess of Claude Desktop / Claude Code and
 * speaks MCP over stdio. Credentials come from the environment (single tenant).
 */
async function main(): Promise<void> {
  const config = loadConfigOrExit();
  const logger = createLogger(config.logLevel);

  let auth;
  try {
    auth = authFromEnv();
  } catch (err) {
    if (err instanceof AuthError) {
      logger.error(err.message);
      process.exit(1);
    }
    throw err;
  }

  const server = buildServer({ auth, config, logger });
  const transport = new StdioServerTransport();
  await server.connect(transport);

  logger.info("netbird mcp server ready (stdio)", {
    name: SERVER_NAME,
    version: SERVER_VERSION,
    baseUrl: auth.baseUrl,
    destructiveEnabled: config.enableDestructive,
  });
}

main().catch((err) => {
  process.stderr.write(`fatal: ${(err as Error).stack ?? err}\n`);
  process.exit(1);
});
