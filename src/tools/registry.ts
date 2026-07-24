import { z } from "zod";
import type { McpServer, ToolCallback } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ZodRawShapeCompat, ShapeOutput } from "@modelcontextprotocol/sdk/server/zod-compat.js";
import type { CallToolResult, ToolAnnotations } from "@modelcontextprotocol/sdk/types.js";
import type { NetBirdClient } from "../netbird/client.js";
import { NetBirdApiError } from "../netbird/client.js";
import type { ServerConfig } from "../config.js";
import type { Logger } from "../logger.js";

export interface ToolDeps {
  client: NetBirdClient;
  config: ServerConfig;
  logger: Logger;
}

/**
 * The registration interface is the only path by which tools reach the MCP
 * server. It owns the draft-and-confirm guardrail (registerMutation,
 * registerDelete), the destructive-tools gate (registerDelete), and the
 * NetBird-error-to-tool-error translation (all three) — so a new tool gets
 * these for free just by being written as a manifest, and cannot skip them.
 */

/**
 * Input shape a write manifest may declare: domain fields only. The guardrail's
 * `confirm` field is reserved by the registry, so a manifest declaring it is
 * rejected at compile time; the runtime guard in withConfirmField backs this up
 * for untyped callers.
 */
type DomainShape = ZodRawShapeCompat & { confirm?: never };

interface ManifestBase<Args extends ZodRawShapeCompat> {
  name: string;
  title: string;
  description: string;
  inputSchema?: Args;
}

export interface ReadManifest<Args extends ZodRawShapeCompat = Record<string, never>>
  extends ManifestBase<Args> {
  path: (args: ShapeOutput<Args>) => string;
  /** Query string params for the GET request. */
  query?: (args: ShapeOutput<Args>) => Record<string, string | number | boolean | undefined>;
  /** Post-process the raw response before rendering it, e.g. a client-side limit. */
  transformResponse?: (data: unknown, args: ShapeOutput<Args>) => unknown;
}

export interface MutationManifest<Args extends DomainShape> extends ManifestBase<Args> {
  inputSchema: Args;
  method: "POST" | "PUT";
  path: (args: ShapeOutput<Args>) => string;
  /** The draft-and-confirm preview line, e.g. "Would create a group." */
  previewAction: (args: ShapeOutput<Args>) => string;
  /**
   * Build the request body from parsed args. Fields left `undefined` are
   * dropped before the body is shown in the preview or sent to NetBird, so
   * hooks can pass every optional field through unconditionally.
   */
  buildBody: (args: ShapeOutput<Args>) => Record<string, unknown>;
}

export interface DeleteManifest<Args extends DomainShape> extends ManifestBase<Args> {
  inputSchema: Args;
  path: (args: ShapeOutput<Args>) => string;
  /** Domain label used in generated preview/result text, e.g. "peer". */
  label: string;
  /** Name of the id field in inputSchema, e.g. "peer_id". */
  idField: string;
}

/** Render a successful result as pretty JSON text content. */
function ok(data: unknown): CallToolResult {
  return {
    content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
  };
}

/** Render an error result (isError so the model can react). */
function fail(message: string): CallToolResult {
  return { content: [{ type: "text", text: message }], isError: true };
}

/**
 * A draft-and-confirm preview: when a mutating tool is called with confirm=false
 * we describe exactly what would happen instead of doing it. This is the
 * guardrail the product promises on every write.
 */
function preview(action: string, request: unknown): CallToolResult {
  return ok({
    status: "preview",
    message:
      `This is a preview — nothing was changed. ${action} ` +
      `Re-run with "confirm": true to apply.`,
    would_send: request,
  });
}

/** Wrap a tool handler so NetBird errors become clean tool errors, not crashes. */
async function guard(logger: Logger, fn: () => Promise<CallToolResult>): Promise<CallToolResult> {
  try {
    return await fn();
  } catch (err) {
    if (err instanceof NetBirdApiError) {
      return fail(
        `NetBird API error (HTTP ${err.status}): ${err.message}\n` +
          (err.body ? JSON.stringify(err.body, null, 2) : ""),
      );
    }
    // Unexpected (non-API) failure: the caller gets a clean message, the
    // operator gets the details — never swallow the context.
    const error = err as Error;
    logger.error("unexpected tool error", { message: error.message, stack: error.stack });
    return fail(`Unexpected error: ${error.message}`);
  }
}

/** Drop fields whose value is `undefined`, without mutating the input. */
function stripUndefined(body: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(body).filter(([, v]) => v !== undefined));
}

function isConfirmed(args: ShapeOutput<ZodRawShapeCompat>): boolean {
  return (args as Record<string, unknown>).confirm === true;
}

/** The single field name the draft-and-confirm guardrail owns. */
const CONFIRM_FIELD = "confirm";

/**
 * The guardrail field a mutation advertises: optional, because a mutation
 * previews when it is omitted and applies when it is true.
 */
const MUTATION_CONFIRM = z.boolean().optional().describe("Set true to apply the change.");

/**
 * The guardrail field a delete advertises: required, so a delete cannot be
 * issued without explicitly opting in.
 */
const DELETE_CONFIRM = z.boolean().describe("Must be true to delete.");

/**
 * Return a new input shape with the guardrail's `confirm` field injected, so
 * every write tool advertises confirm without its manifest declaring one. The
 * manifest's own schema is never mutated. Throws if the manifest already
 * declares `confirm` — a manifest may only declare domain fields, so the
 * guardrail field can never silently collide with one.
 */
function withConfirmField<Args extends DomainShape>(
  inputSchema: Args,
  confirmSchema: z.ZodTypeAny,
): Args & { confirm: z.ZodTypeAny } {
  if (Object.prototype.hasOwnProperty.call(inputSchema, CONFIRM_FIELD)) {
    throw new Error(
      `Tool manifest declares its own "${CONFIRM_FIELD}" field; the registry injects ` +
        "the draft-and-confirm guardrail, so manifests must declare only domain fields.",
    );
  }
  return { ...inputSchema, confirm: confirmSchema };
}

/**
 * Everything the shared primitive needs to register one tool: the advertised
 * metadata/schema and a plain handler. The handler returns the tool result
 * directly — the primitive owns the guard wrap, so handlers stay guard-free.
 */
interface RegisterSpec<Args extends ZodRawShapeCompat> {
  name: string;
  title: string;
  description: string;
  inputSchema: Args;
  annotations: ToolAnnotations;
  handle: (args: ShapeOutput<Args>) => Promise<CallToolResult>;
}

/**
 * The single primitive every public register* function funnels through. It owns
 * the `guard` wrap (NetBird-error-to-tool-error translation) and the one
 * boundary cast the SDK's generic callback type forces. Keeping both here means
 * the public builders below are cast-free config assemblers, and the unsafe
 * `as unknown as ToolCallback` lives in exactly one place.
 */
function register<Args extends ZodRawShapeCompat>(
  server: McpServer,
  deps: ToolDeps,
  spec: RegisterSpec<Args>,
): void {
  server.registerTool(
    spec.name,
    {
      title: spec.title,
      description: spec.description,
      inputSchema: spec.inputSchema,
      annotations: spec.annotations,
    },
    (async (args: ShapeOutput<Args>) =>
      guard(deps.logger, () => spec.handle(args))) as unknown as ToolCallback<Args>,
  );
}

/** Register a read-only tool: a straight GET, optionally with query params or a response transform. */
export function registerRead<Args extends ZodRawShapeCompat = Record<string, never>>(
  server: McpServer,
  deps: ToolDeps,
  manifest: ReadManifest<Args>,
): void {
  register<Args>(server, deps, {
    name: manifest.name,
    title: manifest.title,
    description: manifest.description,
    inputSchema: manifest.inputSchema ?? ({} as Args),
    annotations: { readOnlyHint: true },
    handle: async (args) => {
      const data = await deps.client.get(manifest.path(args), manifest.query?.(args));
      return ok(manifest.transformResponse ? manifest.transformResponse(data, args) : data);
    },
  });
}

/**
 * Register a mutating (create/update) tool. Owns the whole guardrail: no
 * confirm means a preview and zero API calls; confirm sends the body — with
 * undefined fields stripped — via the declared method and path.
 */
export function registerMutation<Args extends DomainShape>(
  server: McpServer,
  deps: ToolDeps,
  manifest: MutationManifest<Args>,
): void {
  register(server, deps, {
    name: manifest.name,
    title: manifest.title,
    description: manifest.description,
    inputSchema: withConfirmField(manifest.inputSchema, MUTATION_CONFIRM),
    annotations: { readOnlyHint: false, destructiveHint: false },
    handle: async (args) => {
      const body = stripUndefined(manifest.buildBody(args));
      if (!isConfirmed(args)) return preview(manifest.previewAction(args), body);
      const path = manifest.path(args);
      const response =
        manifest.method === "POST"
          ? await deps.client.post(path, body)
          : await deps.client.put(path, body);
      return ok(response);
    },
  });
}

/**
 * Register a destructive delete tool. Registers nothing when destructive
 * operations are disabled in server configuration; when enabled, still
 * requires draft-and-confirm — enabling the feature never bypasses the guardrail.
 */
export function registerDelete<Args extends DomainShape>(
  server: McpServer,
  deps: ToolDeps,
  manifest: DeleteManifest<Args>,
): void {
  // Build the advertised schema first: the collision guard is a manifest-
  // correctness check, so it must fire even in read-only deployments where the
  // tool is never registered.
  const inputSchema = withConfirmField(manifest.inputSchema, DELETE_CONFIRM);
  if (!deps.config.enableDestructive) return;

  register(server, deps, {
    name: manifest.name,
    title: manifest.title,
    description: manifest.description,
    inputSchema,
    annotations: { readOnlyHint: false, destructiveHint: true },
    handle: async (args) => {
      const idValue = (args as Record<string, unknown>)[manifest.idField];
      if (!isConfirmed(args)) {
        return preview(`Would DELETE ${manifest.label} ${idValue}.`, {
          [manifest.idField]: idValue,
        });
      }
      await deps.client.delete(manifest.path(args));
      return ok({ status: "deleted", [manifest.idField]: idValue });
    },
  });
}
