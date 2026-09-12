// Server-only integration boundary between the evidence upload route and the
// blockchain anchor lifecycle.
//
// RELIABILITY CONTRACT:
//   Anchoring is a SECONDARY integrity operation. Evidence creation must never
//   fail because the blockchain (or an anchor row) is unavailable — but the
//   reverse must also hold: the intent to anchor must not be silently lost.
//
//   The original design fired the orchestrator as true fire-and-forget work
//   AFTER the 201 response. That is NOT reliable in this deployment model:
//     * serverless runtimes tear down the execution context (and with it any
//       in-flight promise/timer) the moment the handler returns a Response, so
//       background work is not guaranteed to run, and
//     * the orchestrator builds its DB client from request cookies; after the
//       response the request scope is gone, so a detached task has no session
//       to authorize with and would raise not_authenticated.
//   Consequently this module NEVER fires work after a response and NEVER
//   touches Ethereum itself. Instead:
//     * the upload route creates/ensures the PENDING anchor row SYNCHRONOUSLY,
//       before the 201 (a plain DB-only RPC; fast, durable once it returns),
//     * on-chain submission is performed by a separate, retriable trigger
//       (POST .../anchor -> anchorDocumentVersion) that runs inside a fresh
//       request with its own server session, and
//     * the unique (document_version_id) constraint + orchestrator state
//       machine keep the two paths duplicate-safe (a retry reuses a pending
//       row, resets a failed row, and the on-chain AlreadyAnchored guard is
//       the second line of defense).
//
// The orchestrator/ethers runtime is never imported at module load (only
// erased `import type` references), so node:test imports this module directly
// and exercises every helper with stubs.

import type {
  AnchorOrchestrationErrorKind,
  AnchorOutcome,
} from "./orchestrator";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// What ensurePendingAnchor() reports back to the caller.
export type PendingAnchorResult =
  | { status: "pending"; anchorId: string }
  | { status: "already_anchored" };

// Minimal structural type for the server Supabase client: only the rpc() call
// this module makes. Keeping it structural means node:test can inject a stub
// without loading the Supabase/Next runtime. Supabase's rpc actually returns a
// thenable (PostgrestFilterBuilder), not a native Promise, hence PromiseLike.
export interface AnchorRpcClient {
  rpc(
    fn: string,
    params: Record<string, string>,
  ): PromiseLike<{ data: unknown; error: { message: string } | null }>;
}

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// ---------------------------------------------------------------------------
// Upload boundary helpers
// ---------------------------------------------------------------------------

/**
 * Extract the ACTUAL persisted document_version id from the create_evidence
 * jsonb response ({ evidence, document_version }). The RPC inserted the
 * version, so its row (with id) is the authoritative source — never a value
 * derived from the request. Returns null when the version is absent/malformed
 * (i.e. evidence creation did not commit a version; no anchor should run).
 */
export function persistedVersionIdFromResponse(data: unknown): string | null {
  if (typeof data !== "object" || data === null) return null;
  const record = data as Record<string, unknown>;
  const version = record.document_version;
  if (typeof version !== "object" || version === null) return null;
  const id = (version as Record<string, unknown>).id;
  if (typeof id !== "string" || !UUID_PATTERN.test(id)) return null;
  return id;
}

/**
 * Create/ensure the PENDING blockchain anchor row for a document version.
 * Runs synchronously inside the upload request, BEFORE the 201 is returned,
 * so the durable fact "this version is to be anchored" is committed before
 * the client hears a success. It is a plain DB-only SECURITY DEFINER RPC —
 * Ethereum is never contacted here, and no work is deferred to after the
 * response. The RPC re-derives the actor from the session and re-checks
 * profile + case lead/investigator authorization.
 *
 * Returns:
 *   { status: "pending", anchorId }   — a fresh or reused pending row (the id
 *                                       comes from the RPC response, i.e. the
 *                                       committed row).
 *   { status: "already_anchored" }    — the version is already anchored
 *                                       (defensive; impossible for a freshly
 *                                       created version).
 *   null                              — the row could NOT be created (DB/auth
 *                                       failure). The caller MUST still treat
 *                                       evidence creation as successful: the
 *                                       anchor simply does not exist yet and a
 *                                       later explicit trigger will create it
 *                                       on demand. Never throws.
 */
export async function requestPendingAnchor(
  client: AnchorRpcClient,
  documentVersionId: string,
): Promise<PendingAnchorResult | null> {
  if (!UUID_PATTERN.test(documentVersionId)) return null;

  const { data, error } = await client.rpc("create_blockchain_anchor", {
    p_document_version_id: documentVersionId,
  });

  if (error) {
    // 'already_anchored' is the one handled outcome; every other failure just
    // means "no pending row yet" — evidence stays valid.
    if (error.message.includes("already_anchored")) {
      return { status: "already_anchored" };
    }
    logSafe("error", "evidence_anchor_request_failed", { documentVersionId });
    return null;
  }

  const anchor = parseAnchorRow(data);
  if (!anchor) {
    logSafe("error", "evidence_anchor_request_unexpected", {
      documentVersionId,
    });
    return null;
  }
  if (anchor.status === "anchored") {
    // The RPC raises 'already_anchored' rather than returning an anchored
    // row; defensive, mirrors the orchestrator's parseCreateAnchorResult.
    return { status: "already_anchored" };
  }
  if (anchor.status !== "pending") {
    logSafe("error", "evidence_anchor_request_unexpected", {
      documentVersionId,
    });
    return null;
  }
  return { status: "pending", anchorId: anchor.id };
}

/** Extract a validated {id, status} row from the RPC's {anchor: {...}} jsonb. */
function parseAnchorRow(data: unknown): { id: string; status: string } | null {
  if (typeof data !== "object" || data === null) return null;
  const anchor = (data as Record<string, unknown>).anchor;
  if (typeof anchor !== "object" || anchor === null) return null;
  const row = anchor as Record<string, unknown>;
  const id = row.id;
  const status = row.status;
  if (typeof id !== "string" || !UUID_PATTERN.test(id)) return null;
  if (typeof status !== "string") return null;
  return { id, status };
}

// ---------------------------------------------------------------------------
// Trigger boundary helpers (pure — used by the POST .../anchor route)
// ---------------------------------------------------------------------------

/**
 * Map a terminal/reconcilable orchestrator outcome into the HTTP-safe body of
 * the `anchor` field. Every field is already permit-listed by the orchestrator
 * (no secrets, no provider/ethers internals); tx/block metadata is public
 * on-chain data case members may already read via RLS.
 */
export function anchorOutcomeBody(outcome: AnchorOutcome): Record<string, unknown> {
  switch (outcome.status) {
    case "anchored":
      return {
        status: "anchored",
        anchor_id: outcome.anchorId,
        tx_hash: outcome.txHash,
        block_number: outcome.blockNumber,
        anchored_at: outcome.anchoredAt,
      };
    case "reconciled":
      // Recovered without a new transaction; NO tx hash is fabricated — the
      // on-chain read cannot recover one, so the field is intentionally absent.
      return {
        status: "reconciled",
        anchor_id: outcome.anchorId,
        block_number: outcome.blockNumber,
        anchored_at: outcome.anchoredAt,
      };
    case "already_anchored":
      return { status: "already_anchored" };
    case "verification_ambiguous":
      return { status: "verification_ambiguous", anchor_id: outcome.anchorId };
    case "db_sync_failed":
      return { status: "db_sync_failed", anchor_id: outcome.anchorId };
    case "failed":
      return {
        status: "failed",
        anchor_id: outcome.anchorId,
        category: outcome.category,
        message: outcome.message,
      };
    case "verification_failed":
      return {
        status: "verification_failed",
        anchor_id: outcome.anchorId,
        message: outcome.message,
      };
  }
}

/**
 * HTTP status for a handled anchor outcome:
 *   200 — the version ended anchored,
 *   202 — the tx is confirmed on-chain but the DB could not be synced and will
 *         be reconciled by a later retry,
 *   502 — the on-chain submission/verification definitively failed (retryable;
 *         a retry resets a failed row to pending).
 */
export function anchorOutcomeHttpStatus(outcome: AnchorOutcome): number {
  switch (outcome.status) {
    case "anchored":
    case "reconciled":
    case "already_anchored":
      return 200;
    case "verification_ambiguous":
    case "db_sync_failed":
      return 202;
    case "failed":
    case "verification_failed":
      return 502;
  }
}

/**
 * Map a thrown error from anchorDocumentVersion() to an HTTP response.
 * The orchestrator throws AnchorOrchestrationError (with `.kind`) for all
 * hard auth/validation/RPC failures; anything else is an unexpected error.
 * Duck-typed on `.kind` so this helper stays free of a runtime import of the
 * orchestrator (node:test safety).
 */
export function anchorErrorStatus(raw: unknown): { status: number; error: string } {
  if (isOrchestrationError(raw)) {
    switch (raw.kind) {
      case "invalid_request":
        return { status: 400, error: raw.message };
      case "not_authenticated":
        return { status: 401, error: raw.message };
      case "profile_not_found":
      case "not_authorized_to_anchor":
        return { status: 403, error: raw.message };
      case "case_not_open":
        return { status: 409, error: raw.message };
      case "document_version_not_found":
      case "evidence_not_found":
        return { status: 404, error: raw.message };
      case "rpc_error":
      case "invalid_rpc_result":
      case "database_error":
        return { status: 500, error: raw.message };
    }
  }
  return { status: 500, error: "Unexpected error" };
}

function isOrchestrationError(
  value: unknown,
): value is { kind: AnchorOrchestrationErrorKind; message: string } {
  if (typeof value !== "object" || value === null) return false;
  const kind = (value as { kind?: unknown }).kind;
  const message = (value as { message?: unknown }).message;
  return typeof kind === "string" && typeof message === "string";
}

// ---------------------------------------------------------------------------
// Logging (allowlisted fields only — never secrets, keys, or provider details)
// ---------------------------------------------------------------------------

function logSafe(level: "error", event: string, fields: { documentVersionId: string }) {
  console.error(`[evidence-upload-anchor] ${JSON.stringify({ event, ...fields })}`);
}