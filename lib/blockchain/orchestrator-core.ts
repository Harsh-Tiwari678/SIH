// Pure orchestration decision logic for the blockchain anchor lifecycle.
// This module has ZERO imports (no Next/Supabase/ethers/server-only code) so it
// can be unit-tested with node:test without a framework. The live DB/blockchain
// wiring lives in lib/blockchain/orchestrator.ts, which imports these helpers.

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

// Structurally compatible with lib/blockchain/anchor.ts's OnChainAnchor (the
// subset decideVerification consults). Declared locally so this module stays
// free of any dependency on the server-only anchor service.
export interface OnChainAnchorResult {
  exists: boolean;
  storedSha256: string;
  verified: boolean;
}

// What create_blockchain_anchor can produce for this service: a fresh or reused
// pending anchor (with the authoritative DB-derived identifiers + its id) or an
// already anchored version. The RPC returns the complete blockchain_anchors row
// in every path, so the anchor id always comes from the database, never from a
// caller.
export type CreateAnchorOutcome =
  | {
      kind: "pending";
      anchorId: string;
      reused: boolean;
      evidenceId: string;
      documentVersionId: string;
      evidenceSha256: string;
    }
  | { kind: "already_anchored" };

// Hard (thrown) orchestration failures a caller maps to an HTTP status.
export type AnchorOrchestrationErrorKind =
  | "invalid_request"
  | "not_authenticated"
  | "profile_not_found"
  | "document_version_not_found"
  | "evidence_not_found"
  | "not_authorized_to_anchor"
  | "rpc_error"
  | "invalid_rpc_result"
  | "database_error";

export class AnchorOrchestrationError extends Error {
  readonly kind: AnchorOrchestrationErrorKind;

  constructor(kind: AnchorOrchestrationErrorKind, message: string) {
    super(message);
    this.name = "AnchorOrchestrationError";
    this.kind = kind;
  }
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isValidDocumentVersionId(value: string): boolean {
  return UUID_PATTERN.test(value);
}

/**
 * Convert the confirmed block's Unix timestamp (seconds, bigint) into an
 * ISO-8601 timestamptz string suitable for the mark_anchor_anchored RPC.
 * Rejects negative/absurd values that Date cannot represent.
 */
export function blockTimestampToIso(seconds: bigint): string {
  if (seconds < 0n || seconds > 86_400_000_000n) {
    throw new AnchorOrchestrationError(
      "invalid_rpc_result",
      `Refusing to interpret an out-of-range block timestamp: ${seconds} seconds`,
    );
  }
  return new Date(Number(seconds) * 1000).toISOString();
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new AnchorOrchestrationError(
      "invalid_rpc_result",
      `create_blockchain_anchor returned a malformed '${field}' field`,
    );
  }
  return value;
}

/**
 * Parse + validate the jsonb returned by create_blockchain_anchor. The RPC is
 * authoritative for the evidence/version/hash relationship, so the returned
 * evidence_id / document_version_id / evidence_sha256 are taken as truth.
 * Verifies that the returned document_version_id matches the caller-supplied
 * id (a mismatch would indicate a serious invariant break, not a normal case).
 */
export function parseCreateAnchorResult(
  data: unknown,
  expectedDocumentVersionId: string,
): CreateAnchorOutcome {
  if (!isPlainObject(data)) {
    throw new AnchorOrchestrationError(
      "invalid_rpc_result",
      "create_blockchain_anchor returned no result object",
    );
  }
  const anchor = data.anchor;
  if (!isPlainObject(anchor)) {
    throw new AnchorOrchestrationError(
      "invalid_rpc_result",
      "create_blockchain_anchor returned no anchor row",
    );
  }

  const status = anchor.status;
  if (status === "anchored") {
    // The RPC raises 'already_anchored' rather than returning an anchored row,
    // so this branch should not normally occur; treat it defensively.
    return { kind: "already_anchored" };
  }
  if (status !== "pending") {
    throw new AnchorOrchestrationError(
      "invalid_rpc_result",
      `create_blockchain_anchor returned an unexpected status '${String(status)}'`,
    );
  }

  const anchorId = asString(anchor.id, "id");
  const evidenceId = asString(anchor.evidence_id, "evidence_id");
  const documentVersionId = asString(
    anchor.document_version_id,
    "document_version_id",
  );
  const evidenceSha256 = asString(anchor.evidence_sha256, "evidence_sha256");

  if (
    documentVersionId.toLowerCase() !== expectedDocumentVersionId.toLowerCase()
  ) {
    throw new AnchorOrchestrationError(
      "invalid_rpc_result",
      "create_blockchain_anchor returned a document_version_id that does not match the requested one",
    );
  }

  if (!UUID_PATTERN.test(anchorId)) {
    throw new AnchorOrchestrationError(
      "invalid_rpc_result",
      "create_blockchain_anchor returned a malformed anchor id",
    );
  }

  return {
    kind: "pending",
    anchorId,
    reused: data.reused === true,
    evidenceId,
    documentVersionId,
    evidenceSha256,
  };
}

/**
 * Decide, from a read-only getOnChainAnchor() result, whether the stored
 * on-chain anchor matches what we expect. Returns "mismatch" only on a
 * DEFINITIVE on-chain inconsistency (missing entry, hash mismatch, or
 * verify() false). A thrown read error is handled by the caller as ambiguous,
 * never as a mismatch.
 */
export function decideVerification(
  onChain: OnChainAnchorResult,
  expectedEvidenceSha256: string,
): "ok" | "mismatch" {
  if (!onChain.exists) return "mismatch";
  if (
    onChain.storedSha256.toLowerCase() !== expectedEvidenceSha256.toLowerCase()
  ) {
    return "mismatch";
  }
  if (!onChain.verified) return "mismatch";
  return "ok";
}

/** Read the `transitioned` boolean from a mark_*_rpc jsonb result. */
export function readTransitioned(data: unknown): boolean {
  return (
    isPlainObject(data) &&
    typeof data.transitioned === "boolean" &&
    data.transitioned
  );
}