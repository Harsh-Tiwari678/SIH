// Pure orchestration decision logic for the blockchain anchor lifecycle.
// This module has ZERO imports (no Next/Supabase/ethers/server-only code) so it
// can be unit-tested with node:test without a framework. The live DB/blockchain
// wiring lives in lib/blockchain/orchestrator.ts, which imports these helpers.

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

// Structurally compatible with lib/blockchain/anchor.ts's OnChainAnchor (the
// subset the reconcile/classification helpers consult). Declared locally so
// this module stays free of any dependency on the server-only anchor service.
// blockNumber/anchoredAt come from the read-only getAnchor() result and are
// what a reconciliation writes to the DB — the chain stores NO transaction
// hash, so tx_hash can never be recovered here.
export interface OnChainAnchorResult {
  exists: boolean;
  storedSha256: string;
  anchoredAt: bigint;
  blockNumber: bigint;
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
 * Classify a DEFINITIVE read-only on-chain state against the expected evidence
 * SHA-256 (bytes32 hex, e.g. '0x…'). This is the single gate that decides what
 * a retry may do, so NO action — especially no broadcast — happens without it:
 *
 *   "absent"      — the (evidence_id_hash, version_id_hash) slot is empty; a
 *                   normal anchor broadcast is the only thing that may send a
 *                   transaction.
 *   "matched"     — the slot holds EXACTLY our expected evidence hash and
 *                   verify() returned true; the pending DB row can converge to
 *                   anchored WITHOUT broadcasting.
 *   "mismatched"  — the slot is occupied by a DIFFERENT evidence hash (or the
 *                   on-chain verify() disagrees); an integrity anomaly. Never
 *                   mark anchored, never claim the slot as ours — fail for
 *                   review instead.
 *
 * Only a definitive result is classified here; a failed chain READ is handled
 * by the caller as ambiguous (row stays pending), never as a mismatch.
 */
export function classifyOnChainState(
  onChain: OnChainAnchorResult,
  expectedEvidenceSha256: string,
): "absent" | "matched" | "mismatched" {
  if (!onChain.exists) return "absent";
  if (
    onChain.storedSha256.toLowerCase() !==
      expectedEvidenceSha256.toLowerCase() ||
    !onChain.verified
  ) {
    return "mismatched";
  }
  return "matched";
}

/**
 * Build the exact parameters for the reconcile_anchor_anchored RPC from an
 * on-chain observation. Deliberately carries NO transaction hash — the chain
 * read cannot recover one, and fabricating a hash is forbidden. Rejects
 * unusable block metadata (a real mined anchor always has block_number >= 1 and
 * anchored_at > 0); the caller maps that definitive anomaly to a fail-for-review
 * outcome rather than recording garbage.
 */
export interface ReconcileAnchorParams {
  p_anchor_id: string;
  p_block_number: bigint;
  p_anchored_at: string;
}

export function buildReconcileParams(
  anchorId: string,
  onChain: OnChainAnchorResult,
): ReconcileAnchorParams {
  if (onChain.blockNumber < 1n || onChain.anchoredAt <= 0n) {
    throw new AnchorOrchestrationError(
      "invalid_rpc_result",
      "Can't reconcile: the on-chain anchor is missing valid block metadata",
    );
  }
  return {
    p_anchor_id: anchorId,
    p_block_number: onChain.blockNumber,
    p_anchored_at: blockTimestampToIso(onChain.anchoredAt),
  };
}

/**
 * The single decision point of an anchor attempt, decided BEFORE any
 * transaction is sent:
 *
 *   "already_anchored"        — the authoritative DB slot is already anchored
 *                               (terminal); nothing to do.
 *   "reconcile"               — the chain holds OUR evidence hash; converge the
 *                               pending row to anchored, no broadcast.
 *   "broadcast"               — the slot is provably absent; the ONLY phase that
 *                               may send an Ethereum transaction.
 *   "mark_failed_verification"— the slot holds a DIFFERENT hash (integrity
 *                               anomaly); mark failed for review, never anchored.
 *   "verification_ambiguous"  — the chain could not be read (caller passes
 *                               null); keep the row pending, do nothing at all.
 */
export type AnchorPlan =
  | { phase: "already_anchored" }
  | { phase: "reconcile" }
  | { phase: "broadcast" }
  | { phase: "mark_failed_verification"; message: string }
  | { phase: "verification_ambiguous"; message: string };

export function planAnchorAttempt(
  created: CreateAnchorOutcome,
  onChain: OnChainAnchorResult | null,
  expectedEvidenceSha256: string,
): AnchorPlan {
  if (created.kind === "already_anchored") {
    return { phase: "already_anchored" };
  }
  if (onChain === null) {
    return {
      phase: "verification_ambiguous",
      message: "Could not read the on-chain anchor store, so no action was taken",
    };
  }
  switch (classifyOnChainState(onChain, expectedEvidenceSha256)) {
    case "absent":
      return { phase: "broadcast" };
    case "matched":
      return { phase: "reconcile" };
    case "mismatched":
      return {
        phase: "mark_failed_verification",
        message:
          "On-chain verification failed: the anchor slot holds a different evidence hash",
      };
  }
}

/** Read the `transitioned` boolean from a mark_*_rpc jsonb result. */
export function readTransitioned(data: unknown): boolean {
  return (
    isPlainObject(data) &&
    typeof data.transitioned === "boolean" &&
    data.transitioned
  );
}