// Server-only orchestration that moves a document version through the
// blockchain anchor lifecycle: pending -> anchored | failed.
//
// It wires the existing authoritative DB layer (the SECURITY DEFINER RPCs in
// supabase/migrations/20260904203055_create_blockchain_anchors.sql) to the
// existing server-only blockchain service (lib/blockchain/anchor.ts) WITHOUT
// replacing either one.
//
// Responsibilities:
//   * authenticate/authorize via the existing server Supabase client (session
//     cookies + publishable key). It NEVER uses the service-role key and never
//     trusts documentVersionId alone — the RPCs re-check the actor, profile,
//     evidence/version relationship, case membership and lead/investigator
//     role.
//   * obtain the authoritative evidence_id / document_version_id /
//     evidence_sha256 from the RPC result (not from the caller).
//   * call anchorEvidence() only for a confirmed-pending anchor row.
//   * mark the row anchored / failed through the RPCs with BOUNDED safe
//     messages. Never stores raw ethers/provider errors.
//   * tolerate the distributed-sync window (tx confirmed on-chain, DB update
//     fails): it surfaces a distinct db_sync_failed outcome, leaves the DB
//     pending, and never sends a second transaction.

import { createClient } from "@/lib/supabase/server";
import {
  anchorEvidence,
  getOnChainAnchor,
  type AnchorConfirmation,
  type AnchorRequest,
  type OnChainAnchor,
} from "./anchor";
import {
  BlockchainAnchorError,
  ERROR_CATEGORY_MESSAGES,
  type AnchorErrorCategory,
} from "./errors";
import { sha256ToBytes32 } from "./encoding";
// Pure decision logic + domain types live in the framework-free core module so
// they can be unit-tested with node:test; re-exported here so the orchestrator
// keeps a single public surface.
import {
  AnchorOrchestrationError,
  blockTimestampToIso,
  buildReconcileParams,
  isValidDocumentVersionId,
  parseCreateAnchorResult,
  planAnchorAttempt,
  readTransitioned,
  type AnchorPlan,
  type CreateAnchorOutcome,
  type ReconcileAnchorParams,
} from "./orchestrator-core";

export type {
  AnchorOrchestrationErrorKind,
  AnchorPlan,
  CreateAnchorOutcome,
} from "./orchestrator-core";
export {
  AnchorOrchestrationError,
  blockTimestampToIso,
  buildReconcileParams,
  isValidDocumentVersionId,
  parseCreateAnchorResult,
  planAnchorAttempt,
  readTransitioned,
} from "./orchestrator-core";

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

// What the orchestration reports to a caller after a run. These are all handled
// outcomes (returned), whereas hard auth/validation/RPC failures are thrown as
// AnchorOrchestrationError. The db_sync_failed / verification_ambiguous
// outcomes represent the intentional distributed-sync window: the transaction
// is confirmed on-chain but the DB could not be written, so it stays pending
// for later reconciliation. "reconciled" is the recovered terminal state: the
// row converged from pending -> anchored WITHOUT a new transaction and WITHOUT
// a tx hash (the chain read cannot recover one; none is fabricated).
export type AnchorOutcome =
  | { status: "anchored"; anchorId: string; txHash: string; blockNumber: number; anchoredAt: string }
  | { status: "reconciled"; anchorId: string; blockNumber: number; anchoredAt: string }
  | { status: "already_anchored"; anchorId?: string }
  | { status: "failed"; anchorId: string; category: AnchorErrorCategory; message: string }
  | { status: "verification_failed"; anchorId: string; message: string }
  | { status: "db_sync_failed"; anchorId: string; message: string }
  | { status: "verification_ambiguous"; anchorId: string; message: string };

// ---------------------------------------------------------------------------
// RPC error classification (server-side, no secrets)
// ---------------------------------------------------------------------------

/**
 * Map a create_blockchain_anchor RPC failure into a thrown orchestration
 * error. 'already_anchored' is a HANDLED outcome, so it is returned (not
 * thrown); every other known code is mapped to a typed error.
 */
function classifyCreateRpcError(message: string): CreateAnchorOutcome | never {
  if (message.includes("already_anchored")) {
    return { kind: "already_anchored" };
  }
  if (message.includes("not_authenticated")) {
    throw new AnchorOrchestrationError("not_authenticated", "Authentication required");
  }
  if (message.includes("profile_not_found")) {
    throw new AnchorOrchestrationError("profile_not_found", "No application profile");
  }
  if (message.includes("document_version_not_found")) {
    throw new AnchorOrchestrationError("document_version_not_found", "Document version not found");
  }
  if (message.includes("evidence_not_found")) {
    throw new AnchorOrchestrationError("evidence_not_found", "Evidence not found");
  }
  if (message.includes("not_authorized_to_anchor")) {
    throw new AnchorOrchestrationError("not_authorized_to_anchor", "Only the case lead or an investigator can anchor evidence");
  }
  throw new AnchorOrchestrationError("rpc_error", "create_blockchain_anchor failed");
}

/** Wrap a mark_*_rpc failure as a database error (safe, no internals). */
function markRpcError(operation: string, message: string): AnchorOrchestrationError {
  // Known authorization outcomes bubble up with their meaning.
  if (message.includes("not_authenticated")) {
    return new AnchorOrchestrationError("not_authenticated", "Authentication required");
  }
  if (message.includes("not_authorized_to_anchor")) {
    return new AnchorOrchestrationError("not_authorized_to_anchor", "Only the case lead or an investigator can anchor evidence");
  }
  if (operation === "mark_anchor_anchored" && message.includes("hash_mismatch")) {
    return new AnchorOrchestrationError("invalid_rpc_result", "Stored hash does not match the document version hash");
  }
  if (operation === "reconcile_anchor_anchored" && message.includes("hash_mismatch")) {
    return new AnchorOrchestrationError("invalid_rpc_result", "Stored hash does not match the document version hash");
  }
  return new AnchorOrchestrationError("database_error", `${operation} failed`);
}

// ---------------------------------------------------------------------------
// Logging (allowlisted fields only — never secrets, keys, or provider errors)
// ---------------------------------------------------------------------------

function logSafe(level: "info" | "warn" | "error", event: string, fields: {
  documentVersionId?: string;
  anchorId?: string;
  txHash?: string;
  outcome?: string;
}) {
  const msg = `[blockchain-orchestrator] ${JSON.stringify({ event, ...fields })}`;
  if (level === "error") console.error(msg);
  else if (level === "warn") console.warn(msg);
  else console.info(msg);
}

// ---------------------------------------------------------------------------
// RPC wrappers
// ---------------------------------------------------------------------------

function safeChainErrorFrom(category: AnchorErrorCategory): string {
  return ERROR_CATEGORY_MESSAGES[category];
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Move a document version through the blockchain anchor lifecycle.
 *
 * Returns a discriminated AnchorOutcome describing the terminal (or
 * reconcilable) state, or throws AnchorOrchestrationError for hard
 * auth/validation/RPC failures that a caller should map to an HTTP status.
 */
export async function anchorDocumentVersion(
  documentVersionId: string,
): Promise<AnchorOutcome> {
  if (!isValidDocumentVersionId(documentVersionId)) {
    throw new AnchorOrchestrationError("invalid_request", "Invalid document version id");
  }

  // Authenticate + authorize through the existing server Supabase client. The
  // session is resolved from request cookies; the SECURITY DEFINER RPCs below
  // re-check the actor, profile, evidence/version relationship, case
  // membership and role. Service-role is never used.
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) {
    throw new AnchorOrchestrationError("not_authenticated", "Authentication required");
  }

  // Step 1 — create / reuse / reset the anchor slot (authoritative DB layer).
  const { data: createData, error: createError } = await supabase.rpc(
    "create_blockchain_anchor",
    { p_document_version_id: documentVersionId },
  );

  let created: CreateAnchorOutcome;
  if (createError) {
    created = classifyCreateRpcError(createError.message);
  } else {
    created = parseCreateAnchorResult(createData, documentVersionId);
  }

  if (created.kind === "already_anchored") {
    logSafe("info", "already_anchored", { documentVersionId });
    return { status: "already_anchored" };
  }

  // We have a fresh (or reused) pending anchor. Build the request using the
  // AUTHORITATIVE values from the RPC result, never from the caller.
  const request: AnchorRequest = {
    evidenceId: created.evidenceId,
    documentVersionId: created.documentVersionId,
    sha256: created.evidenceSha256,
  };

  // The anchor id comes directly from the RPC result (authoritative).
  // No extra SELECT is needed: create_blockchain_anchor always returns the
  // complete blockchain_anchors row.
  const anchorId = created.anchorId;

  // Step 2 — RECONCILE-FIRST: read the chain BEFORE deciding whether to send a
  // transaction. This is the single gate that prevents a second broadcast
  // merely because the DB row is pending: only an on-chain "absent" result
  // permits broadcasting; a "matched" result converges the row via the
  // reconcile RPC (no new tx, no fabricated tx hash); a read failure keeps the
  // row pending and never marks it failed.
  const expectedSha256 = sha256ToBytes32(created.evidenceSha256);
  let onChain: OnChainAnchor;
  try {
    onChain = await getOnChainAnchor(request);
  } catch (raw) {
    if (raw instanceof BlockchainAnchorError) {
      logSafe("warn", "verification_ambiguous", { documentVersionId, anchorId });
      return ambiguousOutcome(anchorId, raw.category);
    }
    // Any other error is unexpected; do not mis-classify it as a definitive
    // on-chain mismatch or a failed broadcast.
    throw raw;
  }

  const plan = planAnchorAttempt(created, onChain, expectedSha256);

  switch (plan.phase) {
    case "already_anchored":
      // The DB slot is terminal (this path is normally short-circuited by the
      // create RPC, which raises already_anchored); nothing to do.
      logSafe("info", "already_anchored", { documentVersionId, anchorId });
      return { status: "already_anchored", anchorId };
    case "verification_ambiguous":
      return { status: "verification_ambiguous", anchorId, message: plan.message };
    case "mark_failed_verification":
      return resolveFromOnChain(supabase, anchorId, plan, onChain);
    case "reconcile":
      return resolveFromOnChain(supabase, anchorId, plan, onChain);
    case "broadcast":
      break; // the ONLY phase that may transmit — proceed below
  }

  // Step 3 — broadcast (slot proven absent on-chain).
  let confirmation: AnchorConfirmation;
  try {
    confirmation = await anchorEvidence(request);
  } catch (raw) {
    if (raw instanceof BlockchainAnchorError) {
      if (raw.category === "already_anchored") {
        // Second line of defense: a slot appeared between our read and the
        // broadcast. Never mark the row failed and NEVER retry the broadcast —
        // re-read the chain and reconcile if (and only if) it is OUR hash; a
        // different hash is an anomaly to fail for review.
        logSafe("warn", "broadcast_conflict_already_anchored", {
          documentVersionId,
          anchorId,
        });
        let reOnChain: OnChainAnchor;
        try {
          reOnChain = await getOnChainAnchor(request);
        } catch (reRaw) {
          if (reRaw instanceof BlockchainAnchorError) {
            return ambiguousOutcome(anchorId, reRaw.category);
          }
          throw reRaw;
        }
        const rePlan = planAnchorAttempt(created, reOnChain, expectedSha256);
        if (rePlan.phase === "reconcile") {
          return resolveFromOnChain(supabase, anchorId, rePlan, reOnChain);
        }
        if (rePlan.phase === "mark_failed_verification") {
          return resolveFromOnChain(supabase, anchorId, rePlan, reOnChain);
        }
        // "absent" or ambiguous again: the provider gave contradictory data.
        return {
          status: "verification_ambiguous",
          anchorId,
          message: "Could not reconcile the on-chain anchor after a conflicting broadcast",
        };
      }
      // Genuine broadcast failure: definitive on-chain error, safe category.
      const category = raw.category;
      const message = safeChainErrorFrom(category);
      await markFailedBestEffort(supabase, anchorId, message);
      logSafe("error", "anchor_failed", { documentVersionId, anchorId, outcome: category });
      return { status: "failed", anchorId, category, message };
    }
    throw raw;
  }

  // Step 4 — record the confirmed anchor in the DB from the AUTHORITATIVE
  // receipt. The pre-broadcast read already proved the slot absent, so the
  // confirmed receipt is sufficient; no post-broadcast re-read is needed.
  try {
    const { data: markData, error: markError } = await supabase.rpc(
      "mark_anchor_anchored",
      {
        p_anchor_id: anchorId,
        p_tx_hash: confirmation.txHash,
        p_block_number: Number(confirmation.blockNumber),
        p_anchored_at: blockTimestampToIso(confirmation.anchoredAt),
      },
    );
    if (markError) {
      throw markRpcError("mark_anchor_anchored", markError.message);
    }
    const markedAnchored = readTransitioned(markData);
    if (!markedAnchored) {
      // The row was not pending at update time (concurrent terminal transition).
      // The on-chain anchor exists, so this is not a failure.
      logSafe("warn", "anchor_already_terminal", { documentVersionId, anchorId });
      return { status: "already_anchored", anchorId };
    }
  } catch (raw) {
    // Intentional distributed-sync window: the tx is confirmed on-chain but the
    // DB could not be updated. ONLY a genuine database error is treated as that
    // window — leave the DB pending for reconciliation, do NOT mark failed and
    // do NOT send another transaction. Any other failure (authentication,
    // authorization, or a DB invariant anomaly) is re-thrown so it surfaces as
    // its true status instead of being masked as a 202 sync issue.
    if (raw instanceof AnchorOrchestrationError && raw.kind === "database_error") {
      logSafe("error", "db_sync_failed", { documentVersionId, anchorId, txHash: confirmation.txHash });
      return {
        status: "db_sync_failed",
        anchorId,
        message: "The anchor transaction was confirmed on-chain, but the database could not be updated and will be reconciled later",
      };
    }
    throw raw;
  }

  logSafe("info", "anchored", {
    documentVersionId,
    anchorId,
    txHash: confirmation.txHash,
  });
  return {
    status: "anchored",
    anchorId,
    txHash: confirmation.txHash,
    blockNumber: Number(confirmation.blockNumber),
    anchoredAt: blockTimestampToIso(confirmation.anchoredAt),
  };
}

// ---------------------------------------------------------------------------
// Private helpers (server-side)
// ---------------------------------------------------------------------------

function ambiguousOutcome(
  anchorId: string,
  category: AnchorErrorCategory,
): AnchorOutcome {
  return {
    status: "verification_ambiguous",
    anchorId,
    message: safeChainErrorFrom(category),
  };
}

/**
 * Act on a reconcile / mark_failed_verification plan (i.e. after a DEFINITIVE
 * chain read, when the row must converge WITHOUT a broadcast). Every other
 * phase (broadcast / already_anchored / verification_ambiguous) is owned by
 * the caller.
 */
async function resolveFromOnChain(
  supabase: Awaited<ReturnType<typeof createClient>>,
  anchorId: string,
  plan: AnchorPlan,
  onChain: OnChainAnchor,
): Promise<AnchorOutcome> {
  if (plan.phase === "mark_failed_verification") {
    await markFailedBestEffort(supabase, anchorId, plan.message);
    logSafe("error", "verification_failed", { anchorId });
    return { status: "verification_failed", anchorId, message: plan.message };
  }
  return reconcileOutcome(supabase, anchorId, onChain);
}

/**
 * Converge a pending row to anchored from on-chain truth, WITHOUT broadcasting
 * and WITHOUT a transaction hash. `onChain` is the read-only contract result
 * that already proved the slot holds our exact evidence hash; its block_number
 * and anchored_at (not a client-supplied value) become the row's metadata. The
 * RPC re-checks auth/authorization and only transitions pending -> anchored.
 */
async function reconcileOutcome(
  supabase: Awaited<ReturnType<typeof createClient>>,
  anchorId: string,
  onChain: OnChainAnchor,
): Promise<AnchorOutcome> {
  let params: ReconcileAnchorParams;
  try {
    params = buildReconcileParams(anchorId, onChain);
  } catch (raw) {
    if (raw instanceof AnchorOrchestrationError && raw.kind === "invalid_rpc_result") {
      // The slot exists but its block metadata is unusable — a definitive
      // anomaly. Never record garbage and never fabricate data; fail for review.
      const message = "On-chain verification failed: the anchor record is missing valid block metadata";
      await markFailedBestEffort(supabase, anchorId, message);
      logSafe("error", "verification_failed", { anchorId });
      return { status: "verification_failed", anchorId, message };
    }
    throw raw;
  }

  try {
    const { data, error } = await supabase.rpc("reconcile_anchor_anchored", {
      p_anchor_id: params.p_anchor_id,
      p_block_number: Number(params.p_block_number),
      p_anchored_at: params.p_anchored_at,
    });
    if (error) {
      throw markRpcError("reconcile_anchor_anchored", error.message);
    }
    if (!readTransitioned(data)) {
      // The row was not pending at update time (concurrent terminal transition).
      // The chain still holds our anchor, so this is not a failure.
      logSafe("warn", "anchor_already_terminal", { anchorId });
      return { status: "already_anchored", anchorId };
    }
  } catch (raw) {
    // Same distributed-sync window as mark_anchor_anchored: the chain is
    // correct but the DB could not converge. ONLY a genuine database error is
    // swallowed here — the row stays pending for a later reconciliation retry
    // (no mark failed, no new broadcast). Any other failure (authentication,
    // authorization, or a DB invariant anomaly) surfaces as its true status.
    if (raw instanceof AnchorOrchestrationError && raw.kind === "database_error") {
      logSafe("error", "db_sync_failed_reconcile", { anchorId });
      return {
        status: "db_sync_failed",
        anchorId,
        message: "The anchor was found on-chain, but the database could not be updated and will be reconciled later",
      };
    }
    throw raw;
  }

  logSafe("info", "reconciled", { anchorId });
  return {
    status: "reconciled",
    anchorId,
    blockNumber: Number(params.p_block_number),
    anchoredAt: params.p_anchored_at,
  };
}

/**
 * Record a definitive on-chain failure. Only called with a BOUNDED safe
 * message (from ERROR_CATEGORY_MESSAGES or a fixed string) — never raw
 * ethers/provider text. A DB failure here is logged and rethrown so it is not
 * silently swallowed; the pending row remains for reconciliation.
 */
async function markFailedBestEffort(
  supabase: Awaited<ReturnType<typeof createClient>>,
  anchorId: string,
  safeMessage: string,
): Promise<void> {
  const { error } = await supabase.rpc("mark_anchor_failed", {
    p_anchor_id: anchorId,
    p_error_message: safeMessage,
  });
  if (error) {
    const mapped = markRpcError("mark_anchor_failed", error.message);
    if (mapped.kind === "database_error") {
      logSafe("error", "mark_failed_db_error", { anchorId });
      throw mapped;
    }
    throw mapped;
  }
}
