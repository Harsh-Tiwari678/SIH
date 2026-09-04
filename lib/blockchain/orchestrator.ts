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
  decideVerification,
  isValidDocumentVersionId,
  parseCreateAnchorResult,
  readTransitioned,
  type CreateAnchorOutcome,
} from "./orchestrator-core";

export type {
  AnchorOrchestrationErrorKind,
  CreateAnchorOutcome,
} from "./orchestrator-core";
export {
  AnchorOrchestrationError,
  blockTimestampToIso,
  decideVerification,
  isValidDocumentVersionId,
  parseCreateAnchorResult,
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
// for later reconciliation via getOnChainAnchor().
export type AnchorOutcome =
  | { status: "anchored"; anchorId: string; txHash: string; blockNumber: number; anchoredAt: string }
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

  // Step 2 — anchor on-chain (server-only blockchain service).
  let confirmation: AnchorConfirmation;
  try {
    confirmation = await anchorEvidence(request);
  } catch (raw) {
    if (raw instanceof BlockchainAnchorError) {
      const category = raw.category;
      const message = safeChainErrorFrom(category);
      await markFailedBestEffort(supabase, anchorId, message);
      logSafe("error", "anchor_failed", { documentVersionId, anchorId, outcome: category });
      return { status: "failed", anchorId, category, message };
    }
    throw raw;
  }

  // Step 3 — read-only verification against the deployed contract. The tx is
  // already confirmed on-chain; verification only produces a definitive
  // mismatch (each a harmless DB-side state). An ambiguous read error never
  // marks the row failed.
  let verificationPasses = false;
  try {
    const onChain = await getOnChainAnchor(request);
    verificationPasses =
      decideVerification(onChain, sha256ToBytes32(created.evidenceSha256)) === "ok";
  } catch (raw) {
    if (raw instanceof BlockchainAnchorError) {
      const message = safeChainErrorFrom(raw.category);
      // Intentional distributed-sync window: the tx succeeded but we cannot
      // confirm the stored state. Leave the DB pending for reconciliation —
      // do NOT mark failed, do NOT send another tx.
      logSafe("warn", "verification_ambiguous", { documentVersionId, anchorId });
      return { status: "verification_ambiguous", anchorId, message };
    }
    // Any other error is unexpected; do not mis-classify it as a definitive
    // on-chain mismatch by letting it fall through to markFailedBestEffort.
    throw raw;
  }

  if (!verificationPasses) {
    const message = "On-chain verification failed: stored anchor does not match the expected evidence hash";
    await markFailedBestEffort(supabase, anchorId, message);
    logSafe("error", "verification_failed", { documentVersionId, anchorId });
    return { status: "verification_failed", anchorId, message };
  }

  // Step 4 — record the confirmed anchor in the DB.
  let markedAnchored: boolean;
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
    markedAnchored = readTransitioned(markData);
  } catch (raw) {
    if (raw instanceof AnchorOrchestrationError) {
      // Intentional distributed-sync window: the tx is confirmed on-chain but
      // the DB could not be updated. Leave the DB pending for reconciliation —
      // do NOT mark failed, do NOT send another transaction.
      logSafe("error", "db_sync_failed", { documentVersionId, anchorId, txHash: confirmation.txHash });
      return {
        status: "db_sync_failed",
        anchorId,
        message: "The anchor transaction was confirmed on-chain, but the database could not be updated and will be reconciled later",
      };
    }
    throw raw;
  }

  if (!markedAnchored) {
    // The row was not pending at update time (concurrent terminal transition).
    // The on-chain anchor exists, so this is not a failure.
    logSafe("warn", "anchor_already_terminal", { documentVersionId, anchorId });
    return {
      status: "already_anchored",
      anchorId,
    };
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
