// Pure decision/classification logic for the read-only blockchain verification
// feature. This module has only framework-free imports (the anchor-state
// predicate in orchestrator-core) so it can be unit-tested with node:test.
// The live Supabase/ethers wiring lives in lib/blockchain/verification.ts.

import { classifyOnChainState } from "./orchestrator-core";

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

export type VerificationStatus =
  | "verified"
  | "not_anchored"
  | "hash_mismatch"
  | "verification_ambiguous";

// Structurally compatible with lib/blockchain/anchor.ts's OnChainAnchor (the
// subset the classification consults). Declared locally so this module stays
// free of any dependency on the server-only anchor service.
export interface OnChainVerificationState {
  exists: boolean;
  storedSha256: string;
  anchoredAt: bigint;
  blockNumber: bigint;
  verified: boolean;
}

// Hard (thrown) verification failures a caller maps to an HTTP status.
export type VerificationErrorKind =
  | "invalid_request"
  | "not_authenticated"
  | "document_version_not_found"
  | "evidence_not_found"
  | "database_error";

export class VerificationOrchestrationError extends Error {
  readonly kind: VerificationErrorKind;

  constructor(kind: VerificationErrorKind, message: string) {
    super(message);
    this.name = "VerificationOrchestrationError";
    this.kind = kind;
  }
}

// The contract the verification read targeted. Public on-chain facts (network,
// chain id and contract address) carry no case/PII sensitivity; case members
// can already read the same values from blockchain_anchors via RLS.
export interface VerificationContractInfo {
  network: string;
  chainId: number;
  contractAddress: string;
}

// On-chain facts surfaced to the caller. nulls mean "not applicable": the slot
// is empty (exists=false) or the read failed entirely (VerificationFrame.
// blockchain === null).
export interface VerificationOnChainFacts {
  evidenceIdHash: string;
  versionIdHash: string;
  expectedSha256: string;
  exists: boolean;
  storedSha256: string | null;
  anchoredAt: string | null;
  blockNumber: number | null;
  network: string;
  chainId: number;
  contractAddress: string;
}

// Permit-listed database context for the anchor row. txHash is carried ONLY
// when the database genuinely stored one; a reconciled anchor legitimately has
// NULL (the on-chain read cannot recover a transaction hash and none is
// fabricated).
export interface VerificationDbAnchorContext {
  status: "pending" | "anchored" | "failed";
  txHash: string | null;
  blockNumber: number | null;
  anchoredAt: string | null;
  network: string;
  chainId: number;
  contractAddress: string;
}

// The full result a caller turns into a response. `message` is a bounded
// explanation (set for ambiguous reads and for hash_mismatch integrity
// problems); it never carries provider/ethers internals.
export interface VerificationFrame {
  status: VerificationStatus;
  documentVersionId: string;
  evidenceId: string;
  caseId: string;
  databaseSha256: string;
  blockchain: VerificationOnChainFacts | null;
  databaseAnchor: VerificationDbAnchorContext | null;
  message?: string;
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/**
 * Classify a DEFINITIVE read-only on-chain state against the expected evidence
 * SHA-256 (bytes32 hex, e.g. '0x…'). Reuses the exact anchor-state predicate
 * used by the anchor lifecycle (classifyOnChainState) so verification is not a
 * rival reading of on-chain truth:
 *
 *   not_anchored  — the (evidence_id_hash, version_id_hash) slot is empty.
 *   verified      — the slot holds EXACTLY our expected evidence hash and
 *                   verify() returned true.
 *   hash_mismatch — the slot is occupied by a DIFFERENT evidence hash (or the
 *                   on-chain verify() disagrees): an integrity problem.
 *
 * A failed chain READ is never classified here; the caller must map it to
 * verification_ambiguous.
 */
export function classifyVerificationState(
  onChain: OnChainVerificationState,
  expectedSha256Bytes32: string,
): Exclude<VerificationStatus, "verification_ambiguous"> {
  switch (classifyOnChainState(onChain, expectedSha256Bytes32)) {
    case "absent":
      return "not_anchored";
    case "matched":
      return "verified";
    case "mismatched":
      return "hash_mismatch";
  }
}

// ---------------------------------------------------------------------------
// Response body
// ---------------------------------------------------------------------------

/**
 * Build the HTTP-safe body for a verification frame. Every field is
 * permit-listed by the orchestrator that built the frame (no secrets, no
 * provider/ethers internals). tx_hash is carried ONLY from the genuine
 * database value — a reconciled anchor's NULL is passed through as null, never
 * replaced with an invented hash.
 */
export function verificationBody(frame: VerificationFrame): Record<string, unknown> {
  return {
    status: frame.status,
    document_version_id: frame.documentVersionId,
    evidence_id: frame.evidenceId,
    case_id: frame.caseId,
    database_sha256: frame.databaseSha256,
    blockchain: frame.blockchain
      ? {
          evidence_id_hash: frame.blockchain.evidenceIdHash,
          version_id_hash: frame.blockchain.versionIdHash,
          expected_sha256: frame.blockchain.expectedSha256,
          exists: frame.blockchain.exists,
          stored_sha256: frame.blockchain.storedSha256,
          anchored_at: frame.blockchain.anchoredAt,
          block_number: frame.blockchain.blockNumber,
          network: frame.blockchain.network,
          chain_id: frame.blockchain.chainId,
          contract_address: frame.blockchain.contractAddress,
        }
      : null,
    database_anchor: frame.databaseAnchor
      ? {
          status: frame.databaseAnchor.status,
          tx_hash: frame.databaseAnchor.txHash,
          block_number: frame.databaseAnchor.blockNumber,
          anchored_at: frame.databaseAnchor.anchoredAt,
          network: frame.databaseAnchor.network,
          chain_id: frame.databaseAnchor.chainId,
          contract_address: frame.databaseAnchor.contractAddress,
        }
      : null,
    ...(frame.message ? { message: frame.message } : {}),
  };
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

/**
 * Map a thrown error from verifyDocumentVersion() to an HTTP response. The
 * service throws VerificationOrchestrationError (with `.kind`) for all hard
 * auth/validation/DB failures; anything else is an unexpected error.
 * Duck-typed on `.kind` so this helper stays free of a runtime import of the
 * service (node:test safety), mirroring upload-integration's anchorErrorStatus.
 */
export function verificationErrorStatus(raw: unknown): { status: number; error: string } {
  if (isVerificationError(raw)) {
    switch (raw.kind) {
      case "invalid_request":
        return { status: 400, error: raw.message };
      case "not_authenticated":
        return { status: 401, error: raw.message };
      case "document_version_not_found":
      case "evidence_not_found":
        return { status: 404, error: raw.message };
      case "database_error":
        return { status: 500, error: raw.message };
    }
  }
  return { status: 500, error: "Unexpected error" };
}

function isVerificationError(
  value: unknown,
): value is { kind: VerificationErrorKind; message: string } {
  if (typeof value !== "object" || value === null) return false;
  const kind = (value as { kind?: unknown }).kind;
  const message = (value as { message?: unknown }).message;
  return typeof kind === "string" && typeof message === "string";
}