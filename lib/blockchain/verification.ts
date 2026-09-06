// Server-only orchestration for the read-only blockchain verification feature.
//
// SECURITY PROPERTIES:
//   * READ-ONLY: verification never transmits a blockchain transaction and
//     never touches the signer private key. It reads the deployed
//     EvidenceAnchor contract through the existing read-only path
//     (lib/blockchain/anchor.ts getOnChainAnchor), which needs only the RPC URL
//     + contract address (never the deployer key).
//   * The on-chain store is the INDEPENDENT authority: verification never
//     trusts blockchain_anchors.status in the database as proof of anchoring.
//     It derives the deterministic bytes32 identifiers from the document
//     version's own evidence_id / id / sha256, reads the stored slot, and
//     classifies the comparison result. The DB anchor row is surfaced only as
//     permit-listed context.
//   * Authorization uses the existing RLS model: the version/evidence/anchor
//     rows are resolved through the server Supabase client with the
//     request-session user, and the RLS SELECT policies expose rows only to
//     members of the version's OWN case. The case id in the URL is NOT used for
//     authorization (a client-supplied case id is never trusted). No
//     service-role key is used.
//   * Reconciled anchors legitimately carry tx_hash = NULL; nothing here ever
//     fabricates a transaction hash.
//   * Verification is GET-safe: it performs no RPC mutations, no audit inserts
//     (reads are not audited, matching the rest of the system).

import { createClient } from "@/lib/supabase/server";
import {
  BlockchainAnchorError,
  ERROR_CATEGORY_MESSAGES,
  type AnchorErrorCategory,
} from "./errors";
import {
  SEPOLIA_CHAIN_ID,
  deriveAnchorHashes,
  getOnChainAnchor,
  type AnchorRequest,
  type OnChainAnchor,
} from "./anchor";
import {
  blockTimestampToIso,
  isValidDocumentVersionId,
} from "./orchestrator-core";
import {
  VerificationOrchestrationError,
  classifyVerificationState,
  type VerificationContractInfo,
  type VerificationDbAnchorContext,
  type VerificationFrame,
  type VerificationOnChainFacts,
  type VerificationStatus,
} from "./verification-core";

export {
  VerificationOrchestrationError,
  classifyVerificationState,
  verificationBody,
  verificationErrorStatus,
} from "./verification-core";
export type {
  VerificationContractInfo,
  VerificationDbAnchorContext,
  VerificationFrame,
  VerificationOnChainFacts,
  VerificationStatus,
} from "./verification-core";

const CONTRACT_ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/;
const TX_HASH_PATTERN = /^0x[0-9a-fA-F]{64}$/;
const ANCHOR_STATUS = ["pending", "anchored", "failed"] as const;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Read-only on-chain verification of a document version.
 *
 * Resolves the version -> evidence -> case relationship through the existing
 * RLS model (authorizing the session user against the version's OWN case),
 * independently reads the deployed contract's anchor, derives the exact
 * bytes32 encodings the anchoring system uses, and classifies the result.
 *
 * Returns a VerificationFrame (see verification-core.ts) or throws
 * VerificationOrchestrationError for hard auth/validation/DB failures.
 */
export async function verifyDocumentVersion(
  documentVersionId: string,
): Promise<VerificationFrame> {
  if (!isValidDocumentVersionId(documentVersionId)) {
    throw new VerificationOrchestrationError(
      "invalid_request",
      "Invalid document version id",
    );
  }

  // 1. authenticate — the session is resolved from the request, never from
  //    arguments.
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) {
    throw new VerificationOrchestrationError(
      "not_authenticated",
      "Authentication required",
    );
  }

  // 2. authorize + resolve — the version's own evidence -> case relationship,
  //    via the RLS SELECT policies (case members only). A well-formed uuid for
  //    a version outside the actor's cases is indistinguishable from a
  //    nonexistent version (no existence leak).
  const { data: version, error: versionError } = await supabase
    .from("document_versions")
    .select("id, evidence_id, sha256")
    .eq("id", documentVersionId)
    .maybeSingle();
  if (versionError) {
    throw new VerificationOrchestrationError(
      "database_error",
      "Could not read the document version for verification",
    );
  }
  if (!version) {
    throw new VerificationOrchestrationError(
      "document_version_not_found",
      "Document version not found",
    );
  }

  const { data: evidence, error: evidenceError } = await supabase
    .from("evidence")
    .select("id, case_id")
    .eq("id", version.evidence_id)
    .maybeSingle();
  if (evidenceError) {
    throw new VerificationOrchestrationError(
      "database_error",
      "Could not read the evidence for verification",
    );
  }
  if (!evidence) {
    throw new VerificationOrchestrationError(
      "evidence_not_found",
      "Evidence not found",
    );
  }

  // 3. permit-listed database context. The on-chain store — NOT this row — is
  //    the authority for the verification result; the row is only surfaced so
  //    the UI can distinguish "the database thinks it is anchored" from "the
  //    chain shows it is anchored".
  const { data: anchorRow, error: anchorError } = await supabase
    .from("blockchain_anchors")
    .select(
      "status, tx_hash, block_number, anchored_at, network, chain_id, contract_address",
    )
    .eq("document_version_id", documentVersionId)
    .maybeSingle();
  if (anchorError) {
    throw new VerificationOrchestrationError(
      "database_error",
      "Could not read the blockchain anchor for verification",
    );
  }
  const databaseAnchor = parseAnchorContext(anchorRow);

  // 4. build the read request from the AUTHORITATIVE database values and
  //    derive the same deterministic bytes32 encodings the anchoring system
  //    uses (the single deriveAnchorHashes implementation).
  const request: AnchorRequest = {
    evidenceId: version.evidence_id,
    documentVersionId: version.id,
    sha256: version.sha256,
  };
  const hashes = deriveAnchorHashes(request);
  const expectedSha256 = hashes.evidenceSha256;

  // 5. business operation — the independent READ-ONLY blockchain check.
  const read = await readOnChain(request);

  // 6. classify the definitive read; a failed read is ambiguous (never a
  //    definitive verdict).
  const contract = verificationTarget();

  let status: VerificationStatus;
  let blockchain: VerificationOnChainFacts | null = null;
  let message: string | undefined;

  if (read.state === null) {
    status = "verification_ambiguous";
    message = read.message;
  } else {
    status = classifyVerificationState(read.state, expectedSha256);
    try {
      blockchain = buildBlockchainFacts(hashes, read.state, contract);
    } catch {
      // Unusable on-chain metadata (e.g. a degenerate block timestamp) is not
      // a definitive integrity verdict; the honest answer is ambiguous.
      logSafe("warn", "verification_onchain_metadata_unusable", {
        documentVersionId,
      });
      status = "verification_ambiguous";
      blockchain = null;
      message = "The on-chain anchor could not be read reliably";
    }
    if (status === "hash_mismatch") {
      // Integrity problem: the DB is never silently changed to "match" the
      // chain, and the chain is never changed to match the DB.
      message =
        "The on-chain anchor SHA-256 does not match this document version's SHA-256";
    }
  }

  logSafe("info", "verification_complete", { documentVersionId, status });

  return {
    status,
    documentVersionId: version.id,
    evidenceId: version.evidence_id,
    caseId: evidence.case_id,
    databaseSha256: version.sha256,
    blockchain,
    databaseAnchor,
    message,
  };
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

type OnChainRead =
  | { state: OnChainAnchor }
  | { state: null; message: string };

/**
 * Read the on-chain anchor through the existing server-only read path. A
 * BlockchainAnchorError (provider/network/config failure) becomes an ambiguous
 * outcome with a BOUNDED safe message; any other error is rethrown so bugs are
 * not masked as "ambiguous".
 */
async function readOnChain(request: AnchorRequest): Promise<OnChainRead> {
  try {
    return { state: await getOnChainAnchor(request) };
  } catch (raw) {
    if (raw instanceof BlockchainAnchorError) {
      return { state: null, message: safeChainErrorFrom(raw.category) };
    }
    throw raw;
  }
}

function safeChainErrorFrom(category: AnchorErrorCategory): string {
  return ERROR_CATEGORY_MESSAGES[category];
}

// The contract this deployment reads against (public facts, no secrets). Only
// available when the environment is configured; a successful chain read proves
// it was configured, so on the definitive path this is always populated.
function verificationTarget(): VerificationContractInfo | null {
  const contractAddress = process.env.EVIDENCE_ANCHOR_CONTRACT_ADDRESS;
  if (!contractAddress || !CONTRACT_ADDRESS_PATTERN.test(contractAddress)) {
    return null;
  }
  return { network: "sepolia", chainId: SEPOLIA_CHAIN_ID, contractAddress };
}

function buildBlockchainFacts(
  hashes: { evidenceIdHash: string; versionIdHash: string; evidenceSha256: string },
  onChain: OnChainAnchor,
  contract: VerificationContractInfo | null,
): VerificationOnChainFacts {
  const base = {
    evidenceIdHash: hashes.evidenceIdHash,
    versionIdHash: hashes.versionIdHash,
    expectedSha256: hashes.evidenceSha256,
    network: contract?.network ?? "sepolia",
    chainId: contract?.chainId ?? SEPOLIA_CHAIN_ID,
    contractAddress: contract?.contractAddress ?? "",
  };
  if (!onChain.exists) {
    return {
      ...base,
      exists: false,
      storedSha256: null,
      anchoredAt: null,
      blockNumber: null,
    };
  }
  return {
    ...base,
    exists: true,
    storedSha256: onChain.storedSha256,
    // Authoritative block metadata from the read-only contract result. The
    // conversion rejects unusable values (a throw is mapped to ambiguous by
    // the caller, never to a fabricated verdict).
    anchoredAt: blockTimestampToIso(onChain.anchoredAt),
    blockNumber: toSafeBlockNumber(onChain.blockNumber),
  };
}

function toSafeBlockNumber(value: bigint): number {
  if (value < 1n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("unusable on-chain block number");
  }
  return Number(value);
}

/**
 * Parse the optional blockchain_anchors row into a permit-listed context. The
 * values were written through the SECURITY DEFINER RPCs under DB CHECK
 * constraints; this is a light defensive re-validation so a malformed row is
 * dropped as context rather than echoed to a client. tx_hash is only kept when
 * it is a genuine 64-hex hash (reconciled anchors keep NULL).
 */
function parseAnchorContext(row: unknown): VerificationDbAnchorContext | null {
  if (typeof row !== "object" || row === null) return null;
  const r = row as Record<string, unknown>;
  const status = r.status;
  if (typeof status !== "string") return null;
  if (!(ANCHOR_STATUS as readonly string[]).includes(status)) return null;

  return {
    status: status as "pending" | "anchored" | "failed",
    txHash:
      typeof r.tx_hash === "string" && TX_HASH_PATTERN.test(r.tx_hash)
        ? r.tx_hash
        : null,
    blockNumber: toNullableInt(r.block_number),
    anchoredAt: typeof r.anchored_at === "string" ? r.anchored_at : null,
    network: typeof r.network === "string" ? r.network : "sepolia",
    chainId:
      typeof r.chain_id === "number"
        ? r.chain_id
        : typeof r.chain_id === "string"
          ? Number(r.chain_id)
          : SEPOLIA_CHAIN_ID,
    contractAddress:
      typeof r.contract_address === "string" ? r.contract_address : "",
  };
}

function toNullableInt(value: unknown): number | null {
  if (value === null || value === undefined) return null;
  const n = typeof value === "number" ? value : Number(String(value));
  if (!Number.isSafeInteger(n) || n < 1) return null;
  return n;
}

// ---------------------------------------------------------------------------
// Logging (allowlisted fields only — never secrets, keys, or provider errors)
// ---------------------------------------------------------------------------

function logSafe(
  level: "info" | "warn",
  event: string,
  fields: { documentVersionId?: string; status?: string },
) {
  const msg = `[blockchain-verification] ${JSON.stringify({ event, ...fields })}`;
  if (level === "warn") console.warn(msg);
  else console.info(msg);
}