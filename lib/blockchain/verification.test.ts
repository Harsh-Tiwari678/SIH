// End-to-end tests for the read-only on-chain verification service
// (lib/blockchain/verification.ts): a session-authenticated, RLS-gated,
// INDEPENDENT contract read that classifies verified / not_anchored /
// hash_mismatch / verification_ambiguous.
//
// The blockchain service module (!./anchor) is mock.module'd exactly like
// orchestrator.test.ts does. Because the mock REPLACES the whole module, it
// must supply every runtime export verification.ts imports from ./anchor:
// SEPOLIA_CHAIN_ID, deriveAnchorHashes (rebuilt on the real encoding helpers),
// getOnChainAnchor (scripted), and anchorEvidence (a never-call guard — the
// verification service must NEVER broadcast).
//
// The "@/lib/supabase/server" alias is mapped to supabase-server-stub.ts by
// test-support/test-loader.mjs; RLS is simulated by which rows the scripted
// handlers return ({ data: null } → the row is invisible to the actor).
//
// No real Ethereum transaction, no network, no database. The fixtures are NOT
// the live, already-anchored Sepolia pair. Run via: npm test.

import { mock, test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { BlockchainAnchorError, ERROR_CATEGORY_MESSAGES } from "./errors.ts";
import { VerificationOrchestrationError } from "./verification-core.ts";
import { sha256ToBytes32, uuidToBytes32 } from "./encoding.ts";
import {
  clientHolder,
  makeFakeClient,
  type FakeSupabaseClient,
} from "./test-support/supabase-server-stub.ts";

// ---- fixtures (NOT the live, already-anchored Sepolia pair) --------------

const EVIDENCE_UUID = "12345678-1234-4234-8234-123456789abc";
const VERSION_UUID = "abcdefab-cdef-4abc-8def-123456789012";
const CASE_UUID = "22222222-2222-4222-8222-222222222222";
const SHA256_HEX =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const SHA256_BYTES32 = `0x${SHA256_HEX}`;
const OTHER_HASH =
  "0x1111111111111111111111111111111111111111111111111111111111111111";
const TX_HASH = `0x${"a".repeat(64)}`;
const ISO_ANCHORED_AT = "2023-11-14T22:13:20.000Z";
const CONTRACT_ADDRESS = "0x1D76cea78A844fed9aca674C82a900917e848b1a";

const BLOCK_NUMBER = 19_000_000n;
const ANCHORED_AT = 1_700_000_000n;

const VERSION_ROW = { id: VERSION_UUID, evidence_id: EVIDENCE_UUID, sha256: SHA256_HEX };
const EVIDENCE_ROW = { id: EVIDENCE_UUID, case_id: CASE_UUID };

function anchorRow(overrides: Record<string, unknown> = {}) {
  return {
    status: "anchored",
    tx_hash: TX_HASH,
    block_number: 19_000_000,
    anchored_at: ISO_ANCHORED_AT,
    network: "sepolia",
    chain_id: 11155111,
    contract_address: CONTRACT_ADDRESS,
    document_version_id: VERSION_UUID,
    ...overrides,
  };
}

const matchedOnChain = {
  exists: true,
  storedSha256: SHA256_BYTES32,
  anchoredAt: ANCHORED_AT,
  blockNumber: BLOCK_NUMBER,
  verified: true,
};

const absentOnChain = {
  exists: false,
  storedSha256: `0x${"0".repeat(64)}`,
  anchoredAt: 0n,
  blockNumber: 0n,
  verified: false,
};

// ---- blockchain service stubs ---------------------------------------------

let anchorEvidenceCalls = 0;
const readRequests: Array<{
  evidenceId: string;
  documentVersionId: string;
  sha256: string;
}> = [];

// The scripted read for the NEXT getOnChainAnchor invocation.
const scriptedOnChain: { read: () => Promise<unknown> | unknown } = {
  read: () => {
    throw new Error("scriptedOnChain.read not set for this scenario");
  },
};

mock.module(new URL("./anchor.ts", import.meta.url).href, {
  namedExports: {
    SEPOLIA_CHAIN_ID: 11155111,
    // Rebuild the real single implementation of the hash derivation on the
    // real encoding helpers, so no separate logic can drift.
    deriveAnchorHashes: (request: {
      evidenceId: string;
      documentVersionId: string;
      sha256: string;
    }) => ({
      evidenceIdHash: uuidToBytes32(request.evidenceId),
      versionIdHash: uuidToBytes32(request.documentVersionId),
      evidenceSha256: sha256ToBytes32(request.sha256),
    }),
    getOnChainAnchor: async (request: {
      evidenceId: string;
      documentVersionId: string;
      sha256: string;
    }) => {
      readRequests.push(request);
      return scriptedOnChain.read();
    },
    // The verification service must never broadcast; reaching this stub is a
    // failing test.
    anchorEvidence: async () => {
      anchorEvidenceCalls += 1;
      throw new Error("verification must never call anchorEvidence");
    },
  },
});

// Load the REAL verification service AFTER the mocks are registered (static
// imports would be hoisted above the mock registration and defeat it).
const { verifyDocumentVersion } = await import("./verification.ts");

// ---- DB helpers (RLS simulated by which rows the handlers return) ---------

interface DbConfig {
  user?: { id: string } | null;
  version?: typeof VERSION_ROW | null;
  evidence?: typeof EVIDENCE_ROW | null;
  anchor?: ReturnType<typeof anchorRow> | null;
  hideVersion?: boolean;
  hideEvidence?: boolean;
  tableError?: string;
}

function setupDb(config: DbConfig = {}): FakeSupabaseClient {
  const client = makeFakeClient();
  client.user =
    config.user === undefined
      ? { id: "00000000-0000-4000-8000-000000000001" }
      : config.user;

  client.tableHandlers.set("document_versions", (q) => {
    if (config.tableError === "document_versions") {
      return { data: null, error: { message: "database connection lost" } };
    }
    const v = config.version;
    if (!v || config.hideVersion || q.eqValue !== v.id) {
      return { data: null, error: null };
    }
    return { data: v, error: null };
  });
  client.tableHandlers.set("evidence", (q) => {
    if (config.tableError === "evidence") {
      return { data: null, error: { message: "database connection lost" } };
    }
    const e = config.evidence;
    if (!e || config.hideEvidence || q.eqValue !== e.id) {
      return { data: null, error: null };
    }
    return { data: e, error: null };
  });
  client.tableHandlers.set("blockchain_anchors", (q) => {
    if (config.tableError === "blockchain_anchors") {
      return { data: null, error: { message: "database connection lost" } };
    }
    const a = config.anchor;
    if (!a || q.eqValue !== a.document_version_id) {
      return { data: null, error: null };
    }
    return { data: a, error: null };
  });

  clientHolder.current = client;
  return client;
}

async function expectRejectedKind(
  kind: string,
  run: () => Promise<unknown>,
): Promise<void> {
  let caught: unknown = null;
  try {
    await run();
  } catch (raw) {
    caught = raw;
  }
  assert.ok(
    caught instanceof VerificationOrchestrationError,
    `expected VerificationOrchestrationError, got ${String(caught)}`,
  );
  assert.equal((caught as VerificationOrchestrationError).kind, kind);
}

// ---- scenarios -------------------------------------------------------------

beforeEach(() => {
  process.env.EVIDENCE_ANCHOR_CONTRACT_ADDRESS = CONTRACT_ADDRESS;
  anchorEvidenceCalls = 0;
  readRequests.length = 0;
  scriptedOnChain.read = () => {
    throw new Error("unset scripted read");
  };
});

test("[1] authorized member; chain holds exactly the DB hash -> verified, with exact bytes32 encodings", async () => {
  const client = setupDb({
    version: VERSION_ROW,
    evidence: EVIDENCE_ROW,
    anchor: anchorRow(),
  });
  scriptedOnChain.read = async () => matchedOnChain;

  const frame = await verifyDocumentVersion(VERSION_UUID);

  assert.equal(frame.status, "verified");
  assert.equal(frame.documentVersionId, VERSION_UUID);
  assert.equal(frame.evidenceId, EVIDENCE_UUID);
  assert.equal(frame.caseId, CASE_UUID);
  assert.equal(frame.databaseSha256, SHA256_HEX);
  assert.equal(frame.message, undefined);

  // The read hit the chain with the AUTHORITATIVE DB-derived identifiers.
  assert.deepEqual(readRequests, [
    { evidenceId: EVIDENCE_UUID, documentVersionId: VERSION_UUID, sha256: SHA256_HEX },
  ]);
  // Same bytes32 encoding the anchoring pipeline uses (uuid left-padded to
  // bytes32, sha256 0x-prefixed).
  assert.equal(frame.blockchain?.evidenceIdHash, uuidToBytes32(EVIDENCE_UUID));
  assert.equal(
    frame.blockchain?.versionIdHash,
    `0x00000000000000000000000000000000${VERSION_UUID.replace(/-/g, "")}`,
  );
  assert.equal(frame.blockchain?.expectedSha256, sha256ToBytes32(SHA256_HEX));
  assert.equal(frame.blockchain?.exists, true);
  assert.equal(frame.blockchain?.storedSha256, SHA256_BYTES32);
  assert.equal(frame.blockchain?.anchoredAt, ISO_ANCHORED_AT);
  assert.equal(frame.blockchain?.blockNumber, 19_000_000);
  assert.equal(frame.blockchain?.network, "sepolia");
  assert.equal(frame.blockchain?.chainId, 11155111);
  assert.equal(frame.blockchain?.contractAddress, CONTRACT_ADDRESS);

  // Permit-listed DB context, including the genuine tx hash.
  assert.equal(frame.databaseAnchor?.status, "anchored");
  assert.equal(frame.databaseAnchor?.txHash, TX_HASH);
  assert.equal(frame.databaseAnchor?.blockNumber, 19_000_000);

  // READ-ONLY: no broadcast, no RPC mutation anywhere on this path.
  assert.equal(anchorEvidenceCalls, 0);
  assert.equal(client.calls.length, 0);
  assert.deepEqual(
    client.queries.map((q) => q.table),
    ["document_versions", "evidence", "blockchain_anchors"],
  );
});

test("[2] chain slot empty -> not_anchored (a definitive verdict, distinct from any failure)", async () => {
  setupDb({ version: VERSION_ROW, evidence: EVIDENCE_ROW, anchor: anchorRow() });
  scriptedOnChain.read = async () => absentOnChain;

  const frame = await verifyDocumentVersion(VERSION_UUID);

  assert.equal(frame.status, "not_anchored");
  assert.equal(frame.blockchain?.exists, false);
  assert.equal(frame.blockchain?.storedSha256, null);
  assert.equal(frame.blockchain?.anchoredAt, null);
  assert.equal(frame.blockchain?.blockNumber, null);
  assert.equal(frame.message, undefined);
});

test("[3] chain slot holds a DIFFERENT hash -> hash_mismatch (integrity problem, never rewritten)", async () => {
  setupDb({ version: VERSION_ROW, evidence: EVIDENCE_ROW, anchor: anchorRow() });
  scriptedOnChain.read = async () => ({ ...matchedOnChain, storedSha256: OTHER_HASH });

  const frame = await verifyDocumentVersion(VERSION_UUID);

  assert.equal(frame.status, "hash_mismatch");
  assert.equal(
    frame.message,
    "The on-chain anchor SHA-256 does not match this document version's SHA-256",
  );
  assert.equal(frame.blockchain?.storedSha256, OTHER_HASH);
  assert.equal(readRequests.length, 1);
});

test("[4] chain READ failure -> verification_ambiguous with a bounded message, no fabricated verdict", async () => {
  setupDb({ version: VERSION_ROW, evidence: EVIDENCE_ROW, anchor: anchorRow() });
  scriptedOnChain.read = async () => {
    throw new BlockchainAnchorError("network_error");
  };

  const frame = await verifyDocumentVersion(VERSION_UUID);

  assert.equal(frame.status, "verification_ambiguous");
  assert.equal(frame.blockchain, null);
  assert.equal(frame.message, ERROR_CATEGORY_MESSAGES.network_error);
  assert.equal(anchorEvidenceCalls, 0);
});

test("[5] unauthenticated -> rejected BEFORE any row read or chain contact", async () => {
  const client = setupDb({
    user: null,
    version: VERSION_ROW,
    evidence: EVIDENCE_ROW,
    anchor: anchorRow(),
  });
  scriptedOnChain.read = async () => matchedOnChain;

  await expectRejectedKind("not_authenticated", () =>
    verifyDocumentVersion(VERSION_UUID),
  );

  assert.equal(client.queries.length, 0);
  assert.equal(readRequests.length, 0);
});

test("[6] non-member (RLS hides the version) -> document_version_not_found, chain never contacted", async () => {
  const client = setupDb({
    version: VERSION_ROW,
    hideVersion: true,
    evidence: EVIDENCE_ROW,
    anchor: anchorRow(),
  });
  scriptedOnChain.read = async () => matchedOnChain;

  await expectRejectedKind("document_version_not_found", () =>
    verifyDocumentVersion(VERSION_UUID),
  );

  assert.equal(readRequests.length, 0);
  assert.equal(client.calls.length, 0);
});

test("[7] version's evidence is invisible -> evidence_not_found", async () => {
  setupDb({
    version: VERSION_ROW,
    evidence: EVIDENCE_ROW,
    hideEvidence: true,
    anchor: anchorRow(),
  });
  scriptedOnChain.read = async () => matchedOnChain;

  await expectRejectedKind("evidence_not_found", () =>
    verifyDocumentVersion(VERSION_UUID),
  );
});

test("[8] nonexistent version -> document_version_not_found", async () => {
  setupDb({ version: null, evidence: EVIDENCE_ROW, anchor: anchorRow() });
  scriptedOnChain.read = async () => matchedOnChain;

  await expectRejectedKind("document_version_not_found", () =>
    verifyDocumentVersion(VERSION_UUID),
  );
});

test("[9] DB says anchored but the chain slot is empty -> not_anchored: the chain is authoritative", async () => {
  setupDb({ version: VERSION_ROW, evidence: EVIDENCE_ROW, anchor: anchorRow() });
  scriptedOnChain.read = async () => absentOnChain;

  const frame = await verifyDocumentVersion(VERSION_UUID);

  assert.equal(frame.status, "not_anchored");
  // The DB row is only contextual; it cannot override the chain read.
  assert.equal(frame.databaseAnchor?.status, "anchored");
});

test("[10] on-chain verify() disagrees -> hash_mismatch", async () => {
  setupDb({ version: VERSION_ROW, evidence: EVIDENCE_ROW, anchor: anchorRow() });
  scriptedOnChain.read = async () => ({ ...matchedOnChain, verified: false });

  const frame = await verifyDocumentVersion(VERSION_UUID);

  assert.equal(frame.status, "hash_mismatch");
  assert.equal(frame.blockchain?.storedSha256, SHA256_BYTES32);
});

test("[11] reconciled anchor with tx_hash = NULL -> verified, and the NULL pass-through is never fabricated", async () => {
  setupDb({
    version: VERSION_ROW,
    evidence: EVIDENCE_ROW,
    anchor: anchorRow({ tx_hash: null }),
  });
  scriptedOnChain.read = async () => matchedOnChain;

  const frame = await verifyDocumentVersion(VERSION_UUID);

  assert.equal(frame.status, "verified");
  assert.equal(frame.databaseAnchor?.txHash, null);
  assert.equal("txHash" in (frame.blockchain ?? {}), false);
});

test("[12] an invalid document version id is rejected before any client, DB, or chain interaction", async () => {
  clientHolder.current = null;
  scriptedOnChain.read = async () => matchedOnChain;

  await expectRejectedKind("invalid_request", () =>
    verifyDocumentVersion("not-a-uuid"),
  );

  assert.equal(readRequests.length, 0);
});

test("a DB read failure is a database_error, never a blockchain verdict", async () => {
  setupDb({ version: VERSION_ROW, tableError: "document_versions" });
  scriptedOnChain.read = async () => matchedOnChain;

  await expectRejectedKind("database_error", () =>
    verifyDocumentVersion(VERSION_UUID),
  );
});

test("a non-BlockchainAnchorError from the chain is rethrown, never masked as ambiguous", async () => {
  setupDb({ version: VERSION_ROW, evidence: EVIDENCE_ROW, anchor: anchorRow() });
  scriptedOnChain.read = async () => {
    throw new Error("internal bug");
  };

  let caught: unknown = null;
  try {
    await verifyDocumentVersion(VERSION_UUID);
  } catch (raw) {
    caught = raw;
  }
  assert.ok(caught instanceof Error);
  assert.equal((caught as Error).message, "internal bug");
  assert.equal((caught as Error).constructor.name, "Error");
});

test("verification never performs any blockchain WRITE and never touches an RPC", async () => {
  const client = setupDb({
    version: VERSION_ROW,
    evidence: EVIDENCE_ROW,
    anchor: null,
  });
  scriptedOnChain.read = async () => absentOnChain;

  const frame = await verifyDocumentVersion(VERSION_UUID);

  assert.equal(frame.status, "not_anchored");
  assert.equal(anchorEvidenceCalls, 0);
  assert.equal(client.calls.length, 0);
  // Only the three read queries (version, evidence, anchor context) are made.
  assert.deepEqual(
    client.queries.map((q) => q.table),
    ["document_versions", "evidence", "blockchain_anchors"],
  );
});