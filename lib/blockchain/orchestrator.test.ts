// End-to-end orchestrator tests for the reconcile-first anchor lifecycle.
//
// These exercise the REAL anchorDocumentVersion() (lib/blockchain/orchestrator.ts)
// against a stubbed blockchain service (!./anchor.ts is mock.module'd) and a
// scripted Supabase RPC client (the "@/lib/supabase/server" alias is mapped to
// test-support/supabase-server-stub.ts by test-support/test-loader.mjs).
//
// No real Ethereum transaction, no network, no database. The critical property
// under test: the retry-after-chain-success/DB-failure scenario can never
// create a second on-chain transaction, and a transaction hash is never
// fabricated.
//
// Run via: npm test  (package.json wires the loader + module-mock flags).

import { mock, test } from "node:test";
import assert from "node:assert/strict";
import { BlockchainAnchorError, ERROR_CATEGORY_MESSAGES } from "./errors.ts";
import { AnchorOrchestrationError } from "./orchestrator-core.ts";
import {
  clientHolder,
  makeFakeClient,
  type FakeSupabaseClient,
  type RpcHandler,
} from "./test-support/supabase-server-stub.ts";

// ---- fixtures (NOT the live, already-anchored Sepolia pair) --------------

const EVIDENCE_UUID = "12345678-1234-4234-8234-123456789abc";
const VERSION_UUID = "abcdefab-cdef-4abc-8def-123456789012";
const ANCHOR_ID = "aaaaaaaa-1111-4111-8111-111111111111";
const SHA256_HEX =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const SHA256_BYTES32 = `0x${SHA256_HEX}`;
const OTHER_HASH =
  "0x1111111111111111111111111111111111111111111111111111111111111111";
const TX_HASH = `0x${"a".repeat(64)}`;
const ISO_ANCHORED_AT = "2023-11-14T22:13:20.000Z";

const BLOCK_NUMBER = 19_000_000n;
const ANCHORED_AT = 1_700_000_000n;

function pendingCreated(reused = false) {
  return {
    anchor: {
      id: ANCHOR_ID,
      status: "pending",
      evidence_id: EVIDENCE_UUID,
      document_version_id: VERSION_UUID,
      evidence_sha256: SHA256_HEX,
    },
    reused,
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

const confirmation = {
  txHash: TX_HASH,
  blockNumber: BLOCK_NUMBER + 1n,
  anchoredAt: ANCHORED_AT,
  evidenceIdHash: `0x00000000000000000000000000000000${EVIDENCE_UUID.replace(/-/g, "")}`,
  versionIdHash: `0x00000000000000000000000000000000${VERSION_UUID.replace(/-/g, "")}`,
  evidenceSha256: SHA256_BYTES32,
};

// ---- blockchain service stubs ---------------------------------------------

let anchorEvidenceCalls = 0;
let getOnChainCalls = 0;
let totalAnchorEvidenceCalls = 0; // never reset: cumulative across attempts
let anchorEvidenceImpl: () => Promise<typeof confirmation>;
let getOnChainImpl: () => Promise<typeof matchedOnChain>;

function neverCalled(name: string): never {
  throw new Error(`${name} must not be called in this scenario`);
}

mock.module(new URL("./anchor.ts", import.meta.url).href, {
  namedExports: {
    anchorEvidence: () => {
      anchorEvidenceCalls += 1;
      totalAnchorEvidenceCalls += 1;
      return anchorEvidenceImpl();
    },
    getOnChainAnchor: () => {
      getOnChainCalls += 1;
      return getOnChainImpl();
    },
  },
});

// Load the real orchestrator AFTER the mocks are registered (static imports
// would be hoisted above the mock registration and defeat it).
const { anchorDocumentVersion } = await import("./orchestrator.ts");

// ---- helpers ---------------------------------------------------------------

function setup(handlers: Record<string, RpcHandler>): FakeSupabaseClient {
  anchorEvidenceCalls = 0;
  getOnChainCalls = 0;
  const client = makeFakeClient();
  for (const [name, handler] of Object.entries(handlers)) {
    client.handlers.set(name, handler);
  }
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
    caught instanceof AnchorOrchestrationError,
    `expected AnchorOrchestrationError, got ${String(caught)}`,
  );
  assert.equal((caught as AnchorOrchestrationError).kind, kind);
}

// ---- scenarios -------------------------------------------------------------

test("[1] pending + matching chain anchor -> reconciled (never broadcast)", async () => {
  setup({
    create_blockchain_anchor: () => ({ data: pendingCreated(), error: null }),
    reconcile_anchor_anchored: () => ({ data: { transitioned: true }, error: null }),
  });
  anchorEvidenceImpl = () => neverCalled("anchorEvidence");
  getOnChainImpl = async () => matchedOnChain;

  const outcome = await anchorDocumentVersion(VERSION_UUID);

  assert.deepEqual(outcome, {
    status: "reconciled",
    anchorId: ANCHOR_ID,
    blockNumber: Number(BLOCK_NUMBER),
    anchoredAt: ISO_ANCHORED_AT,
  });
  assert.equal(anchorEvidenceCalls, 0);
  assert.equal(getOnChainCalls, 1);
});

test("[2] the reconciled path performs ZERO broadcast calls", async () => {
  const client = setup({
    create_blockchain_anchor: () => ({ data: pendingCreated(), error: null }),
    reconcile_anchor_anchored: () => ({ data: { transitioned: true }, error: null }),
  });
  anchorEvidenceImpl = () => neverCalled("anchorEvidence");
  getOnChainImpl = async () => matchedOnChain;

  const outcome = await anchorDocumentVersion(VERSION_UUID);

  assert.equal(outcome.status, "reconciled");
  assert.equal(anchorEvidenceCalls, 0);
  // The only RPCs the DB boundary ever sees are create + reconcile.
  const mutators = client.calls.filter((c) => c.fn !== "create_blockchain_anchor");
  assert.deepEqual(
    mutators.map((c) => c.fn),
    ["reconcile_anchor_anchored"],
  );
});

test("[10] reconciliation never fabricates a transaction hash", async () => {
  const client = setup({
    create_blockchain_anchor: () => ({ data: pendingCreated(), error: null }),
    reconcile_anchor_anchored: () => ({ data: { transitioned: true }, error: null }),
  });
  anchorEvidenceImpl = async () => confirmation;
  getOnChainImpl = async () => matchedOnChain;

  const outcome = await anchorDocumentVersion(VERSION_UUID);

  assert.equal(outcome.status, "reconciled");
  assert.equal("txHash" in outcome, false);
  const reconcile = client.calls.find((c) => c.fn === "reconcile_anchor_anchored");
  assert.ok(reconcile);
  assert.equal("p_tx_hash" in reconcile.params, false);
  assert.deepEqual(
    Object.keys(reconcile.params).sort(),
    ["p_anchor_id", "p_anchored_at", "p_block_number"],
  );
  // anchorEvidence must not even be invokable in this path: the broadcast
  // stub would have returned a hash, and it must never be read.
  assert.equal(anchorEvidenceCalls, 0);
});

test("[3] pending + absent chain -> exactly one broadcast, then anchored", async () => {
  const client = setup({
    create_blockchain_anchor: () => ({ data: pendingCreated(), error: null }),
    mark_anchor_anchored: () => ({ data: { transitioned: true }, error: null }),
  });
  anchorEvidenceImpl = async () => confirmation;
  getOnChainImpl = async () => absentOnChain;

  const outcome = await anchorDocumentVersion(VERSION_UUID);

  assert.deepEqual(outcome, {
    status: "anchored",
    anchorId: ANCHOR_ID,
    txHash: TX_HASH,
    blockNumber: Number(BLOCK_NUMBER + 1n),
    anchoredAt: ISO_ANCHORED_AT,
  });
  assert.equal(anchorEvidenceCalls, 1);
  const mark = client.calls.find((c) => c.fn === "mark_anchor_anchored");
  assert.ok(mark);
  assert.equal(mark.params.p_tx_hash, TX_HASH);
});

test("[4] pending + mismatched chain -> verification_failed, never reconciled, no broadcast", async () => {
  const client = setup({
    create_blockchain_anchor: () => ({ data: pendingCreated(), error: null }),
    mark_anchor_failed: () => ({ data: { transitioned: true }, error: null }),
  });
  anchorEvidenceImpl = () => neverCalled("anchorEvidence");
  getOnChainImpl = async () => ({ ...matchedOnChain, storedSha256: OTHER_HASH });

  const outcome = await anchorDocumentVersion(VERSION_UUID);

  assert.equal(outcome.status, "verification_failed");
  assert.equal(anchorEvidenceCalls, 0);
  assert.equal(client.calls.some((c) => c.fn === "reconcile_anchor_anchored"), false);
  assert.equal(client.calls.some((c) => c.fn === "mark_anchor_anchored"), false);
});

test("[5] pending + chain READ failure -> verification_ambiguous, row untouched, no broadcast", async () => {
  const client = setup({
    create_blockchain_anchor: () => ({ data: pendingCreated(), error: null }),
  });
  anchorEvidenceImpl = () => neverCalled("anchorEvidence");
  getOnChainImpl = async () => {
    throw new BlockchainAnchorError("network_error");
  };

  const outcome = await anchorDocumentVersion(VERSION_UUID);

  assert.deepEqual(outcome, {
    status: "verification_ambiguous",
    anchorId: ANCHOR_ID,
    message: ERROR_CATEGORY_MESSAGES.network_error,
  });
  assert.equal(anchorEvidenceCalls, 0);
  // No DB mutation at all: the row must remain pending for a later retry.
  const mutators = client.calls.filter((c) => c.fn !== "create_blockchain_anchor");
  assert.equal(mutators.length, 0);
});

test("[6] original tx succeeded + DB sync failed -> later retry reconciles with zero second broadcast", async () => {
  // The cumulative broadcast counter spans earlier tests, so capture a delta.
  const broadcastsBefore = totalAnchorEvidenceCalls;

  // Attempt 1: broadcast confirmed on-chain, but mark_anchor_anchored loses
  // the DB write. The orchestrator must surface db_sync_failed and leave the
  // row pending (it must NOT mark it failed).
  const c1 = setup({
    create_blockchain_anchor: () => ({ data: pendingCreated(), error: null }),
    mark_anchor_anchored: () => ({
      data: null,
      error: { message: "database connection lost" },
    }),
  });
  anchorEvidenceImpl = async () => confirmation;
  getOnChainImpl = async () => absentOnChain;

  const first = await anchorDocumentVersion(VERSION_UUID);
  assert.equal(first.status, "db_sync_failed");
  assert.equal(anchorEvidenceCalls, 1);
  assert.equal(c1.calls.some((c) => c.fn === "mark_anchor_failed"), false);

  // Attempt 2 (the retry): DB row is STILL pending; the chain now holds our
  // anchor. The only correct action is reconciliation — never a second
  // broadcast.
  const c2 = setup({
    create_blockchain_anchor: () => ({ data: pendingCreated(true), error: null }),
    reconcile_anchor_anchored: () => ({ data: { transitioned: true }, error: null }),
  });
  getOnChainImpl = async () => matchedOnChain;

  const second = await anchorDocumentVersion(VERSION_UUID);
  assert.deepEqual(second, {
    status: "reconciled",
    anchorId: ANCHOR_ID,
    blockNumber: Number(BLOCK_NUMBER),
    anchoredAt: ISO_ANCHORED_AT,
  });
  // The CORE invariant: across both attempts, the chain saw exactly ONE
  // transaction.
  assert.equal(totalAnchorEvidenceCalls, broadcastsBefore + 1);
  assert.equal(c2.calls.some((c) => c.fn === "mark_anchor_anchored"), false);
});

test("[7] a retry after reconciliation is terminal and never broadcasts again", async () => {
  // Now the row is 'anchored' (reconciled). A further retry must short-circuit
  // at create_blockchain_anchor (already_anchored) — no chain read, no
  // broadcast, no mutation.
  const client = setup({
    create_blockchain_anchor: () => ({
      data: null,
      error: { message: "already_anchored" },
    }),
  });
  getOnChainImpl = () => neverCalled("getOnChainAnchor");
  anchorEvidenceImpl = () => neverCalled("anchorEvidence");

  const outcome = await anchorDocumentVersion(VERSION_UUID);

  assert.deepEqual(outcome, { status: "already_anchored" });
  assert.equal(getOnChainCalls, 0);
  assert.equal(anchorEvidenceCalls, 0);
  assert.equal(client.calls.length, 1); // only the create RPC
});

test("[8] a failed row's retry reuses the pending slot and broadcasts once", async () => {
  setup({
    create_blockchain_anchor: () => ({ data: pendingCreated(true), error: null }),
    mark_anchor_anchored: () => ({ data: { transitioned: true }, error: null }),
  });
  anchorEvidenceImpl = async () => confirmation;
  getOnChainImpl = async () => absentOnChain;

  const outcome = await anchorDocumentVersion(VERSION_UUID);

  assert.equal(outcome.status, "anchored");
  assert.equal(anchorEvidenceCalls, 1);
  assert.equal(getOnChainCalls, 1);
});

test("[9] already-anchored DB row stays terminal regardless of a broadcast-classified plan", async () => {
  // Even when the create RPC returns pending (concurrent terminal transition
  // between create and plan), an already... is handled via the plan gate: here
  // the create RPC reports already_anchored, so nothing on the chain is
  // consulted and nothing is broadcast.
  const client = setup({
    create_blockchain_anchor: () => ({
      data: null,
      error: { message: "already_anchored" },
    }),
  });
  getOnChainImpl = () => neverCalled("getOnChainAnchor");
  anchorEvidenceImpl = () => neverCalled("anchorEvidence");

  const outcome = await anchorDocumentVersion(VERSION_UUID);
  assert.equal(outcome.status, "already_anchored");
  assert.equal(getOnChainCalls, 0);
  assert.equal(anchorEvidenceCalls, 0);
  assert.equal(client.calls.length, 1);
});

test("[race] a conflicting broadcast is reconciled from the re-read, never rebroadcast", async () => {
  // The slot was absent at the pre-broadcast read, but a concurrent request
  // anchored it before our broadcast landed, so anchorEvidence reverts with
  // AlreadyAnchored. The orchestrator must re-read the chain, find OUR hash,
  // and reconcile the pending row — WITHOUT retrying the broadcast.
  const client = setup({
    create_blockchain_anchor: () => ({ data: pendingCreated(), error: null }),
    reconcile_anchor_anchored: () => ({ data: { transitioned: true }, error: null }),
  });
  const reads = [absentOnChain, matchedOnChain];
  getOnChainImpl = async () => reads.shift() ?? neverCalled("getOnChainAnchor");
  anchorEvidenceImpl = async () => {
    throw new BlockchainAnchorError("already_anchored");
  };

  const outcome = await anchorDocumentVersion(VERSION_UUID);

  assert.equal(outcome.status, "reconciled");
  assert.equal("txHash" in outcome, false);
  // One broadcast attempt (reverted by the contract); never a second one.
  assert.equal(anchorEvidenceCalls, 1);
  assert.equal(getOnChainCalls, 2);
  assert.ok(client.calls.some((c) => c.fn === "reconcile_anchor_anchored"));
});

test("[12] unauthorized role is rejected at create and never reaches the chain", async () => {
  const client = setup({
    create_blockchain_anchor: () => ({
      data: null,
      error: { message: "not_authorized_to_anchor: only the case lead may anchor" },
    }),
  });
  getOnChainImpl = () => neverCalled("getOnChainAnchor");
  anchorEvidenceImpl = () => neverCalled("anchorEvidence");

  await expectRejectedKind("not_authorized_to_anchor", () =>
    anchorDocumentVersion(VERSION_UUID),
  );

  assert.equal(getOnChainCalls, 0);
  assert.equal(anchorEvidenceCalls, 0);
  assert.equal(client.calls.length, 1);
});

test("[11] cross-case authorization failure at reconcile surfaces as an error, not a masked sync issue", async () => {
  // The chain holds OUR hash, but the reconcile RPC (which re-derives the
  // actor's role from the anchor's OWN evidence -> case, never from any URL
  // case id) rejects the actor. This must surface as not_authorized_to_anchor
  // (-> 403), NOT be swallowed into a db_sync_failed 202.
  const client = setup({
    create_blockchain_anchor: () => ({ data: pendingCreated(), error: null }),
    reconcile_anchor_anchored: () => ({
      data: null,
      error: { message: "not_authorized_to_anchor: actor not on this evidence's case" },
    }),
  });
  getOnChainImpl = async () => matchedOnChain;
  anchorEvidenceImpl = () => neverCalled("anchorEvidence");

  await expectRejectedKind("not_authorized_to_anchor", () =>
    anchorDocumentVersion(VERSION_UUID),
  );

  assert.equal(anchorEvidenceCalls, 0);
  assert.equal(client.calls.some((c) => c.fn === "mark_anchor_anchored"), false);
});

test("a mark_anchor_anchored authorization rejection is not masked as db_sync_failed", async () => {
  const client = setup({
    create_blockchain_anchor: () => ({ data: pendingCreated(), error: null }),
    mark_anchor_anchored: () => ({
      data: null,
      error: { message: "not_authenticated: session expired" },
    }),
  });
  anchorEvidenceImpl = async () => confirmation;
  getOnChainImpl = async () => absentOnChain;

  await expectRejectedKind("not_authenticated", () =>
    anchorDocumentVersion(VERSION_UUID),
  );

  assert.equal(anchorEvidenceCalls, 1);
  // The on-chain fact is safe: a later retry (fresh session) will read the
  // chain, see the match, and reconcile — so the row must still be pending.
  assert.equal(client.calls.some((c) => c.fn === "mark_anchor_failed"), false);
});