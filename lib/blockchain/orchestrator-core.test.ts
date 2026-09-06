// Unit tests for the pure blockchain orchestration decision logic.
// Uses Node's built-in test runner (node:test) — no extra dependencies and no
// DB/blockchain/network access. The test UUIDs are distinct from the live,
// already-anchored Sepolia pair.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  AnchorOrchestrationError,
  blockTimestampToIso,
  buildReconcileParams,
  classifyOnChainState,
  isValidDocumentVersionId,
  parseCreateAnchorResult,
  planAnchorAttempt,
  readTransitioned,
  type CreateAnchorOutcome,
} from "./orchestrator-core.ts";

// Test fixtures (NOT the live, already-anchored pair).
const EVIDENCE_UUID = "12345678-1234-4234-8234-123456789abc";
const VERSION_UUID = "abcdefab-cdef-4abc-8def-123456789012";
const ANCHOR_ID = "aaaaaaaa-1111-4111-8111-111111111111";
const SHA256_HEX =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const SHA256_BYTES32 = `0x${SHA256_HEX}`;

// ---- isValidDocumentVersionId ----------------------------------------------

test("isValidDocumentVersionId accepts a canonical UUID", () => {
  assert.equal(isValidDocumentVersionId(VERSION_UUID), true);
});

test("isValidDocumentVersionId accepts uppercase UUIDs", () => {
  assert.equal(isValidDocumentVersionId(VERSION_UUID.toUpperCase()), true);
});

test("isValidDocumentVersionId rejects non-UUID input", () => {
  assert.equal(isValidDocumentVersionId("not-a-uuid"), false);
  assert.equal(isValidDocumentVersionId(""), false);
  assert.equal(isValidDocumentVersionId(`${VERSION_UUID}g`), false);
});

// ---- blockTimestampToIso ---------------------------------------------------

test("blockTimestampToIso converts bigint seconds to an ISO timestamptz", () => {
  assert.equal(
    blockTimestampToIso(1_700_000_000n),
    "2023-11-14T22:13:20.000Z",
  );
});

test("blockTimestampToIso handles the epoch", () => {
  assert.equal(blockTimestampToIso(0n), "1970-01-01T00:00:00.000Z");
});

test("blockTimestampToIso rejects negative timestamps", () => {
  assert.throws(() => blockTimestampToIso(-1n), AnchorOrchestrationError);
});

test("blockTimestampToIso rejects absurd out-of-range timestamps", () => {
  assert.throws(() => blockTimestampToIso(87_000_000_000n), AnchorOrchestrationError);
});

// ---- parseCreateAnchorResult -----------------------------------------------

function anchorRow(overrides: Record<string, unknown> = {}) {
  return {
    id: ANCHOR_ID,
    status: "pending",
    evidence_id: EVIDENCE_UUID,
    document_version_id: VERSION_UUID,
    evidence_sha256: SHA256_HEX,
    ...overrides,
  };
}

test("parseCreateAnchorResult parses a fresh pending anchor (reused=false)", () => {
  const result = parseCreateAnchorResult(
    { anchor: anchorRow(), reused: false },
    VERSION_UUID,
  );
  assert.deepEqual(result, {
    kind: "pending",
    anchorId: ANCHOR_ID,
    reused: false,
    evidenceId: EVIDENCE_UUID,
    documentVersionId: VERSION_UUID,
    evidenceSha256: SHA256_HEX,
  });
});

test("parseCreateAnchorResult parses a reused pending anchor (reused=true)", () => {
  const result = parseCreateAnchorResult(
    { anchor: anchorRow(), reused: true },
    VERSION_UUID,
  );
  assert.equal(result.kind, "pending");
  if (result.kind === "pending") {
    assert.equal(result.anchorId, ANCHOR_ID);
    assert.equal(result.reused, true);
  }
});

test("parseCreateAnchorResult rejects a malformed anchor id", () => {
  assert.throws(
    () =>
      parseCreateAnchorResult(
        { anchor: anchorRow({ id: "not-a-uuid" }), reused: false },
        VERSION_UUID,
      ),
    AnchorOrchestrationError,
  );
});

test("parseCreateAnchorResult treats an anchored row as already_anchored", () => {
  const result = parseCreateAnchorResult(
    { anchor: anchorRow({ status: "anchored" }) },
    VERSION_UUID,
  );
  assert.deepEqual(result, { kind: "already_anchored" });
});

test("parseCreateAnchorResult rejects an unexpected status", () => {
  assert.throws(
    () =>
      parseCreateAnchorResult(
        { anchor: anchorRow({ status: "weird" }) },
        VERSION_UUID,
      ),
    AnchorOrchestrationError,
  );
});

test("parseCreateAnchorResult rejects a malformed result (missing anchor)", () => {
  assert.throws(() => parseCreateAnchorResult({ reused: false }, VERSION_UUID), AnchorOrchestrationError);
});

test("parseCreateAnchorResult rejects when document_version_id does not match the requested id", () => {
  const wrongVersion = "11111111-2222-4333-8444-555555555555";
  assert.throws(
    () => parseCreateAnchorResult({ anchor: anchorRow(), reused: false }, wrongVersion),
    AnchorOrchestrationError,
  );
});

test("parseCreateAnchorResult accepts the authoritative v_anchor even when the input case differs", () => {
  const result = parseCreateAnchorResult(
    { anchor: anchorRow({ document_version_id: VERSION_UUID.toUpperCase() }), reused: false },
    VERSION_UUID,
  );
  assert.equal(result.kind, "pending");
});

// ---- classifyOnChainState --------------------------------------------------

const okOnChain = {
  exists: true,
  storedSha256: SHA256_BYTES32,
  anchoredAt: 1_700_000_000n,
  blockNumber: 19_000_000n,
  verified: true,
};

const OTHER_HASH =
  "0x1111111111111111111111111111111111111111111111111111111111111111";

test("classifyOnChainState returns absent when the slot is empty", () => {
  assert.equal(
    classifyOnChainState({ ...okOnChain, exists: false }, SHA256_BYTES32),
    "absent",
  );
});

test("classifyOnChainState returns matched when the slot holds our exact hash and verify() is true", () => {
  assert.equal(classifyOnChainState(okOnChain, SHA256_BYTES32), "matched");
});

test("classifyOnChainState returns mismatched when the stored hash differs", () => {
  assert.equal(
    classifyOnChainState({ ...okOnChain, storedSha256: OTHER_HASH }, SHA256_BYTES32),
    "mismatched",
  );
});

test("classifyOnChainState returns mismatched when verify() disagrees", () => {
  assert.equal(
    classifyOnChainState({ ...okOnChain, verified: false }, SHA256_BYTES32),
    "mismatched",
  );
});

test("classifyOnChainState compares the hash case-insensitively", () => {
  assert.equal(
    classifyOnChainState(
      { ...okOnChain, storedSha256: SHA256_BYTES32.toUpperCase() },
      SHA256_BYTES32,
    ),
    "matched",
  );
});

// ---- buildReconcileParams --------------------------------------------------

test("buildReconcileParams uses only the on-chain block metadata (req 10: no tx hash)", () => {
  const params = buildReconcileParams(ANCHOR_ID, okOnChain);
  assert.deepEqual(params, {
    p_anchor_id: ANCHOR_ID,
    p_block_number: 19_000_000n,
    p_anchored_at: "2023-11-14T22:13:20.000Z",
  });
  assert.equal("p_tx_hash" in params, false);
});

test("buildReconcileParams rejects an on-chain record without a block number", () => {
  assert.throws(
    () => buildReconcileParams(ANCHOR_ID, { ...okOnChain, blockNumber: 0n }),
    AnchorOrchestrationError,
  );
});

test("buildReconcileParams rejects an on-chain record without an anchor timestamp", () => {
  assert.throws(
    () => buildReconcileParams(ANCHOR_ID, { ...okOnChain, anchoredAt: 0n }),
    AnchorOrchestrationError,
  );
});

// ---- planAnchorAttempt (the reconcile-first decision gate) -----------------

function pendingCreated(overrides: { reused?: boolean } = {}): CreateAnchorOutcome {
  return {
    kind: "pending",
    anchorId: ANCHOR_ID,
    reused: overrides.reused ?? false,
    evidenceId: EVIDENCE_UUID,
    documentVersionId: VERSION_UUID,
    evidenceSha256: SHA256_HEX,
  };
}

test("[1] pending + matched on-chain -> reconcile, never broadcast", () => {
  assert.deepEqual(planAnchorAttempt(pendingCreated(), okOnChain, SHA256_BYTES32), {
    phase: "reconcile",
  });
});

test("[2] pending + absent on-chain -> broadcast (normal anchor proceeds)", () => {
  assert.deepEqual(
    planAnchorAttempt(
      pendingCreated(),
      { ...okOnChain, exists: false },
      SHA256_BYTES32,
    ),
    { phase: "broadcast" },
  );
});

test("[3] pending + mismatched slot -> mark failed for review, never anchored", () => {
  const plan = planAnchorAttempt(
    pendingCreated(),
    { ...okOnChain, storedSha256: OTHER_HASH },
    SHA256_BYTES32,
  );
  assert.equal(plan.phase, "mark_failed_verification");
  assert.match(plan.message, /different evidence hash/);
});

test("[4] pending + chain READ failure (null) -> verification_ambiguous, do nothing", () => {
  const plan = planAnchorAttempt(pendingCreated(), null, SHA256_BYTES32);
  assert.equal(plan.phase, "verification_ambiguous");
  assert.notEqual(plan.phase, "broadcast");
  assert.notEqual(plan.phase, "mark_failed_verification");
});

test("[5] a db_sync-failed retry recovers via reconciliation with no second broadcast", () => {
  // After db_sync_failed the row STAYS pending; the retry's chain read is
  // matched, so it plans reconcile and builds only the block-metadata RPC
  // params — the exact primitive that converges the row without another tx.
  assert.equal(planAnchorAttempt(pendingCreated(), okOnChain, SHA256_BYTES32).phase, "reconcile");
  const params = buildReconcileParams(ANCHOR_ID, okOnChain);
  assert.equal("p_tx_hash" in params, false);
});

test("[6] a retry after a reconcile does NOT broadcast (row is now anchored)", () => {
  // create_blockchain_anchor returns already_anchored for the now-terminal row.
  assert.deepEqual(
    planAnchorAttempt({ kind: "already_anchored" }, okOnChain, SHA256_BYTES32),
    { phase: "already_anchored" },
  );
});

test("[7] reconcile params carry no caller identity (authorization is session-derived)", () => {
  const params = buildReconcileParams(ANCHOR_ID, okOnChain);
  assert.deepEqual(Object.keys(params).sort(), [
    "p_anchor_id",
    "p_anchored_at",
    "p_block_number",
  ]);
});

test("[8] an already-anchored DB row stays terminal regardless of chain state", () => {
  for (const onChain of [
    okOnChain,
    { ...okOnChain, exists: false },
    { ...okOnChain, storedSha256: OTHER_HASH },
  ]) {
    assert.equal(
      planAnchorAttempt({ kind: "already_anchored" }, onChain, SHA256_BYTES32).phase,
      "already_anchored",
    );
  }
});

test("[9] a failed row's retry (reused pending slot) proceeds safely by chain state", () => {
  // create_blockchain_anchor resets a failed row to pending (reused=true); the
  // plan then routes exactly like any other pending row.
  const reused = pendingCreated({ reused: true });
  assert.equal(
    planAnchorAttempt(reused, { ...okOnChain, exists: false }, SHA256_BYTES32).phase,
    "broadcast",
  );
  assert.equal(planAnchorAttempt(reused, okOnChain, SHA256_BYTES32).phase, "reconcile");
});

// ---- readTransitioned ------------------------------------------------------

test("readTransitioned returns true when the RPC reports a transition", () => {
  assert.equal(readTransitioned({ transitioned: true }), true);
});

test("readTransitioned returns false when the RPC reports no transition", () => {
  assert.equal(readTransitioned({ transitioned: false }), false);
});

test("readTransitioned returns false for malformed data", () => {
  assert.equal(readTransitioned(null), false);
  assert.equal(readTransitioned(undefined), false);
  assert.equal(readTransitioned({ transitioned: "yes" }), false);
  assert.equal(readTransitioned([]), false);
});