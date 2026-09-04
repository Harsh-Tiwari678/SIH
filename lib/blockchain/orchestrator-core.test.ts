// Unit tests for the pure blockchain orchestration decision logic.
// Uses Node's built-in test runner (node:test) — no extra dependencies and no
// DB/blockchain/network access. The test UUIDs are distinct from the live,
// already-anchored Sepolia pair.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  AnchorOrchestrationError,
  blockTimestampToIso,
  decideVerification,
  isValidDocumentVersionId,
  parseCreateAnchorResult,
  readTransitioned,
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

// ---- decideVerification ----------------------------------------------------

const okOnChain = {
  exists: true,
  storedSha256: SHA256_BYTES32,
  anchoredAt: 1_700_000_000n,
  blockNumber: 19_000_000n,
  verified: true,
};

test("decideVerification returns ok when the stored anchor matches and verify() is true", () => {
  assert.equal(decideVerification(okOnChain, SHA256_BYTES32), "ok");
});

test("decideVerification returns mismatch when the on-chain entry does not exist", () => {
  assert.equal(
    decideVerification({ ...okOnChain, exists: false }, SHA256_BYTES32),
    "mismatch",
  );
});

test("decideVerification returns mismatch when the stored hash differs", () => {
  const otherHash =
    "0x1111111111111111111111111111111111111111111111111111111111111111";
  assert.equal(decideVerification({ ...okOnChain, storedSha256: otherHash }, SHA256_BYTES32), "mismatch");
});

test("decideVerification returns mismatch when verify() is false", () => {
  assert.equal(
    decideVerification({ ...okOnChain, verified: false }, SHA256_BYTES32),
    "mismatch",
  );
});

test("decideVerification compares the hash case-insensitively", () => {
  assert.equal(
    decideVerification({ ...okOnChain, storedSha256: SHA256_BYTES32.toUpperCase() }, SHA256_BYTES32),
    "ok",
  );
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