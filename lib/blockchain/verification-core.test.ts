// Unit tests for the pure blockchain verification classification/body logic.
// Uses Node's built-in test runner (node:test) — no DB/blockchain/network. The
// test UUIDs are distinct from the live, already-anchored Sepolia pair.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  classifyVerificationState,
  verificationBody,
  verificationErrorStatus,
  type OnChainVerificationState,
} from "./verification-core.ts";

const EVIDENCE_UUID = "12345678-1234-4234-8234-123456789abc";
const VERSION_UUID = "abcdefab-cdef-4abc-8def-123456789012";
const SHA256_HEX =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const SHA256_BYTES32 = `0x${SHA256_HEX}`;
const OTHER_HASH =
  "0x1111111111111111111111111111111111111111111111111111111111111111";
const ANCHORED_AT_ISO = "2023-11-14T22:13:20.000Z";

const EVIDENCE_HASH = `0x00000000000000000000000000000000${EVIDENCE_UUID.replace(
  /-/g,
  "",
)}`;
const VERSION_HASH = `0x00000000000000000000000000000000${VERSION_UUID.replace(
  /-/g,
  "",
)}`;

const okOnChain: OnChainVerificationState = {
  exists: true,
  storedSha256: SHA256_BYTES32,
  anchoredAt: 1_700_000_000n,
  blockNumber: 19_000_000n,
  verified: true,
};

const emptyOnChain: OnChainVerificationState = {
  exists: false,
  storedSha256: `0x${"0".repeat(64)}`,
  anchoredAt: 0n,
  blockNumber: 0n,
  verified: false,
};

// ---- classifyVerificationState -----------------------------------------------

test("classifyVerificationState: matching anchor + verify() true -> verified", () => {
  assert.equal(classifyVerificationState(okOnChain, SHA256_BYTES32), "verified");
});

test("classifyVerificationState: empty slot -> not_anchored (never verified)", () => {
  assert.equal(
    classifyVerificationState(emptyOnChain, SHA256_BYTES32),
    "not_anchored",
  );
});

test("classifyVerificationState: stored hash differs -> hash_mismatch", () => {
  assert.equal(
    classifyVerificationState(
      { ...okOnChain, storedSha256: OTHER_HASH },
      SHA256_BYTES32,
    ),
    "hash_mismatch",
  );
});

test("classifyVerificationState: verify() disagrees -> hash_mismatch", () => {
  assert.equal(
    classifyVerificationState({ ...okOnChain, verified: false }, SHA256_BYTES32),
    "hash_mismatch",
  );
});

test("classifyVerificationState compares the hash case-insensitively", () => {
  assert.equal(
    classifyVerificationState(
      { ...okOnChain, storedSha256: SHA256_BYTES32.toUpperCase() },
      SHA256_BYTES32,
    ),
    "verified",
  );
});

// ---- verificationBody --------------------------------------------------------

const baseFrame = {
  status: "verified" as const,
  documentVersionId: VERSION_UUID,
  evidenceId: EVIDENCE_UUID,
  caseId: "22222222-2222-4222-8222-222222222222",
  databaseSha256: SHA256_HEX,
};

test("verificationBody exposes the full verified state with the derived hash encodings", () => {
  const body = verificationBody({
    ...baseFrame,
    blockchain: {
      evidenceIdHash: EVIDENCE_HASH,
      versionIdHash: VERSION_HASH,
      expectedSha256: SHA256_BYTES32,
      exists: true,
      storedSha256: SHA256_BYTES32,
      anchoredAt: ANCHORED_AT_ISO,
      blockNumber: 19_000_000,
      network: "sepolia",
      chainId: 11155111,
      contractAddress: "0x1D76cea78A844fed9aca674C82a900917e848b1a",
    },
    databaseAnchor: {
      status: "anchored",
      txHash: `0x${"a".repeat(64)}`,
      blockNumber: 19_000_000,
      anchoredAt: ANCHORED_AT_ISO,
      network: "sepolia",
      chainId: 11155111,
      contractAddress: "0x1D76cea78A844fed9aca674C82a900917e848b1a",
    },
  });

  assert.deepEqual(body, {
    status: "verified",
    document_version_id: VERSION_UUID,
    evidence_id: EVIDENCE_UUID,
    case_id: "22222222-2222-4222-8222-222222222222",
    database_sha256: SHA256_HEX,
    blockchain: {
      evidence_id_hash: EVIDENCE_HASH,
      version_id_hash: VERSION_HASH,
      expected_sha256: SHA256_BYTES32,
      exists: true,
      stored_sha256: SHA256_BYTES32,
      anchored_at: ANCHORED_AT_ISO,
      block_number: 19_000_000,
      network: "sepolia",
      chain_id: 11155111,
      contract_address: "0x1D76cea78A844fed9aca674C82a900917e848b1a",
    },
    database_anchor: {
      status: "anchored",
      tx_hash: `0x${"a".repeat(64)}`,
      block_number: 19_000_000,
      anchored_at: ANCHORED_AT_ISO,
      network: "sepolia",
      chain_id: 11155111,
      contract_address: "0x1D76cea78A844fed9aca674C82a900917e848b1a",
    },
  });
});

test("verificationBody not_anchored has null on-chain facts but keeps contract info", () => {
  const body = verificationBody({
    ...baseFrame,
    status: "not_anchored",
    blockchain: {
      evidenceIdHash: EVIDENCE_HASH,
      versionIdHash: VERSION_HASH,
      expectedSha256: SHA256_BYTES32,
      exists: false,
      storedSha256: null,
      anchoredAt: null,
      blockNumber: null,
      network: "sepolia",
      chainId: 11155111,
      contractAddress: "0x1D76cea78A844fed9aca674C82a900917e848b1a",
    },
    databaseAnchor: null,
  });

  assert.equal(body.status, "not_anchored");
  assert.equal((body.blockchain as Record<string, unknown>).exists, false);
  assert.equal((body.blockchain as Record<string, unknown>).stored_sha256, null);
  assert.equal((body.blockchain as Record<string, unknown>).block_number, null);
  assert.equal((body.blockchain as Record<string, unknown>).anchored_at, null);
  assert.equal((body.blockchain as Record<string, unknown>).contract_address,
    "0x1D76cea78A844fed9aca674C82a900917e848b1a");
  assert.equal(body.database_anchor, null);
  assert.equal("message" in body, false);
});

test("verificationBody passes a reconciled NULL tx_hash through as null (never fabricated)", () => {
  const body = verificationBody({
    ...baseFrame,
    blockchain: null,
    databaseAnchor: {
      status: "anchored",
      txHash: null,
      blockNumber: 19_000_000,
      anchoredAt: ANCHORED_AT_ISO,
      network: "sepolia",
      chainId: 11155111,
      contractAddress: "0x1D76cea78A844fed9aca674C82a900917e848b1a",
    },
  });

  assert.equal((body.database_anchor as Record<string, unknown>).tx_hash, null);
  const blockchain = (body as { blockchain: Record<string, unknown> | null }).blockchain;
  assert.ok(blockchain === null || !("tx_hash" in blockchain));
});

test("verificationBody hash_mismatch carries the integrity message and no fabricated facts", () => {
  const body = verificationBody({
    ...baseFrame,
    status: "hash_mismatch",
    blockchain: {
      evidenceIdHash: EVIDENCE_HASH,
      versionIdHash: VERSION_HASH,
      expectedSha256: SHA256_BYTES32,
      exists: true,
      storedSha256: OTHER_HASH,
      anchoredAt: ANCHORED_AT_ISO,
      blockNumber: 19_000_000,
      network: "sepolia",
      chainId: 11155111,
      contractAddress: "0x1D76cea78A844fed9aca674C82a900917e848b1a",
    },
    databaseAnchor: null,
    message: "The on-chain anchor SHA-256 does not match this document version's SHA-256",
  });

  assert.equal(body.status, "hash_mismatch");
  assert.equal(body.message, "The on-chain anchor SHA-256 does not match this document version's SHA-256");
  assert.equal((body.blockchain as Record<string, unknown>).stored_sha256, OTHER_HASH);
});

test("verificationBody verification_ambiguous exposes a bounded message and no chain facts", () => {
  const body = verificationBody({
    ...baseFrame,
    status: "verification_ambiguous",
    blockchain: null,
    databaseAnchor: null,
    message: "Unable to reach the blockchain network",
  });

  assert.equal(body.status, "verification_ambiguous");
  assert.equal(body.blockchain, null);
  assert.equal(body.message, "Unable to reach the blockchain network");
});

// ---- verificationErrorStatus --------------------------------------------------

test("verificationErrorStatus maps verification error kinds to HTTP statuses", () => {
  assert.deepEqual(
    verificationErrorStatus({ kind: "invalid_request", message: "m" }),
    { status: 400, error: "m" },
  );
  assert.deepEqual(
    verificationErrorStatus({ kind: "not_authenticated", message: "m" }),
    { status: 401, error: "m" },
  );
  assert.deepEqual(
    verificationErrorStatus({ kind: "document_version_not_found", message: "m" }),
    { status: 404, error: "m" },
  );
  assert.deepEqual(
    verificationErrorStatus({ kind: "evidence_not_found", message: "m" }),
    { status: 404, error: "m" },
  );
  assert.deepEqual(
    verificationErrorStatus({ kind: "database_error", message: "m" }),
    { status: 500, error: "m" },
  );
  assert.deepEqual(
    verificationErrorStatus(new Error("boom")),
    { status: 500, error: "Unexpected error" },
  );
});

test("auth failures never map to a successful 2xx", () => {
  assert.notEqual(
    verificationErrorStatus({ kind: "not_authenticated", message: "m" }).status,
    200,
  );
  assert.notEqual(
    verificationErrorStatus({ kind: "document_version_not_found", message: "m" }).status,
    200,
  );
});