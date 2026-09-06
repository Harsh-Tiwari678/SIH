// Unit tests for the pure EvidenceAnchor bytes32 encoding helpers.
// Uses Node's built-in test runner (node:test) — no extra dependencies.
// These tests ONLY exercise the pure encoding functions and never contact the
// blockchain. The UUIDs below are distinct from the already-used live pairs.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  EncodingError,
  isValidUuid,
  isValidSha256,
  uuidToBytes32,
  sha256ToBytes32,
} from "./encoding.ts";

// Test fixtures (NOT the live, already-anchored pair).
const EVIDENCE_UUID = "12345678-1234-4234-8234-123456789abc";
const VERSION_UUID = "abcdefab-cdef-4abc-8def-123456789012";

// Expected: each UUID's hex (dashes removed), lowercased, left-padded to 64.
const EVIDENCE_HEX = "12345678123442348234123456789abc".toLowerCase();
const VERSION_HEX = "abcdefabcdef4abc8def123456789012";

const SHA256_HEX =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

test("valid UUID converts to the exact expected bytes32", () => {
  const expected = `0x${EVIDENCE_HEX.padStart(64, "0")}`;
  assert.equal(uuidToBytes32(EVIDENCE_UUID), expected);
});

test("uppercase UUID is accepted and normalized to lowercase bytes32", () => {
  const upper = EVIDENCE_UUID.toUpperCase();
  const lower = EVIDENCE_HEX.toLowerCase();
  assert.equal(uuidToBytes32(upper), `0x${lower.padStart(64, "0")}`);
  assert.equal(isValidUuid(upper), true);
});

test("invalid UUID is rejected by uuidToBytes32", () => {
  const bad = `${EVIDENCE_UUID}g`; // g is not hex
  assert.equal(isValidUuid(bad), false);
  assert.throws(() => uuidToBytes32(bad), EncodingError);
});

test("UUID with wrong length is rejected", () => {
  const short = "12345678-1234-4234-8234";
  assert.equal(isValidUuid(short), false);
  assert.throws(() => uuidToBytes32(short), EncodingError);
});

test("valid lowercase SHA-256 converts to the exact expected bytes32", () => {
  assert.equal(sha256ToBytes32(SHA256_HEX), `0x${SHA256_HEX}`);
  assert.equal(isValidSha256(SHA256_HEX), true);
});

test("uppercase SHA-256 is rejected", () => {
  const upper = SHA256_HEX.toUpperCase();
  assert.equal(isValidSha256(upper), false);
  assert.throws(() => sha256ToBytes32(upper), EncodingError);
});

test("wrong SHA-256 length is rejected", () => {
  const short = SHA256_HEX.slice(0, 63);
  assert.equal(isValidSha256(short), false);
  assert.throws(() => sha256ToBytes32(short), EncodingError);
});

test("invalid SHA-256 characters are rejected", () => {
  const bad = `g${SHA256_HEX.slice(1)}`; // 'g' is not hex
  assert.equal(isValidSha256(bad), false);
  assert.throws(() => sha256ToBytes32(bad), EncodingError);
});

test("version UUID also converts to the exact expected bytes32", () => {
  const expected = `0x${VERSION_HEX.padStart(64, "0")}`;
  assert.equal(uuidToBytes32(VERSION_UUID), expected);
});
