// Unit tests for the create_evidence() hash-registration capability gate.
//
// The server passes the RAW HASH_CONFIRMATION_SECRET to create_evidence();
// the database hashes the token inside PostgreSQL and compares the computed
// digest to its stored verifier.  These tests prove:
//   - the helper returns the raw secret, not its digest (the digest is a
//     public constant and must NOT authenticate);
//   - the raw secret's SHA-256 equals the verifier embedded in migration
//     20260925000000 (the DB-compatible chain the route depends on);
//   - misconfiguration (unset/invalid secret) is surfaced clearly.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { evidenceRegistrationToken } from "@/lib/evidence-registration";
import { sha256Hex } from "@/lib/storage";

// The production verifier embedded in migration 20260925000000 (the SHA-256
// of HASH_CONFIRMATION_SECRET).  It is a VERIFIER, not a bearer token.
const EXPECTED_DIGEST =
  "0b91ed06536d236e343af0ac61392108fa9f55188baa4a19d90c895b63c30781";

const ORIGINAL_SECRET = process.env.HASH_CONFIRMATION_SECRET;

test("evidenceRegistrationToken returns the raw secret, not its digest", async () => {
  // A 64-hex fixture secret distinct from the production one. The returned
  // token must be the RAW value: if it were the digest, sha256Hex(token)
  // would not equal the embedded verifier below and the DB gate would reject
  // it (sha256(digest) <> digest).
  const fixture = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899";
  process.env.HASH_CONFIRMATION_SECRET = fixture;
  try {
    const token = await evidenceRegistrationToken();
    // Token IS the raw secret, not its digest.
    assert.equal(token, fixture);
    assert.match(token, /^[0-9a-f]{64}$/);
    // Non-vacuous proof: the token is NOT its own digest.
    const digestOfToken = await sha256Hex(new TextEncoder().encode(token));
    assert.notEqual(token, digestOfToken);
    // And hashing the token reproduces the DB-compatible verifier of that
    // secret (known-answer: sha256(fixture) — proving the DB-side
    // sha256(token) == verifier chain holds for the exact bytes sent).
    assert.equal(
      digestOfToken,
      "cc765b7d975bb90eb5549c9bf04ba1c18581d76ef8fbdc3ab14947bd5c7db962",
      "sha256(fixture) known-answer mismatch: DB would reject this token",
    );
  } finally {
    if (ORIGINAL_SECRET) process.env.HASH_CONFIRMATION_SECRET = ORIGINAL_SECRET;
    else delete process.env.HASH_CONFIRMATION_SECRET;
  }
});

test("evidenceRegistrationToken throws configuration_error when HASH_CONFIRMATION_SECRET is unset", async () => {
  const saved = process.env.HASH_CONFIRMATION_SECRET;
  delete process.env.HASH_CONFIRMATION_SECRET;
  try {
    await assert.rejects(() => evidenceRegistrationToken(), {
      message: "HASH_CONFIRMATION_SECRET is not configured on the server",
    });
  } finally {
    if (saved) process.env.HASH_CONFIRMATION_SECRET = saved;
  }
});

test("evidenceRegistrationToken throws configuration_error when HASH_CONFIRMATION_SECRET is not a 64-hex value", async () => {
  const saved = process.env.HASH_CONFIRMATION_SECRET;
  process.env.HASH_CONFIRMATION_SECRET = "obviously-not-a-hex-secret";
  try {
    await assert.rejects(() => evidenceRegistrationToken(), {
      message: "HASH_CONFIRMATION_SECRET must be a 64-character hex value",
    });
  } finally {
    if (saved) process.env.HASH_CONFIRMATION_SECRET = saved;
  }
});

test("the raw .env.local secret hashes to the verifier embedded in the migration", async () => {
  // Reads the git-ignored server secret and verifies the invariant the
  // database depends on: sha256(HASH_CONFIRMATION_SECRET) must equal the
  // v_expected_confirmation verifier in migration 20260925000000, and the
  // token sent over the wire is the raw secret itself. If the file is absent
  // (fresh checkout/CI) the test is skipped rather than failed.
  const envPath = join(process.cwd(), ".env.local");
  let secret: string | undefined;
  try {
    const raw = readFileSync(envPath, "utf8");
    const match = raw.match(/^HASH_CONFIRMATION_SECRET=([0-9a-f]+)$/m);
    if (match) secret = match[1];
  } catch {
    // no .env.local — nothing to verify.
  }
  if (!secret) {
    await assert.rejects(() => evidenceRegistrationToken(), {
      message: "HASH_CONFIRMATION_SECRET is not configured on the server",
    });
    return;
  }
  process.env.HASH_CONFIRMATION_SECRET = secret;
  try {
    const token = await evidenceRegistrationToken();
    assert.equal(token, secret, "The route must send the raw secret as the token");
    const digest = await sha256Hex(new TextEncoder().encode(token));
    assert.equal(
      digest,
      EXPECTED_DIGEST,
      "sha256(raw secret) must equal the v_expected_confirmation verifier in the migration",
    );
  } finally {
    if (ORIGINAL_SECRET) process.env.HASH_CONFIRMATION_SECRET = ORIGINAL_SECRET;
    else delete process.env.HASH_CONFIRMATION_SECRET;
  }
});