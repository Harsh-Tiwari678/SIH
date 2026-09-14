// Server capability token for the create_evidence() hash-registration gate
// (migration 20260925000000).
//
// The database stores ONLY the SHA-256 digest of HASH_CONFIRMATION_SECRET as a
// VERIFIER and hashes the supplied token inside PostgreSQL (extensions.digest)
// before comparing.  So the value this module returns MUST be the RAW secret
// itself — never its digest.  Passing the digest (a public constant in the
// migration) does NOT authenticate: the DB would hash it again and the result
// would not match the verifier (sha256(digest) <> digest).
//
// The raw secret lives only in the server process (env/.env.local) and is
// never exposed to the browser or client.  It is a 64-hex value so it also
// satisfies create_evidence()'s format precondition.
//
// Rotating the secret:
//   1. Generate a fresh 256-bit random value.
//   2. Put it into .env.local as HASH_CONFIRMATION_SECRET.
//   3. Compute its SHA-256 digest.
//   4. Embed the new digest as v_expected_confirmation in a NEW migration
//      (never editing a landed migration retroactively), mirroring the C1
//      ANCHOR_CONFIRMATION_SECRET rotation procedure.

export async function evidenceRegistrationToken(): Promise<string> {
  const secret = process.env.HASH_CONFIRMATION_SECRET;

  if (!secret) {
    throw new Error(
      "HASH_CONFIRMATION_SECRET is not configured on the server",
    );
  }

  if (!/^[0-9a-f]{64}$/.test(secret)) {
    throw new Error(
      "HASH_CONFIRMATION_SECRET must be a 64-character hex value",
    );
  }

  return secret;
}