// Pure, deterministic helpers for the EvidenceAnchor bytes32 encoding.
// These are shared by the server-only blockchain service and its unit tests.
// They run anywhere (no node-only APIs), keep all signing/network logic out.

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;

// A canonical lowercase 0x-prefixed 64-hex bytes32 string.
export type Bytes32Hex = string;

export class EncodingError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EncodingError";
  }
}

/**
 * Validate a UUID string and return true if it matches the canonical
 * 8-4-4-4-12 hexadecimal form.
 */
export function isValidUuid(value: string): boolean {
  return UUID_PATTERN.test(value);
}

/**
 * Validate a string that is already a lowercase 64-hex SHA-256 digest.
 */
export function isValidSha256(value: string): boolean {
  return SHA256_PATTERN.test(value);
}

/**
 * Produce the exact same bytes32 encoding used by the EvidenceAnchor contract
 * and its test suite: the 16-byte UUID is left-padded with 16 zero bytes, so
 * the UUID occupies the right-most 16 bytes of the bytes32 value.
 *
 *   uuidToBytes32("a1b2c3d4-e5f6-7890-abcd-ef1234567890")
 *     === "0x00000000000000000000000000000000a1b2c3d4e5f67890abcdef1234567890"
 *
 * Throws EncodingError for an invalid UUID.
 */
export function uuidToBytes32(uuid: string): Bytes32Hex {
  if (!isValidUuid(uuid)) {
    throw new EncodingError(`Invalid UUID: ${uuid}`);
  }
  const hex = uuid.replace(/-/g, "").toLowerCase();
  return `0x${hex.padStart(64, "0")}`;
}

/**
 * Convert a validated lowercase 64-hex SHA-256 digest into its bytes32
 * representation. Rejects anything that is not exactly 64 lowercase hex
 * characters (the format stored in document_versions.sha256).
 */
export function sha256ToBytes32(sha256Hex: string): Bytes32Hex {
  if (!isValidSha256(sha256Hex)) {
    throw new EncodingError(
      `Invalid SHA-256 (expected 64 lowercase hex chars): ${sha256Hex}`,
    );
  }
  return `0x${sha256Hex}`;
}
