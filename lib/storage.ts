// Server-only helpers for evidence file storage. The browser is never
// trusted for hashing, MIME detection, size limits, or storage keys — all of
// that happens here or in the calling route handler, on the exact bytes that
// reach the server.

export const EVIDENCE_BUCKET = "evidence-files";

// Keep in sync with storage.buckets.allowed_mime_types /
// storage.buckets.file_size_limit in 20260903000000_create_evidence.sql.
// The bucket enforces these server-side as well (defense in depth).
export const MAX_EVIDENCE_FILE_SIZE_BYTES = 52428800; // 50 MiB

export const ALLOWED_EVIDENCE_MIME_TYPES = [
  "application/pdf",
  "image/png",
  "image/jpeg",
  "video/mp4",
  "audio/mpeg",
  "text/plain",
] as const;

export type EvidenceMimeType = (typeof ALLOWED_EVIDENCE_MIME_TYPES)[number];

export const EVIDENCE_TYPES = [
  "document",
  "image",
  "video",
  "audio",
  "other",
] as const;

export type EvidenceType = (typeof EVIDENCE_TYPES)[number];

// Strips any path components and control characters from a client-supplied
// filename. The result is display-only metadata — the stored object key is
// always {case_id}/{evidence_id}/{document_version_id}.
export function sanitizeFileName(rawName: string): string {
  const base = rawName.split(/[\\/]/).pop() ?? "";
  // Remove control characters (C0, DEL, C1) that could corrupt storage or
  // display layers.
  const cleaned = base.replace(/[\u0000-\u001f\u007f-\u009f]/g, "").trim();
  return cleaned.slice(0, 255);
}

export function isAllowedEvidenceMime(
  mimeType: string,
): mimeType is EvidenceMimeType {
  return (ALLOWED_EVIDENCE_MIME_TYPES as readonly string[]).includes(mimeType);
}

export function isEvidenceType(value: string): value is EvidenceType {
  return (EVIDENCE_TYPES as readonly string[]).includes(value);
}

// Minimal magic-number verification: the declared Content-Type is
// client-controlled, so binary formats are checked against their file
// signature before anything is stored. text/plain is verified structurally
// (must decode as UTF-8). This is a sanity gate, not full content analysis.
export function bytesMatchMimeType(bytes: Uint8Array, mimeType: string): boolean {
  const startsWith = (signature: number[], offset = 0) =>
    signature.every((b, i) => bytes[offset + i] === b);

  switch (mimeType) {
    case "application/pdf":
      return startsWith([0x25, 0x50, 0x44, 0x46]); // %PDF
    case "image/png":
      return startsWith([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    case "image/jpeg":
      return startsWith([0xff, 0xd8, 0xff]);
    case "video/mp4":
      // ftyp box at offset 4; brands starting with 'M','S','N','V' are
      // QuickTime-derived and rejected conservatively.
      return (
        bytes.length >= 12 &&
        startsWith([0x66, 0x74, 0x79, 0x70], 4) && // "ftyp"
        [0x4d, 0x53, 0x4e, 0x56].includes(bytes[8])
      );
    case "audio/mpeg":
      return (
        startsWith([0x49, 0x44, 0x33]) || // "ID3"
        (bytes.length >= 2 && bytes[0] === 0xff && (bytes[1] & 0xe0) === 0xe0)
      );
    case "text/plain": {
      try {
        new TextDecoder("utf-8", { fatal: true }).decode(bytes);
        return true;
      } catch {
        return false;
      }
    }
    default:
      return false;
  }
}

// SHA-256 over the exact uploaded bytes, for integrity verification only.
// It is not encryption and, alone, proves nothing about who handled a file —
// that is the role of chain_of_custody and audit_logs.
export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
