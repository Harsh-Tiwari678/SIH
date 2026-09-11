// Client-side helpers and shared response types for the evidence experience.
// Types mirror the pure response shaping in lib/evidence-serialization.ts; the
// verification/anchor shapes mirror the existing API contracts (verification
// GET + anchor POST).

import { EVIDENCE_TYPES } from "@/lib/evidence-serialization";
import type { AnchorStatus } from "@/lib/evidence-serialization";

export const ALLOWED_EVIDENCE_MIME_TYPES = [
  "application/pdf",
  "image/png",
  "image/jpeg",
  "video/mp4",
  "audio/mpeg",
  "text/plain",
] as const;

export const MAX_EVIDENCE_FILE_SIZE_BYTES = 52428800; // 50 MiB

export const ACCEPT_FILE_INPUT = ALLOWED_EVIDENCE_MIME_TYPES.join(",");

export function capitalize(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1)
}

// Title-case a snake_- or single-word status for display.
export function humanize(value: string): string {
  return value
    .split("_")
    .filter(Boolean)
    .map(capitalize)
    .join(" ")
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "—"
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

export function shortHash(hash: string, width = 10): string {
  if (hash.length <= width * 2) return hash
  return `${hash.slice(0, width)}…${hash.slice(-width)}`
}

export function shortId(id: string): string {
  return id.slice(0, 8)
}

// A document version's allowed MIME list drives the upload dialog's default
// type suggestion, so a file picked from the accept list maps to something
// sensible while the user can still override it.
export function suggestedTypeForMime(mime: string): string {
  const normalized = mime.toLowerCase()
  if (normalized === "application/pdf" || normalized === "text/plain") {
    return "document"
  }
  if (normalized.startsWith("image/")) return "image"
  if (normalized.startsWith("video/")) return "video"
  if (normalized.startsWith("audio/")) return "audio"
  return "other"
}

export function isAllowedEvidenceMime(mime: string): boolean {
  return (ALLOWED_EVIDENCE_MIME_TYPES as readonly string[]).includes(mime)
}

export const EVIDENCE_TYPE_OPTIONS = [...EVIDENCE_TYPES] as const;

// ---------------------------------------------------------------------------
// Blockchain verification GET response ({ verification: VerificationFrame })
// ---------------------------------------------------------------------------

export type VerificationStatus =
  | "verified"
  | "not_anchored"
  | "hash_mismatch"
  | "verification_ambiguous"

export interface VerificationFrame {
  status: VerificationStatus
  document_version_id: string
  evidence_id: string
  case_id: string
  database_sha256: string
  blockchain: {
    evidence_id_hash: string
    version_id_hash: string
    expected_sha256: string
    exists: boolean
    stored_sha256: string | null
    anchored_at: string | null
    block_number: number | null
    network: string
    chain_id: number
    contract_address: string
  } | null
  database_anchor: {
    status: AnchorStatus
    tx_hash: string | null
    block_number: number | null
    anchored_at: string | null
    network: string
    chain_id: number
    contract_address: string
  } | null
  message?: string
}

// ---------------------------------------------------------------------------
// Anchor trigger POST response ({ anchor: AnchorOutcomeBody })
// ---------------------------------------------------------------------------

export type AnchorOutcomeStatus =
  | "anchored"
  | "reconciled"
  | "already_anchored"
  | "verification_ambiguous"
  | "db_sync_failed"
  | "failed"
  | "verification_failed"

export interface AnchorOutcomeBody {
  status: AnchorOutcomeStatus
  anchor_id?: string
  tx_hash?: string
  block_number?: number
  anchored_at?: string
  category?: string
  message?: string
}