// Pure response-shaping for the audit trail read endpoints
// (GET /api/cases/[id]/audit and
// GET /api/cases/[id]/evidence/[evidenceId]/audit). No framework or database
// imports — deliberately framework-free so it can be unit-tested with
// node:test like the other lib modules, and imported (for types and shaping)
// by the client views without pulling server code into the browser bundle.
//
// Security contract:
//   * The DB RPCs (list_case_audit_events / list_evidence_audit_events) are
//     the authorization boundary. They gate on case membership, resolve the
//     polymorphic entity, and strip `storage_key` from meta. This module is a
//     SECOND, client-side-only allow-list: even if a future DB event carries an
//     unexpected meta key, it is never rendered.
//   * SHA-256 digests, tx hashes, chain ids, contract addresses and error
//     messages are fingerprints / public chain metadata already surfaced by the
//     evidence UI — not secrets. Storage keys, object internals and anything
//     outside AUDIT_META_ALLOW_LIST are never exposed.

export const AUDIT_ENTITY_TYPES = [
  "case",
  "case_member",
  "evidence",
  "document_version",
  "blockchain_anchor",
] as const;
export type AuditEntityType = (typeof AUDIT_ENTITY_TYPES)[number];

export interface AuditEventRawRow {
  id: string;
  action: string;
  entity_type: string;
  entity_id: string;
  actor_id: string | null;
  actor_name: string | null;
  case_id: string | null;
  evidence_id: string | null;
  entity_label: string | null;
  created_at: string;
  meta: Record<string, unknown> | null;
}

// ---------------------------------------------------------------------------
// Action vocabulary (mirrors the dotted actions written by the SECURITY
// DEFINER RPCs). Unknown actions fall back to a humanized form rather than
// erroring, so a future event type still renders readably.
// ---------------------------------------------------------------------------

const ACTION_LABELS: Record<string, string> = {
  "case.created": "Case created",
  "case.updated": "Case updated",
  "case.status_changed": "Case status changed",
  "case.member_added": "Member added",
  "case.member_role_changed": "Member role changed",
  "case.member_removed": "Member removed",
  "evidence.created": "Evidence uploaded",
  "evidence.hash_generated": "Fingerprint generated",
  "evidence.status_changed": "Evidence status changed",
  "evidence.verification_requested": "Verification requested",
  "evidence.verification_passed": "Verification passed",
  "evidence.verification_failed": "Verification failed",
  "evidence.anchor_requested": "Anchor requested",
  "evidence.anchor_retry": "Anchor retried",
  "evidence.anchored": "Anchor confirmed on chain",
  "evidence.anchor_failed": "Anchor failed",
  "evidence.anchor_reconciled": "Anchor reconciled",
  "evidence.custody_received": "Evidence received into custody",
  "evidence.accessed": "Evidence accessed",
};

export function auditActionLabel(action: string): string {
  const known = ACTION_LABELS[action];
  if (known) return known;
  const segment = action.split(".").filter(Boolean).at(-1) ?? action;
  return segment
    .split("_")
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

const ENTITY_TYPE_LABELS: Record<string, string> = {
  case: "Case",
  case_member: "Member",
  evidence: "Evidence",
  document_version: "Version",
  blockchain_anchor: "Blockchain anchor",
};

export function auditEntityTypeLabel(entityType: string): string {
  return ENTITY_TYPE_LABELS[entityType] ?? entityType;
}

// ---------------------------------------------------------------------------
// Meta allow-list. Only these keys, in this order, may ever be rendered, and
// only as flat scalar strings. Everything else (storage_key, nested objects,
// internal ids) is dropped.
// ---------------------------------------------------------------------------

const AUDIT_META_ALLOW_LIST: Array<{ key: string; label: string }> = [
  { key: "case_number", label: "Case" },
  { key: "evidence_number", label: "Evidence" },
  { key: "title", label: "Title" },
  { key: "file_name", label: "File" },
  { key: "previous_status", label: "Status from" },
  { key: "new_status", label: "Status to" },
  { key: "role_in_case", label: "Role" },
  { key: "previous_role_in_case", label: "Role from" },
  { key: "new_role_in_case", label: "Role to" },
  { key: "removed_role_in_case", label: "Role removed" },
  { key: "result", label: "Result" },
  { key: "verdict", label: "Verdict" },
  { key: "mode", label: "Mode" },
  { key: "network", label: "Network" },
  { key: "chain_id", label: "Chain ID" },
  { key: "contract_address", label: "Contract" },
  { key: "tx_hash", label: "Transaction" },
  { key: "block_number", label: "Block" },
  { key: "anchored_at", label: "Anchored at" },
  { key: "sha256", label: "SHA-256" },
  { key: "error_message", label: "Error" },
  { key: "notes", label: "Notes" },
];

const META_VALUE_MAX = 200;

function toMetaString(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value === "string") {
    const collapsed = value.replace(/[\r\n]+/g, " ").trim();
    if (collapsed === "") return null;
    return collapsed.length > META_VALUE_MAX
      ? collapsed.slice(0, META_VALUE_MAX - 1) + "…"
      : collapsed;
  }
  if (typeof value === "number" || typeof value === "bigint" || typeof value === "boolean") {
    if (typeof value === "number" && !Number.isFinite(value)) return null;
    return String(value);
  }
  // Nested objects / arrays are never rendered.
  return null;
}

export interface AuditMetaItem {
  key: string;
  label: string;
  value: string;
}

export function sanitizeAuditMeta(
  meta: Record<string, unknown> | null,
): AuditMetaItem[] {
  if (!meta) return [];
  const out: AuditMetaItem[] = [];
  for (const entry of AUDIT_META_ALLOW_LIST) {
    if (!(entry.key in meta)) continue;
    const value = toMetaString(meta[entry.key]);
    if (value === null) continue;
    out.push({ key: entry.key, label: entry.label, value });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Entity rendering
// ---------------------------------------------------------------------------

export function auditEntityLabel(row: AuditEventRawRow): string | null {
  if (row.entity_label) return row.entity_label;
  // Row-scoped type guard: only recognize the known vocabulary so an
  // unexpected entity_type falls back to a neutral label rather than
  // mirroring raw input.
  const known =
    (AUDIT_ENTITY_TYPES as readonly string[]).includes(row.entity_type) &&
    row.entity_type;
  return known ? (ENTITY_TYPE_LABELS[known] ?? null) : null;
}

// ---------------------------------------------------------------------------
// Verification outcome mapping — mirrors record_verification_event's coherent
// result/verdict pairs. A frame that yields no definitive verdict (e.g.
// not_anchored) produces no terminal passed/failed event; ambiguous reads are
// recorded as failed so unsuccessful verification attempts stay on the record.
// ---------------------------------------------------------------------------

export type VerificationVerdict =
  | "verified"
  | "not_anchored"
  | "hash_mismatch"
  | "verification_ambiguous";

export type VerificationAuditOutcome =
  | { result: "passed"; verdict: "verified" }
  | { result: "failed"; verdict: "hash_mismatch" | "verification_ambiguous" };

export function verificationAuditOutcome(
  verdict: string,
): VerificationAuditOutcome | null {
  switch (verdict) {
    case "verified":
      return { result: "passed", verdict: "verified" };
    case "hash_mismatch":
      return { result: "failed", verdict: "hash_mismatch" };
    case "verification_ambiguous":
      return { result: "failed", verdict: "verification_ambiguous" };
    default:
      // not_anchored and anything unknown: no passed/failed terminal event.
      return null;
  }
}

// ---------------------------------------------------------------------------
// Serialized shape — GET /api/cases/[id]/audit
//   GET /api/cases/[id]/evidence/[evidenceId]/audit
// ---------------------------------------------------------------------------

export interface AuditEventItem {
  id: string;
  action: string;
  action_label: string;
  entity_type: string;
  entity_type_label: string;
  entity_id: string;
  entity_label: string | null;
  actor_name: string | null;
  evidence_id: string | null;
  created_at: string;
  meta: AuditMetaItem[];
}

export function serializeAuditEvent(row: AuditEventRawRow): AuditEventItem {
  return {
    id: row.id,
    action: row.action,
    action_label: auditActionLabel(row.action),
    entity_type: row.entity_type,
    entity_type_label: auditEntityTypeLabel(row.entity_type),
    entity_id: row.entity_id,
    entity_label: auditEntityLabel(row),
    actor_name: row.actor_name,
    evidence_id: row.evidence_id,
    created_at: row.created_at,
    meta: sanitizeAuditMeta(row.meta),
  };
}

export function serializeAuditEvents(rows: AuditEventRawRow[]): AuditEventItem[] {
  return rows.map(serializeAuditEvent);
}