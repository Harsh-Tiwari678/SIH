// Pure response-shaping types and helpers for the evidence read endpoints
// (GET /api/cases/[id]/evidence and
// GET /api/cases/[id]/evidence/[evidenceId]). No framework or database
// imports — deliberately framework-free so it can be unit-tested with
// node:test like the blockchain core modules, and imported (for types and
// vocabulary) by the client views without pulling server code into the
// browser bundle.
//
// The vocabulary mirrors the DB CHECK constraints:
//   evidence.status          ('received', 'under_review', 'verified',
//                             'rejected', 'archived')
//   evidence.type            ('document', 'image', 'video', 'audio', 'other')
//   blockchain_anchors.status ('pending', 'anchored', 'failed')
//   chain_of_custody.action  ('received', 'transferred', 'returned',
//                             'verified', 'released', 'archived')

export const EVIDENCE_STATUSES = [
  "received",
  "under_review",
  "verified",
  "rejected",
  "archived",
] as const;
export type EvidenceStatus = (typeof EVIDENCE_STATUSES)[number];

export const EVIDENCE_TYPES = [
  "document",
  "image",
  "video",
  "audio",
  "other",
] as const;
export type EvidenceType = (typeof EVIDENCE_TYPES)[number];

export const ANCHOR_STATUSES = ["pending", "anchored", "failed"] as const;
export type AnchorStatus = (typeof ANCHOR_STATUSES)[number];

export const CUSTODY_ACTIONS = [
  "received",
  "transferred",
  "returned",
  "verified",
  "released",
  "archived",
] as const;
export type CustodyAction = (typeof CUSTODY_ACTIONS)[number];

// ---------------------------------------------------------------------------
// Shared raw row fragments (PostgREST embeds)
// ---------------------------------------------------------------------------

export interface ProfileRef {
  id: string;
  full_name: string;
}

// The FK hints disambiguate embeds the same way the case detail uses
// profiles!case_members_profile_id_fkey: every table below has more than one
// FK into profiles, so an unqualified embed would fail the PostgREST query.
export interface EvidenceCoreRawRow {
  id: string;
  case_id: string;
  evidence_number: string;
  title: string;
  description: string | null;
  type: string;
  status: string;
  created_at: string;
  updated_at: string;
  created_by: string;
  creator?: ProfileRef | null;
}

export interface VersionRawRow {
  id: string;
  version: number;
  prev_version_id: string | null;
  file_name: string;
  mime_type: string;
  file_size_bytes: number;
  sha256: string;
  uploaded_by: string;
  uploaded_at: string;
  notes: string | null;
  uploader?: ProfileRef | null;
}

export interface AnchorRawRow {
  id: string;
  document_version_id: string;
  status: string;
  tx_hash: string | null;
  block_number: number | null;
  anchored_at: string | null;
  network: string;
  chain_id: number | string;
  contract_address: string;
  error_message: string | null;
}

export interface CustodyRawRow {
  id: string;
  action: string;
  actor_id: string;
  from_profile_id: string | null;
  to_profile_id: string | null;
  location: string | null;
  notes: string | null;
  occurred_at: string;
  actor?: ProfileRef | null;
  from_profile?: ProfileRef | null;
  to_profile?: ProfileRef | null;
}

// ---------------------------------------------------------------------------
// List shape — GET /api/cases/[id]/evidence
// ---------------------------------------------------------------------------

export interface EvidenceListVersion {
  id: string;
  version: number;
  file_name: string;
  mime_type: string;
  file_size_bytes: number;
  sha256: string;
  uploaded_at: string;
}

export interface EvidenceListRawRow extends EvidenceCoreRawRow {
  document_versions?: Array<{
    id: string;
    version: number;
    file_name: string;
    mime_type: string;
    file_size_bytes: number;
    sha256: string;
    uploaded_at: string;
  }>;
}

export interface EvidenceListItem {
  id: string;
  case_id: string;
  evidence_number: string;
  title: string;
  description: string | null;
  type: EvidenceType;
  status: EvidenceStatus;
  created_at: string;
  updated_at: string;
  created_by: string;
  creator_name: string | null;
  latest_version: EvidenceListVersion | null;
  version_count: number;
}

export function serializeEvidenceListItem(
  row: EvidenceListRawRow,
): EvidenceListItem {
  const versions = row.document_versions ?? [];
  const latest =
    versions.length === 0
      ? null
      : versions.reduce((a, b) => (b.version > a.version ? b : a));
  return {
    id: row.id,
    case_id: row.case_id,
    evidence_number: row.evidence_number,
    title: row.title,
    description: row.description,
    // RLS exposes only rows a case member may read, and the DB CHECK
    // constraints pin type/status to this vocabulary; the cast is a
    // DB-guaranteed mapping, not a client trust boundary.
    type: row.type as EvidenceType,
    status: row.status as EvidenceStatus,
    created_at: row.created_at,
    updated_at: row.updated_at,
    created_by: row.created_by,
    creator_name: row.creator?.full_name ?? null,
    latest_version: latest
      ? {
          id: latest.id,
          version: latest.version,
          file_name: latest.file_name,
          mime_type: latest.mime_type,
          file_size_bytes: latest.file_size_bytes,
          sha256: latest.sha256,
          uploaded_at: latest.uploaded_at,
        }
      : null,
    version_count: versions.length,
  };
}

// ---------------------------------------------------------------------------
// Detail shape — GET /api/cases/[id]/evidence/[evidenceId]
// ---------------------------------------------------------------------------

// Permit-listed blockchain_anchors context for a document version. Defensive
// re-validation mirrors the verification service: a malformed row is dropped
// as context rather than echoed to a client, and a non-genuine tx_hash is
// never invented (reconciled anchors legitimately carry tx_hash = NULL).
export interface AnchorContext {
  id: string;
  document_version_id: string;
  status: AnchorStatus;
  tx_hash: string | null;
  block_number: number | null;
  anchored_at: string | null;
  network: string;
  chain_id: number;
  contract_address: string;
  error_message: string | null;
}

const TX_HASH_PATTERN = /^0x[0-9a-fA-F]{64}$/;

export function parseAnchorContext(row: AnchorRawRow | null | undefined): AnchorContext | null {
  if (!row) return null;
  if (typeof row.id !== "string" || typeof row.document_version_id !== "string") {
    return null;
  }
  if (!(ANCHOR_STATUSES as readonly string[]).includes(row.status)) return null;
  const chainId =
    typeof row.chain_id === "number"
      ? row.chain_id
      : Number(String(row.chain_id));
  return {
    id: row.id,
    document_version_id: row.document_version_id,
    status: row.status as AnchorStatus,
    tx_hash:
      typeof row.tx_hash === "string" && TX_HASH_PATTERN.test(row.tx_hash)
        ? row.tx_hash
        : null,
    block_number: toSafeBlockNumber(row.block_number),
    anchored_at: typeof row.anchored_at === "string" ? row.anchored_at : null,
    network:
      typeof row.network === "string" && row.network ? row.network : "sepolia",
    chain_id: Number.isSafeInteger(chainId) && chainId > 0 ? chainId : 0,
    contract_address:
      typeof row.contract_address === "string" && row.contract_address
        ? row.contract_address
        : "",
    error_message:
      typeof row.error_message === "string" ? row.error_message : null,
  };
}

function toSafeBlockNumber(value: unknown): number | null {
  if (value === null || value === undefined) return null;
  const n = typeof value === "number" ? value : Number(String(value));
  if (!Number.isSafeInteger(n) || n < 1) return null;
  return n;
}

export interface EvidenceVersion {
  id: string;
  version: number;
  prev_version_id: string | null;
  file_name: string;
  mime_type: string;
  file_size_bytes: number;
  sha256: string;
  uploaded_by: string;
  uploaded_at: string;
  notes: string | null;
  uploader_name: string | null;
  anchor: AnchorContext | null;
}

export function serializeEvidenceVersion(
  row: VersionRawRow,
  anchor: AnchorContext | null,
): EvidenceVersion {
  return {
    id: row.id,
    version: row.version,
    prev_version_id: row.prev_version_id,
    file_name: row.file_name,
    mime_type: row.mime_type,
    file_size_bytes: row.file_size_bytes,
    sha256: row.sha256,
    uploaded_by: row.uploaded_by,
    uploaded_at: row.uploaded_at,
    notes: row.notes,
    uploader_name: row.uploader?.full_name ?? null,
    anchor,
  };
}

export interface CustodyEntry {
  id: string;
  action: CustodyAction;
  actor_id: string;
  from_profile_id: string | null;
  to_profile_id: string | null;
  location: string | null;
  notes: string | null;
  occurred_at: string;
  actor_name: string | null;
  from_name: string | null;
  to_name: string | null;
}

export function serializeCustodyEntry(row: CustodyRawRow): CustodyEntry {
  return {
    id: row.id,
    action: row.action as CustodyAction,
    actor_id: row.actor_id,
    from_profile_id: row.from_profile_id,
    to_profile_id: row.to_profile_id,
    location: row.location,
    notes: row.notes,
    occurred_at: row.occurred_at,
    actor_name: row.actor?.full_name ?? null,
    from_name: row.from_profile?.full_name ?? null,
    to_name: row.to_profile?.full_name ?? null,
  };
}

export interface EvidenceCore {
  id: string;
  case_id: string;
  evidence_number: string;
  title: string;
  description: string | null;
  type: EvidenceType;
  status: EvidenceStatus;
  created_at: string;
  updated_at: string;
  created_by: string;
  creator_name: string | null;
}

export interface EvidenceDetailPayload {
  evidence: EvidenceCore;
  versions: EvidenceVersion[];
  custody: CustodyEntry[];
}

export function serializeEvidenceDetail(
  core: EvidenceCoreRawRow,
  versionRows: VersionRawRow[],
  anchorRows: AnchorRawRow[],
  custodyRows: CustodyRawRow[],
): EvidenceDetailPayload {
  const anchorsByVersion = new Map<string, AnchorContext>();
  for (const row of anchorRows) {
    const ctx = parseAnchorContext(row);
    if (ctx) anchorsByVersion.set(ctx.document_version_id, ctx);
  }
  return {
    evidence: {
      id: core.id,
      case_id: core.case_id,
      evidence_number: core.evidence_number,
      title: core.title,
      description: core.description,
      type: core.type as EvidenceType,
      status: core.status as EvidenceStatus,
      created_at: core.created_at,
      updated_at: core.updated_at,
      created_by: core.created_by,
      creator_name: core.creator?.full_name ?? null,
    },
    versions: versionRows.map((row) =>
      serializeEvidenceVersion(
        row,
        anchorsByVersion.get(row.id) ?? null,
      ),
    ),
    custody: custodyRows.map(serializeCustodyEntry),
  };
}