// Pure vocabulary and helpers for evidence file access
// (GET /api/cases/[id]/evidence/[evidenceId]/access).
// No framework or database imports — deliberately framework-free so it can be
// unit-tested with node:test and imported by the client views without pulling
// server code into the browser bundle.
//
// Security contract:
//   * The RPCs (resolve_evidence_access / record_evidence_access) are the
//     authorization boundary. This module only describes what a resolved,
//     authorized access may become in the UI (preview renderer + labels).
//   * The signed URL lifetime is the shortest that keeps an immediate preview
//     or download usable end-to-end. It is short enough that a leaked link has
//     minimal value and every new open needs a fresh, server-authorized token.
//
// The access response carries NO storage key and never embeds the underlying
// object path beyond what a short-lived signed URL necessarily contains.

export const EVIDENCE_ACCESS_MODES = ["preview", "download"] as const;
export type EvidenceAccessMode = (typeof EVIDENCE_ACCESS_MODES)[number];

export function isEvidenceAccessMode(value: unknown): value is EvidenceAccessMode {
  return (
    typeof value === "string" &&
    (EVIDENCE_ACCESS_MODES as readonly string[]).includes(value)
  );
}

// 120 seconds: long enough for the UI to open the link immediately after
// minting it, short enough that the token has no lasting value if leaked.
// Cap any future configurable lifetime to this ceiling.
export const SIGNED_URL_LIFETIME_SECONDS = 120;

export function signedUrlExpiry(nowMs: number = Date.now()): string {
  return new Date(nowMs + SIGNED_URL_LIFETIME_SECONDS * 1000).toISOString();
}

// ---------------------------------------------------------------------------
// Browser preview support — mirrors the permitted upload MIME types in
// lib/storage.ts. Every permitted type is browser-renderable today; anything
// else is download-only until its type is explicitly admitted elsewhere.
// ---------------------------------------------------------------------------

export const EV_MIME_PREVIEW_KINDS = [
  "image",
  "pdf",
  "text",
  "video",
  "audio",
] as const;
export type EvidencePreviewKind = (typeof EV_MIME_PREVIEW_KINDS)[number] | "none";

export function evidencePreviewKind(mimeType: string): EvidencePreviewKind {
  switch ((mimeType || "").toLowerCase()) {
    case "image/png":
    case "image/jpeg":
      return "image";
    case "application/pdf":
      return "pdf";
    case "text/plain":
      return "text";
    case "video/mp4":
      return "video";
    case "audio/mpeg":
      return "audio";
    default:
      return "none";
  }
}

const PREVIEW_KIND_LABELS: Record<EvidencePreviewKind, string> = {
  image: "Image",
  pdf: "PDF document",
  text: "Plain text",
  video: "Video",
  audio: "Audio",
  none: "",
};

export function evidencePreviewKindLabel(kind: EvidencePreviewKind): string {
  return PREVIEW_KIND_LABELS[kind];
}

// ---------------------------------------------------------------------------
// Access response — GET /api/cases/[id]/evidence/[evidenceId]/access
// The minimal safe surface the UI needs. storage_key and server internals
// are never part of this shape, and a non-https url is a programming error.
// ---------------------------------------------------------------------------

export interface EvidenceAccessSource {
  file_name: string;
  mime_type: string;
  version: number;
}

export interface EvidenceAccessResponse {
  url: string;
  expires_at: string;
  mode: EvidenceAccessMode;
  file_name: string;
  mime_type: string;
  version: number;
}

export function buildAccessResponse(
  source: EvidenceAccessSource,
  mode: EvidenceAccessMode,
  url: string,
  expiresAt: string,
): EvidenceAccessResponse | null {
  if (!/^https?:\/\//i.test(url)) return null;
  if (expiresAt === "" || Number.isNaN(Date.parse(expiresAt))) return null;
  return {
    url,
    expires_at: expiresAt,
    mode,
    file_name: source.file_name,
    mime_type: source.mime_type,
    version: source.version,
  };
}