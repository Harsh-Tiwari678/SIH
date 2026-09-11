import { cn } from "@/lib/utils"

export type StatusTone =
  | "neutral"
  | "info"
  | "success"
  | "warning"
  | "danger"

const TONE_TEXT: Record<StatusTone, string> = {
  neutral: "text-muted-foreground",
  info: "text-primary",
  success: "text-success",
  warning: "text-warning",
  danger: "text-danger",
}

const TONE_DOT: Record<StatusTone, string> = {
  neutral: "bg-muted-foreground/70",
  info: "bg-primary",
  success: "bg-success",
  warning: "bg-warning",
  danger: "bg-danger",
}

export type StatusBadgeProps = {
  tone?: StatusTone
  label: string
  className?: string
  dim?: boolean
}

export function StatusBadge({
  tone = "neutral",
  label,
  dim = false,
  className,
}: StatusBadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border border-border/80 bg-muted/40 px-1.5 py-0.5 text-xs font-medium leading-none",
        TONE_TEXT[tone],
        dim && "opacity-60",
        className,
      )}
    >
      <span
        aria-hidden
        className={cn(
          "size-1.5 rounded-full",
          TONE_DOT[tone],
        )}
      />
      <span>{label}</span>
    </span>
  )
}

type StatusEntry = { tone: StatusTone; dim?: boolean }

// Case status vocabulary (cases.status): 'active' is the operational state and
// uses the restrained green (success) treatment. 'draft' / 'closed' are
// neutral; 'archived' is dimmed to read as inactive. Green is reserved for
// positive/operational states only — not every security status.
const CASE_STATUS_STYLES: Record<string, StatusEntry> = {
  draft:    { tone: "neutral" },
  active:   { tone: "success" },
  closed:   { tone: "neutral" },
  archived: { tone: "neutral", dim: true },
}

function capitalize(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1)
}

// Title-case a snake- or single-word status for display, e.g.
// "under_review" -> "Under Review", "anchored" -> "Anchored".
function humanize(value: string): string {
  return value
    .split("_")
    .filter(Boolean)
    .map(capitalize)
    .join(" ")
}

export function CaseStatusBadge({ status }: { status: string }) {
  const entry = CASE_STATUS_STYLES[status] ?? { tone: "neutral" as const }
  return (
    <StatusBadge
      tone={entry.tone}
      label={capitalize(status)}
      dim={entry.dim}
    />
  )
}

// Case-scoped member roles (case_members.role_in_case). All neutral text;
// roles are differentiated by label, not color.
export function RoleBadge({ role }: { role: string }) {
  const label = role === "lead" ? "Lead" : capitalize(role)
  return <StatusBadge label={label} />
}

// Evidence status vocabulary (evidence.status). 'received' is the neutral
// intake state, 'under_review' is the amber in-progress state, 'verified' is
// the restrained green success state, 'rejected' is danger, and 'archived' is
// dimmed to read as inactive.
const EVIDENCE_STATUS_STYLES: Record<string, StatusEntry> = {
  received:     { tone: "neutral" },
  under_review: { tone: "warning" },
  verified:     { tone: "success" },
  rejected:     { tone: "danger" },
  archived:     { tone: "neutral", dim: true },
}

export function EvidenceStatusBadge({ status }: { status: string }) {
  const entry = EVIDENCE_STATUS_STYLES[status] ?? { tone: "neutral" as const }
  return (
    <StatusBadge
      tone={entry.tone}
      label={humanize(status)}
      dim={entry.dim}
    />
  )
}

// Blockchain anchor row status (blockchain_anchors.status). This is the DATABASE
// state of the anchor slot — it is explicitly NOT an on-chain verdict (that is
// VerificationStatusBadge). pending is an in-flight intent, anchored is the
// positive terminal state, failed is a retryable failure.
const ANCHOR_STATUS_STYLES: Record<string, StatusEntry> = {
  pending:  { tone: "warning" },
  anchored: { tone: "success" },
  failed:   { tone: "danger" },
}

export function AnchorStatusBadge({ status }: { status: string }) {
  const entry = ANCHOR_STATUS_STYLES[status] ?? { tone: "neutral" as const }
  return (
    <StatusBadge tone={entry.tone} label={humanize(status)} dim={entry.dim} />
  )
}

// Independent on-chain integrity verification outcomes (verification.status).
// 'verified' is only ever shown for a genuine matching contract read;
// 'not_anchored' is neutral ("no anchor yet"), 'hash_mismatch' is a real
// integrity problem, and 'verification_ambiguous' is an inconclusive read.
const VERIFICATION_STATUS_STYLES: Record<string, StatusEntry> = {
  verified:               { tone: "success" },
  not_anchored:           { tone: "neutral" },
  hash_mismatch:          { tone: "danger" },
  verification_ambiguous: { tone: "warning" },
}

export function VerificationStatusBadge({ status }: { status: string }) {
  const entry = VERIFICATION_STATUS_STYLES[status] ?? { tone: "warning" as const }
  return (
    <StatusBadge
      tone={entry.tone}
      label={humanize(status)}
      dim={entry.dim}
    />
  )
}