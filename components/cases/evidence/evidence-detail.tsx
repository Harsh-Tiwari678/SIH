"use client"

import * as React from "react"
import {
  AlertCircle,
  ArrowLeft,
  CheckCircle2,
  History,
  Loader2,
  Lock,
  ShieldCheck,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { CopyButton } from "@/components/cases/evidence/copy-button"
import { EvidenceAuditSection } from "@/components/cases/evidence/evidence-audit-section"
import { FileAccessPanel } from "@/components/cases/evidence/file-access-panel"
import {
  AnchorStatusBadge,
  EvidenceStatusBadge,
  VerificationStatusBadge,
} from "@/components/cases/status-badge"
import type {
  AnchorContext,
  CustodyEntry,
  EvidenceVersion,
} from "@/lib/evidence-serialization"
import {
  type AnchorOutcomeBody,
  type VerificationFrame,
  formatBytes,
  humanize,
  shortHash,
} from "@/components/cases/evidence/evidence"
import { formatDate } from "@/lib/format"
import { cn } from "@/lib/utils"

type Core = {
  evidence_number: string
  title: string
  description: string | null
  type: string
  status: string
  created_at: string
  updated_at: string
  creator_name: string | null
}

type DetailState =
  | { status: "loading" }
  | { status: "error" }
  | { status: "ready"; core: Core; versions: EvidenceVersion[]; custody: CustodyEntry[] }

export function EvidenceDetail({
  caseId,
  evidenceId,
  myRole,
  caseOpen,
  onBack,
}: {
  caseId: string
  evidenceId: string
  myRole: string | null
  caseOpen: boolean
  onBack: () => void
}) {
  const [state, setState] = React.useState<DetailState>({ status: "loading" })
  const [reloadKey, setReloadKey] = React.useState(0)

  React.useEffect(() => {
    let cancelled = false
    async function load() {
      setState({ status: "loading" })
      let res: Response
      try {
        res = await fetch(`/api/cases/${caseId}/evidence/${evidenceId}`, {
          cache: "no-store",
        })
      } catch {
        if (!cancelled) setState({ status: "error" })
        return
      }
      if (cancelled) return
      if (!res.ok) {
        if (!cancelled) setState({ status: "error" })
        return
      }
      const data = (await res.json().catch(() => ({}))) as {
        evidence?: Core
        versions?: EvidenceVersion[]
        custody?: CustodyEntry[]
      }
      if (cancelled) return
      if (!data.evidence) {
        setState({ status: "error" })
        return
      }
      setState({
        status: "ready",
        core: data.evidence,
        versions: data.versions ?? [],
        custody: data.custody ?? [],
      })
    }
    load()
    return () => {
      cancelled = true
    }
  }, [caseId, evidenceId, reloadKey])

  if (state.status === "loading") {
    return (
      <div
        aria-busy="true"
        aria-label="Loading evidence"
        className="space-y-3"
      >
        <div className="h-4 w-40 animate-pulse rounded bg-muted/60" />
        <div className="h-7 w-72 animate-pulse rounded bg-muted/60" />
        <div className="h-32 animate-pulse rounded-lg border border-border/60 bg-muted/40" />
      </div>
    )
  }

  if (state.status === "error") {
    return (
      <div className="flex flex-col items-center justify-center rounded-lg border border-border/80 bg-background px-6 py-12 text-center">
        <div className="flex size-9 items-center justify-center rounded-full border border-border/70 bg-muted/50 text-muted-foreground">
          <AlertCircle className="size-4" aria-hidden />
        </div>
        <h2 className="mt-4 text-sm font-semibold text-foreground">
          Could not load evidence
        </h2>
        <p className="mt-1 max-w-sm text-sm text-muted-foreground">
          We could not load this evidence record right now. Try refreshing.
        </p>
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="mt-4"
          onClick={() => setReloadKey((k) => k + 1)}
        >
          Retry
        </Button>
      </div>
    )
  }

  const { core, versions, custody } = state

  return (
    <div className="space-y-5">
      <div>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={onBack}
          className="-ml-2 mb-2"
        >
          <ArrowLeft aria-hidden className="size-4" />
          Back to evidence
        </Button>
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="text-sm font-semibold text-foreground">{core.title}</h3>
          <EvidenceStatusBadge status={core.status} />
        </div>
        <p className="mt-1 font-mono text-xs text-muted-foreground">
          {core.evidence_number}
        </p>
        {core.description ? (
          <p className="mt-2 max-w-2xl whitespace-pre-wrap text-sm text-muted-foreground">
            {core.description}
          </p>
        ) : null}
      </div>

      <EvidenceMeta core={core} versions={versions} />

      <FileAccessPanel caseId={caseId} evidenceId={evidenceId} versions={versions} />

      <VersionTimeline versions={versions} />

      <IntegrityPanel versions={versions} />

      <BlockchainPanel
        caseId={caseId}
        versions={versions}
        myRole={myRole}
        caseOpen={caseOpen}
        onVerified={() => setReloadKey((k) => k + 1)}
      />

      <CustodyPanel custody={custody} />

      <EvidenceAuditSection caseId={caseId} evidenceId={evidenceId} />
    </div>
  )
}

// ---------------------------------------------------------------------------
// Meta
// ---------------------------------------------------------------------------

function MetaRow({
  label,
  children,
  mono = false,
}: {
  label: string
  children: React.ReactNode
  mono?: boolean
}) {
  return (
    <div className="flex flex-col gap-0.5 py-2 sm:flex-row sm:items-baseline sm:gap-6">
      <dt className="w-32 shrink-0 text-xs uppercase tracking-wide text-muted-foreground">
        {label}
      </dt>
      <dd
        className={cn(
          "min-w-0 break-all text-sm text-foreground",
          mono && "font-mono text-[13px]",
        )}
      >
        {children}
      </dd>
    </div>
  )
}

function EvidenceMeta({ core, versions }: { core: Core; versions: EvidenceVersion[] }) {
  const latest = versions[versions.length - 1]
  return (
    <div>
      <h4 className="text-sm font-semibold text-foreground">Details</h4>
      <dl className="mt-2 divide-y divide-border/70 border-y border-border/70">
        <MetaRow label="Type">{humanize(core.type)}</MetaRow>
        <MetaRow label="Added by">{core.creator_name ?? "—"}</MetaRow>
        <MetaRow label="Added" mono>
          {formatDate(core.created_at)}
        </MetaRow>
        <MetaRow label="Updated" mono>
          {formatDate(core.updated_at)}
        </MetaRow>
        {latest ? (
          <>
            <MetaRow label="File" mono>
              {latest.file_name}
            </MetaRow>
            <MetaRow label="MIME type" mono>
              {latest.mime_type}
            </MetaRow>
            <MetaRow label="Size">{formatBytes(latest.file_size_bytes)}</MetaRow>
          </>
        ) : null}
      </dl>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Versions
// ---------------------------------------------------------------------------

function VersionTimeline({
  versions,
}: {
  versions: EvidenceVersion[]
}) {
  if (versions.length <= 1) return null
  return (
    <div>
      <h4 className="text-sm font-semibold text-foreground">
        Document versions
        <span className="ml-2 text-xs font-normal text-muted-foreground">
          {versions.length} total
        </span>
      </h4>
      <div className="mt-2 overflow-hidden rounded-lg border border-border/80 bg-background shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-border/80 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                <th scope="col" className="py-2 pl-4 pr-3 font-medium">
                  Version
                </th>
                <th scope="col" className="hidden px-3 py-2 font-medium sm:table-cell">
                  File
                </th>
                <th scope="col" className="hidden px-3 py-2 font-medium md:table-cell">
                  SHA-256
                </th>
                <th scope="col" className="px-3 py-2 font-medium">
                  Uploaded
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/70">
              {versions.map((version) => (
                <tr key={version.id}>
                  <td className="whitespace-nowrap py-2.5 pl-4 pr-3">
                    <span className="font-mono text-xs text-muted-foreground">
                      v{version.version}
                    </span>
                  </td>
                  <td className="hidden max-w-0 py-2.5 pl-3 pr-3 sm:table-cell">
                    <span className="block truncate font-mono text-[13px] text-foreground">
                      {version.file_name}
                    </span>
                    <span className="block font-mono text-xs text-muted-foreground">
                      {version.mime_type} · {formatBytes(version.file_size_bytes)}
                    </span>
                    {version.notes ? (
                      <span className="mt-0.5 block truncate text-xs text-muted-foreground">
                        {version.notes}
                      </span>
                    ) : null}
                  </td>
                  <td className="hidden py-2.5 pl-3 pr-3 md:table-cell">
                    <span className="font-mono text-xs text-muted-foreground">
                      {shortHash(version.sha256)}
                    </span>
                  </td>
                  <td className="whitespace-nowrap py-2.5 pl-3 pr-4 text-right">
                    <span className="font-mono text-xs text-muted-foreground">
                      {formatDate(version.uploaded_at)}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      <p className="mt-2 text-xs text-muted-foreground">
        Evidence is versioned, never overwritten; each immutable version carries
        its own integrity fingerprint and custody history.
      </p>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Integrity
// ---------------------------------------------------------------------------

function IntegrityPanel({ versions }: { versions: EvidenceVersion[] }) {
  const latest = versions[versions.length - 1]
  return (
    <div>
      <h4 className="flex items-center gap-1.5 text-sm font-semibold text-foreground">
        <ShieldCheck aria-hidden className="size-4 text-muted-foreground" />
        Integrity
      </h4>
      {latest ? (
        <div className="mt-2 space-y-1.5">
          <p className="text-xs text-muted-foreground">
            SHA-256 fingerprint of the latest version (for integrity
            verification only — it is not encryption).
          </p>
          <div className="flex items-center gap-2 rounded-md border border-border/80 bg-muted/40 px-2.5 py-2">
            <code className="min-w-0 break-all font-mono text-[13px] text-foreground">
              {latest.sha256}
            </code>
            <span className="shrink-0">
              <CopyButton value={latest.sha256} label="SHA-256 hash" />
            </span>
          </div>
        </div>
      ) : (
        <p className="mt-2 text-sm text-muted-foreground">
          No file version has been recorded for this evidence item.
        </p>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Blockchain verification / anchoring
// ---------------------------------------------------------------------------

type VerifyState =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "done"; frame: VerificationFrame }

function BlockchainPanel({
  caseId,
  versions,
  myRole,
  caseOpen,
  onVerified,
}: {
  caseId: string
  versions: EvidenceVersion[]
  myRole: string | null
  caseOpen: boolean
  onVerified: () => void
}) {
  const latest = versions[versions.length - 1]
  const [verifyState, setVerifyState] = React.useState<VerifyState>({
    status: "idle",
  })
  const [anchorState, setAnchorState] = React.useState<
    | { status: "idle" }
    | { status: "loading" }
    | { status: "done"; outcome: AnchorOutcomeBody }
    | { status: "error"; message: string }
  >({ status: "idle" })

  if (!latest) {
    return null
  }

  const anchor = latest.anchor
  const isTerminalAnchor =
    anchor?.status === "anchored" || anchor?.status === "failed"
  const canAnchor = caseOpen && (myRole === "lead" || myRole === "investigator")

  async function runVerification() {
    try {
      const res = await fetch(
        `/api/cases/${caseId}/evidence/${latest.id}/verification`,
        { cache: "no-store" },
      )
      const data = (await res.json().catch(() => ({}))) as {
        verification?: VerificationFrame
        error?: string
      }
      if (!res.ok || !data.verification) {
        setVerifyState({ status: "idle" })
        return
      }
      setVerifyState({ status: "done", frame: data.verification })
    } catch {
      setVerifyState({ status: "idle" })
    }
  }

  async function runAnchor() {
    setAnchorState({ status: "loading" })
    try {
      const res = await fetch(
        `/api/cases/${caseId}/evidence/${latest.id}/anchor`,
        { method: "POST" },
      )
      const data = (await res.json().catch(() => ({}))) as {
        anchor?: AnchorOutcomeBody
        error?: string
      }
      if (!res.ok || !data.anchor) {
        setAnchorState({
          status: "error",
          message: data.error ?? "Anchoring failed. Try again.",
        })
        return
      }
      setAnchorState({ status: "done", outcome: data.anchor })
      onVerified()
      setVerifyState({ status: "idle" })
    } catch {
      setAnchorState({
        status: "error",
        message: "Anchoring failed. Try again.",
      })
    }
  }

  return (
    <div>
      <h4 className="flex items-center gap-1.5 text-sm font-semibold text-foreground">
        <Lock aria-hidden className="size-4 text-muted-foreground" />
        Blockchain integrity
      </h4>

      <div className="mt-2 overflow-hidden rounded-lg border border-border/80 bg-background shadow-sm">
        <div className="border-b border-border/70 px-4 py-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-sm font-medium text-foreground">
              Anchor status
            </span>
            {anchor ? (
              <AnchorStatusBadge status={anchor.status} />
            ) : (
              <span className="text-sm text-muted-foreground">Not anchored</span>
            )}
          </div>
          {anchor ? (
            <dl className="mt-2 space-y-0.5">
              <AnchorMeta anchor={anchor} />
            </dl>
          ) : (
            <p className="mt-1 text-xs text-muted-foreground">
              This version has no blockchain anchor yet.
            </p>
          )}
        </div>

        {verifyState.status === "done" ? (
          <div className="border-b border-border/70 px-4 py-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-medium text-foreground">
                On-chain verification
              </span>
              <VerificationStatusBadge status={verifyState.frame.status} />
            </div>
            <VerificationFacts frame={verifyState.frame} />
          </div>
        ) : null}

        <div className="flex flex-wrap items-center gap-2 px-4 py-3">
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={runVerification}
            disabled={verifyState.status === "loading"}
          >
            {verifyState.status === "loading" ? (
              <Loader2 className="size-3.5 animate-spin" aria-hidden />
            ) : (
              <ShieldCheck aria-hidden className="size-3.5" />
            )}
            {verifyState.status === "loading"
              ? "Verifying"
              : "Run on-chain verification"}
          </Button>

          {!isTerminalAnchor && canAnchor ? (
            <Button
              type="button"
              size="sm"
              onClick={runAnchor}
              disabled={anchorState.status === "loading"}
            >
              {anchorState.status === "loading" ? (
                <Loader2 className="size-3.5 animate-spin" aria-hidden />
              ) : (
                <Lock aria-hidden className="size-3.5" />
              )}
              {anchorState.status === "loading"
                ? "Anchoring"
                : anchor?.status === "failed"
                  ? "Retry anchoring"
                  : "Anchor on chain"}
            </Button>
          ) : null}
        </div>

        {anchorState.status === "done" ? (
          <AnchorOutcome outcome={anchorState.outcome} />
        ) : null}
        {anchorState.status === "error" ? (
          <p
            role="alert"
            className="flex items-center gap-1.5 border-t border-border/70 px-4 py-2.5 text-sm text-danger"
          >
            <AlertCircle className="size-4 shrink-0" aria-hidden />
            <span>{anchorState.message}</span>
          </p>
        ) : null}
      </div>

      <p className="mt-2 text-xs text-muted-foreground">
        “Anchored” reports the blockchain state recorded in this system. On-chain
        verification independently re-reads the contract to confirm the
        fingerprint matches this version.
      </p>
    </div>
  )
}

function AnchorMeta({ anchor }: { anchor: AnchorContext }) {
  return (
    <div className="space-y-1 text-xs text-muted-foreground">
      <div className="flex flex-wrap items-center gap-x-2">
        <span className="w-24 shrink-0 uppercase tracking-wide">Network</span>
        <span className="font-mono text-foreground">{anchor.network}</span>
        <span className="font-mono">(chain {anchor.chain_id})</span>
      </div>
      <div className="flex items-start gap-2">
        <span className="w-24 shrink-0 pt-px uppercase tracking-wide">Contract</span>
        <code className="min-w-0 break-all font-mono text-foreground">
          {anchor.contract_address || "—"}
        </code>
        {anchor.contract_address ? (
          <CopyButton value={anchor.contract_address} label="contract address" />
        ) : null}
      </div>
      {anchor.tx_hash ? (
        <div className="flex items-start gap-2">
          <span className="w-24 shrink-0 pt-px uppercase tracking-wide">
            Tx hash
          </span>
          <code className="min-w-0 break-all font-mono text-foreground">
            {anchor.tx_hash}
          </code>
          <CopyButton value={anchor.tx_hash} label="transaction hash" />
        </div>
      ) : null}
      {anchor.block_number ? (
        <div className="flex flex-wrap items-center gap-x-2">
          <span className="w-24 shrink-0 uppercase tracking-wide">Block</span>
          <span className="font-mono text-foreground">
            {anchor.block_number}
          </span>
          {anchor.anchored_at ? (
            <span className="font-mono">{formatDate(anchor.anchored_at)}</span>
          ) : null}
        </div>
      ) : null}
      {anchor.error_message ? (
        <p className="text-danger">{anchor.error_message}</p>
      ) : null}
    </div>
  )
}

function VerificationFacts({ frame }: { frame: VerificationFrame }) {
  if (frame.status === "hash_mismatch") {
    return (
      <p className="mt-1 flex items-start gap-1.5 text-sm text-danger">
        <AlertCircle className="mt-0.5 size-4 shrink-0" aria-hidden />
        <span>{frame.message ?? "The fingerprint does not match the anchor."}</span>
      </p>
    )
  }
  if (frame.status === "verification_ambiguous") {
    return (
      <p className="mt-1 text-sm text-muted-foreground">
        {frame.message ??
          "The blockchain could not be read reliably; no verdict is concluded."}
      </p>
    )
  }
  if (frame.status === "verified" && frame.blockchain) {
    const facts = frame.blockchain
    return (
      <div className="mt-1 space-y-0.5 text-xs text-muted-foreground">
        <p className="flex items-center gap-1.5 text-sm text-foreground">
          <CheckCircle2 aria-hidden className="size-4 text-success" />
          An on-chain anchor matches this version&apos;s SHA-256.
        </p>
        <div className="flex items-center gap-2">
          <span className="w-24 shrink-0 uppercase tracking-wide">Stored SHA</span>
          <code className="min-w-0 break-all font-mono text-foreground">
            {facts.stored_sha256 ?? "—"}
          </code>
          {facts.stored_sha256 ? (
            <CopyButton value={facts.stored_sha256} label="stored SHA-256" />
          ) : null}
        </div>
        {facts.block_number ? (
          <div className="flex flex-wrap items-center gap-x-2">
            <span className="w-24 shrink-0 uppercase tracking-wide">Block</span>
            <span className="font-mono text-foreground">{facts.block_number}</span>
            {facts.anchored_at ? (
              <span className="font-mono">{formatDate(facts.anchored_at)}</span>
            ) : null}
          </div>
        ) : null}
        <div className="flex items-center gap-2">
          <span className="w-24 shrink-0 uppercase tracking-wide">Network</span>
          <span className="font-mono text-foreground">{facts.network}</span>
          <span className="font-mono">chain {facts.chain_id}</span>
        </div>
      </div>
    )
  }
  if (frame.status === "not_anchored") {
    return (
      <p className="mt-1 text-sm text-muted-foreground">
        This version has no matching anchor on-chain yet.
      </p>
    )
  }
  return null
}

const ANCHOR_OUTCOME_LABEL: Record<AnchorOutcomeBody["status"], string> = {
  anchored: "Anchored on chain.",
  reconciled: "Confirmed on-chain; the record was reconciled without a new transaction.",
  already_anchored: "This version was already anchored.",
  verification_ambiguous: "Anchoring submitted; on-chain confirmation could not be verified.",
  db_sync_failed: "The transaction is on chain, but the record could not be synced. Retry to reconcile.",
  failed: "Anchoring failed.",
  verification_failed: "Anchoring failed during on-chain verification.",
}

function AnchorOutcome({ outcome }: { outcome: AnchorOutcomeBody }) {
  const ok = outcome.status === "anchored" || outcome.status === "reconciled"
  return (
    <div
      role="status"
      className={cn(
        "flex items-start gap-2 border-t border-border/70 px-4 py-2.5 text-sm",
        ok ? "text-foreground" : "text-warning",
      )}
    >
      {ok ? (
        <CheckCircle2 aria-hidden className="mt-0.5 size-4 shrink-0 text-success" />
      ) : (
        <AlertCircle aria-hidden className="mt-0.5 size-4 shrink-0 text-warning" />
      )}
      <div className="min-w-0">
        <p className="font-medium">
          {ANCHOR_OUTCOME_LABEL[outcome.status]}
        </p>
        {outcome.tx_hash ? (
          <div className="mt-1 flex items-center gap-2">
            <code className="min-w-0 break-all font-mono text-xs text-muted-foreground">
              {outcome.tx_hash}
            </code>
            <CopyButton value={outcome.tx_hash} label="transaction hash" />
          </div>
        ) : null}
        {outcome.block_number ? (
          <p className="font-mono text-xs text-muted-foreground">
            block {outcome.block_number}
            {outcome.anchored_at ? ` · ${formatDate(outcome.anchored_at)}` : ""}
          </p>
        ) : null}
        {outcome.message ? (
          <p className="text-xs text-muted-foreground">{outcome.message}</p>
        ) : null}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Chain of custody
// ---------------------------------------------------------------------------

const CUSTODY_ACTION_LABEL: Record<string, string> = {
  received: "Received",
  transferred: "Transferred",
  returned: "Returned",
  verified: "Verified",
  released: "Released",
  archived: "Archived",
}

function CustodyPanel({ custody }: { custody: CustodyEntry[] }) {
  return (
    <div>
      <h4 className="flex items-center gap-1.5 text-sm font-semibold text-foreground">
        <History aria-hidden className="size-4 text-muted-foreground" />
        Chain of custody
      </h4>
      {custody.length === 0 ? (
        <p className="mt-2 rounded-lg border border-border/80 bg-background px-4 py-5 text-sm text-muted-foreground">
          No custody events have been recorded for this evidence item.
        </p>
      ) : (
        <div className="mt-2 overflow-hidden rounded-lg border border-border/80 bg-background shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="border-b border-border/80 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                  <th scope="col" className="py-2 pl-4 pr-3 font-medium">
                    Action
                  </th>
                  <th scope="col" className="hidden px-3 py-2 font-medium sm:table-cell">
                    Actor
                  </th>
                  <th scope="col" className="hidden px-3 py-2 font-medium md:table-cell">
                    Location
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    When
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/70">
                {custody.map((entry) => (
                  <tr key={entry.id}>
                    <td className="whitespace-nowrap py-2.5 pl-4 pr-3 font-medium text-foreground">
                      {CUSTODY_ACTION_LABEL[entry.action] ?? humanize(entry.action)}
                    </td>
                    <td className="hidden py-2.5 pl-3 pr-3 sm:table-cell">
                      <span className="text-foreground">
                        {entry.actor_name ?? "—"}
                      </span>
                      <span className="ml-2 font-mono text-xs text-muted-foreground">
                        {shortHash(entry.actor_id, 5)}
                      </span>
                    </td>
                    <td className="hidden max-w-0 py-2.5 pl-3 pr-3 md:table-cell">
                      <span className="block truncate text-muted-foreground">
                        {entry.location ?? "—"}
                      </span>
                    </td>
                    <td className="whitespace-nowrap py-2.5 pl-3 pr-4 text-right">
                      <span className="font-mono text-xs text-muted-foreground">
                        {formatDate(entry.occurred_at)}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {custody.some((e) => e.notes) ? (
            <div className="border-t border-border/70 px-4 py-2">
              {custody
                .filter((e) => e.notes)
                .map((e) => (
                  <p key={e.id} className="text-xs text-muted-foreground">
                    <span className="font-medium">{CUSTODY_ACTION_LABEL[e.action] ?? e.action}:</span>{" "}
                    {e.notes}
                  </p>
                ))}
            </div>
          ) : null}
        </div>
      )}
      <p className="mt-2 text-xs text-muted-foreground">
        Chain of custody records who handled each version of this evidence.
      </p>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Audit trail
// ---------------------------------------------------------------------------

// Rendered inline via EvidenceAuditSection (the evidence-scoped audit read).