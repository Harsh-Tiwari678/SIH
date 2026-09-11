"use client"

import * as React from "react"
import { AlertTriangle } from "lucide-react"
import { CaseHeader } from "@/components/cases/case-header"
import { RoleBadge } from "@/components/cases/status-badge"
import { AuditPanel } from "@/components/cases/audit/audit-panel"
import { MembersNote } from "@/components/cases/read-gap"
import { EvidencePanel } from "@/components/cases/evidence/evidence-panel"
import type { CaseDetail } from "@/components/cases/case-detail"
import { cn } from "@/lib/utils"
import { formatDate } from "@/lib/format"

type WorkspaceState =
  | { status: "loading" }
  | { status: "unauthorized" }
  | { status: "not_found" }
  | { status: "error" }
  | { status: "ready"; caseDetail: CaseDetail; myRole: string | null }

const TABS = [
  { id: "overview", label: "Overview" },
  { id: "evidence", label: "Evidence" },
  { id: "members", label: "Members" },
  { id: "audit", label: "Audit" },
] as const

type TabId = (typeof TABS)[number]["id"]

export function CaseWorkspace({
  caseId,
  initialTab = "overview",
  initialEvidenceId,
}: {
  caseId: string
  initialTab?: string
  initialEvidenceId?: string
}) {
  const [state, setState] = React.useState<WorkspaceState>({
    status: "loading",
  })
  const [reloadKey, setReloadKey] = React.useState(0)
  const [tab, setTab] = React.useState<TabId>(() =>
    isTab(initialTab) ? initialTab : "overview",
  )
  const [evidenceId, setEvidenceId] = React.useState<string | null>(
    initialEvidenceId ?? null,
  )

  React.useEffect(() => {
    let cancelled = false

    async function load() {
      let res: Response
      try {
        res = await fetch(`/api/cases/${caseId}`, { cache: "no-store" })
      } catch {
        if (!cancelled) setState({ status: "error" })
        return
      }
      if (cancelled) return

      if (res.status === 401) {
        setState({ status: "unauthorized" })
        return
      }
      if (res.status === 404) {
        setState({ status: "not_found" })
        return
      }
      if (!res.ok) {
        setState({ status: "error" })
        return
      }

      const data = (await res.json().catch(() => ({}))) as {
        case?: CaseDetail
        my_role?: string | null
      }
      if (cancelled) return

      if (!data.case) {
        setState({ status: "error" })
        return
      }
      setState({
        status: "ready",
        caseDetail: data.case,
        myRole: data.my_role ?? null,
      })
    }

    load()
    return () => {
      cancelled = true
    }
  }, [caseId, reloadKey])

  function selectEvidence(nextEvidenceId: string) {
    setEvidenceId(nextEvidenceId)
    setTab("evidence")
    history.replaceState(
      null,
      "",
      `${caseBasePath()}?tab=evidence&evidence=${encodeURIComponent(nextEvidenceId)}`,
    )
  }

  function backToEvidence() {
    setEvidenceId(null)
    history.replaceState(null, "", `${caseBasePath()}?tab=evidence`)
  }

  if (state.status === "loading") {
    return <WorkspaceSkeleton />
  }

  if (state.status === "unauthorized") {
    return (
      <WorkspaceMessage
        title="Session expired"
        message="Your session has expired. Sign in again to view this case."
      />
    )
  }

  if (state.status === "not_found") {
    return (
      <WorkspaceMessage
        title="Case not found"
        message="This case does not exist or you do not have access to it."
      />
    )
  }

  if (state.status === "error") {
    return (
      <WorkspaceMessage
        title="Could not load case"
        message="We could not load this case right now. Try refreshing the page."
      />
    )
  }

  const { caseDetail, myRole } = state

  return (
    <div className="space-y-6 sm:space-y-8">
      <CaseHeader
        caseDetail={caseDetail}
        myRole={myRole}
        onSaved={() => setReloadKey((k) => k + 1)}
      />

      <div
        role="tablist"
        aria-label="Case sections"
        className="flex gap-6 overflow-x-auto border-b border-border/70"
      >
        {TABS.map((t) => (
          <button
            key={t.id}
            role="tab"
            id={`tab-${t.id}`}
            aria-selected={tab === t.id}
            aria-controls={`panel-${t.id}`}
            onClick={() => {
              setTab(t.id)
              setEvidenceId(null)
              const base = caseBasePath()
              history.replaceState(
                null,
                "",
                t.id === "overview"
                  ? base
                  : `${base}?tab=${encodeURIComponent(t.id)}`,
              )
            }}
            className={cn(
              "-mb-px border-b-2 px-1 pb-2 text-sm transition-colors duration-150 ease-out-quick",
              tab === t.id
                ? "border-primary font-medium text-foreground"
                : "border-transparent text-muted-foreground hover:text-foreground",
            )}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div
        role="tabpanel"
        id={`panel-${tab}`}
        aria-labelledby={`tab-${tab}`}
        className="min-w-0"
      >
        {tab === "overview" ? (
          <OverviewPanel caseDetail={caseDetail} />
        ) : null}
        {tab === "evidence" ? (
          <EvidencePanel
            caseId={caseId}
            caseDetail={caseDetail}
            myRole={myRole}
            evidenceId={evidenceId}
            onSelect={selectEvidence}
            onBack={backToEvidence}
          />
        ) : null}
        {tab === "members" ? (
          <MembersPanel caseDetail={caseDetail} />
        ) : null}
        {tab === "audit" ? <AuditPanel caseId={caseId} /> : null}
      </div>
    </div>
  )
}

function WorkspaceSkeleton() {
  return (
    <div className="space-y-6 sm:space-y-8" aria-busy="true" aria-label="Loading case">
      <div className="space-y-3">
        <div className="h-4 w-32 animate-pulse rounded bg-muted/60" />
        <div className="h-7 w-64 animate-pulse rounded bg-muted/60" />
      </div>
      <div className="h-10 animate-pulse rounded-lg border border-border/60 bg-muted/40" />
      <div className="h-32 animate-pulse rounded-lg border border-border/60 bg-muted/40" />
    </div>
  )
}

function WorkspaceMessage({
  title,
  message,
}: {
  title: string
  message: string
}) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-border/80 bg-background px-6 py-12 text-center">
      <div className="flex size-9 items-center justify-center rounded-full border border-border/70 bg-muted/50 text-muted-foreground">
        <AlertTriangle className="size-4" aria-hidden />
      </div>
      <h2 className="mt-4 text-sm font-semibold text-foreground">{title}</h2>
      <p className="mt-1 max-w-sm text-sm text-muted-foreground">{message}</p>
    </div>
  )
}

function DetailItem({
  label,
  value,
  mono = false,
}: {
  label: string
  value: string
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
        {value}
      </dd>
    </div>
  )
}

function OverviewPanel({ caseDetail }: { caseDetail: CaseDetail }) {
  return (
    <div>
      <h3 className="text-sm font-semibold text-foreground">Case details</h3>
      <dl className="mt-2 divide-y divide-border/70 border-y border-border/70">
        <DetailItem label="Case number" value={caseDetail.case_number} mono />
        <DetailItem label="Status" value={capitalize(caseDetail.status)} />
        <DetailItem label="Case ID" value={caseDetail.id} mono />
        <DetailItem label="Created" value={formatDate(caseDetail.created_at)} mono />
        <DetailItem label="Updated" value={formatDate(caseDetail.updated_at)} mono />
        {caseDetail.closed_at ? (
          <DetailItem
            label="Closed"
            value={formatDate(caseDetail.closed_at)}
            mono
          />
        ) : null}
      </dl>
    </div>
  )
}

function MembersPanel({ caseDetail }: { caseDetail: CaseDetail }) {
  const members = caseDetail.case_members ?? []

  return (
    <div>
      <div className="mb-2 flex items-center justify-between gap-2">
        <h3 className="text-sm font-semibold text-foreground">
          Members
        </h3>
        <span className="text-xs text-muted-foreground">
          {members.length} {members.length === 1 ? "member" : "members"}
        </span>
      </div>

      {members.length === 0 ? (
        <p className="rounded-lg border border-border/80 bg-background px-4 py-6 text-sm text-muted-foreground">
          No members are listed for this case.
        </p>
      ) : (
        <div className="overflow-hidden rounded-lg border border-border/80 bg-background shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="border-b border-border/80 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                  <th scope="col" className="py-2 pl-4 pr-3 font-medium">
                    Member
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    Role
                  </th>
                  <th scope="col" className="hidden py-2 pl-3 pr-4 text-right font-medium sm:table-cell">
                    Added
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/70">
                {members.map((m) => (
                  <tr key={m.profile_id}>
                    <td className="py-2.5 pl-4 pr-3">
                      <span className="font-medium text-foreground">
                        {m.profiles?.full_name ?? shortId(m.profile_id)}
                      </span>
                      <span className="ml-2 font-mono text-xs text-muted-foreground">
                        {shortId(m.profile_id)}
                      </span>
                    </td>
                    <td className="px-3 py-2.5">
                      <RoleBadge role={m.role_in_case} />
                    </td>
                    <td className="hidden py-2.5 pl-3 pr-4 text-right align-top sm:table-cell">
                      <span className="whitespace-nowrap font-mono text-xs text-muted-foreground">
                        {formatDate(m.added_at)}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="mt-3">
        <MembersNote />
      </div>
    </div>
  )
}

function shortId(id: string): string {
  return id.slice(0, 8)
}

function isTab(value: string): value is TabId {
  return (TABS as readonly { id: TabId }[]).some((t) => t.id === value)
}

function caseBasePath(): string {
  if (typeof window === "undefined") return ""
  return window.location.pathname.replace(/\/$/, "") || ""
}

function capitalize(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1)
}