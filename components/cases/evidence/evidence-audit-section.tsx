"use client"

import * as React from "react"
import { FileText } from "lucide-react"
import { AuditEventList } from "@/components/cases/audit/audit-event-list"
import type { AuditEventItem } from "@/lib/audit-serialization"

type AuditState =
  | { status: "loading" }
  | { status: "error" }
  | { status: "ready"; events: AuditEventItem[] }

// Evidence-scoped audit trail, shown on the evidence detail page. Data comes
// from GET /api/cases/[id]/evidence/[evidenceId]/audit, whose SECURITY
// DEFINER RPC enforces membership of the evidence's own case; this component
// only renders the already-sanitized events.
export function EvidenceAuditSection({
  caseId,
  evidenceId,
}: {
  caseId: string
  evidenceId: string
}) {
  const [state, setState] = React.useState<AuditState>({ status: "loading" })
  const [reloadKey, setReloadKey] = React.useState(0)

  React.useEffect(() => {
    let cancelled = false

    async function load() {
      setState({ status: "loading" })
      let res: Response
      try {
        res = await fetch(`/api/cases/${caseId}/evidence/${evidenceId}/audit`, {
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
        events?: AuditEventItem[]
      }
      if (cancelled) return
      setState({ status: "ready", events: data.events ?? [] })
    }

    load()
    return () => {
      cancelled = true
    }
  }, [caseId, evidenceId, reloadKey])

  return (
    <div>
      <h4 className="flex items-center gap-1.5 text-sm font-semibold text-foreground">
        <FileText aria-hidden className="size-4 text-muted-foreground" />
        Audit trail
      </h4>
      <p className="mt-1 text-xs text-muted-foreground">
        Operational events for this evidence — uploads, fingerprints, anchors,
        verifications and status changes. Separate from the chain of custody,
        which records who physically handled the file.
      </p>

      <div className="mt-3">
        {state.status === "loading" ? (
          <div className="space-y-2" aria-busy="true" aria-label="Loading evidence audit trail">
            <div className="h-11 animate-pulse rounded-lg border border-border/60 bg-muted/40" />
            <div className="h-11 animate-pulse rounded-lg border border-border/60 bg-muted/40" />
          </div>
        ) : state.status === "error" ? (
          <button
            type="button"
            onClick={() => setReloadKey((k) => k + 1)}
            className="w-full rounded-lg border border-border/80 bg-background px-4 py-4 text-left text-sm text-muted-foreground hover:border-border"
          >
            Could not load the audit trail. Click to retry.
          </button>
        ) : (
          <AuditEventList
            events={state.events}
            emptyText="No audit events have been recorded for this evidence item yet."
          />
        )}
      </div>
    </div>
  )
}