"use client"

import * as React from "react"
import { AlertCircle, History } from "lucide-react"
import { Button } from "@/components/ui/button"
import { AuditEventList } from "@/components/cases/audit/audit-event-list"
import type { AuditEventItem } from "@/lib/audit-serialization"

type AuditState =
  | { status: "loading" }
  | { status: "error" }
  | { status: "ready"; events: AuditEventItem[] }

// Case-level audit trail (Audit tab). Data comes from GET /api/cases/[id]/audit,
// whose SECURITY DEFINER RPC enforces membership; this component only renders
// the already-sanitized events.
export function AuditPanel({ caseId }: { caseId: string }) {
  const [state, setState] = React.useState<AuditState>({ status: "loading" })
  const [reloadKey, setReloadKey] = React.useState(0)

  React.useEffect(() => {
    let cancelled = false

    async function load() {
      setState({ status: "loading" })
      let res: Response
      try {
        res = await fetch(`/api/cases/${caseId}/audit`, {
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
  }, [caseId, reloadKey])

  return (
    <div>
      <div className="flex items-center gap-1.5">
        <h3 className="flex items-center gap-1.5 text-sm font-semibold text-foreground">
          <History aria-hidden className="size-4 text-muted-foreground" />
          Audit trail
        </h3>
      </div>
      <p className="mt-1 max-w-2xl text-xs text-muted-foreground">
        Who did what, when, on this case. Events are recorded server-side from
        the signed-in session identity; the trail is append-only and cannot be
        edited by users.
      </p>

      <div className="mt-3">
        {state.status === "loading" ? (
          <AuditListSkeleton />
        ) : state.status === "error" ? (
          <div className="flex flex-col items-center justify-center rounded-lg border border-border/80 bg-background px-6 py-10 text-center">
            <div className="flex size-9 items-center justify-center rounded-full border border-border/70 bg-muted/50 text-muted-foreground">
              <AlertCircle className="size-4" aria-hidden />
            </div>
            <p className="mt-3 text-sm text-muted-foreground">
              We could not load the audit trail right now.
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
        ) : (
          <AuditEventList
            events={state.events}
            emptyText="No audit events have been recorded for this case yet."
          />
        )}
      </div>
    </div>
  )
}

export function AuditListSkeleton() {
  return (
    <div className="space-y-2" aria-busy="true" aria-label="Loading audit trail">
      <div className="h-12 animate-pulse rounded-lg border border-border/60 bg-muted/40" />
      <div className="h-12 animate-pulse rounded-lg border border-border/60 bg-muted/40" />
      <div className="h-12 animate-pulse rounded-lg border border-border/60 bg-muted/40" />
    </div>
  )
}