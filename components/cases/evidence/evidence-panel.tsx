"use client"

import * as React from "react"
import { AlertTriangle } from "lucide-react"
import { Button } from "@/components/ui/button"
import { EvidenceList } from "@/components/cases/evidence/evidence-list"
import { EvidenceDetail } from "@/components/cases/evidence/evidence-detail"
import type { EvidenceListItem } from "@/lib/evidence-serialization"
import type { CaseDetail } from "@/components/cases/case-detail"

type PanelState =
  | { status: "loading" }
  | { status: "error" }
  | { status: "ready"; evidence: EvidenceListItem[] }

export function EvidencePanel({
  caseId,
  caseDetail,
  myRole,
  evidenceId,
  onSelect,
  onBack,
}: {
  caseId: string
  caseDetail: CaseDetail
  myRole: string | null
  evidenceId: string | null
  onSelect: (evidenceId: string) => void
  onBack: () => void
}) {
  const [state, setState] = React.useState<PanelState>({ status: "loading" })
  const [reloadKey, setReloadKey] = React.useState(0)

  React.useEffect(() => {
    let cancelled = false

    async function load() {
      let res: Response
      try {
        res = await fetch(`/api/cases/${caseId}/evidence`, { cache: "no-store" })
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
        evidence?: EvidenceListItem[]
      }
      if (cancelled) return
      setState({
        status: "ready",
        evidence: Array.isArray(data.evidence) ? data.evidence : [],
      })
    }

    load()
    return () => {
      cancelled = true
    }
  }, [caseId, reloadKey])

  if (evidenceId) {
    return (
      <EvidenceDetail
        caseId={caseId}
        evidenceId={evidenceId}
        myRole={myRole}
        caseOpen={caseStatusOpen(caseDetail.status)}
        caseMembers={caseDetail.case_members ?? []}
        onBack={onBack}
      />
    )
  }

  return (
    <div className="space-y-4">
      {state.status === "loading" ? (
        <div aria-busy="true" aria-label="Loading evidence" className="space-y-3">
          <div className="h-5 w-32 animate-pulse rounded bg-muted/60" />
          <div className="h-9 animate-pulse rounded-md bg-muted/40" />
          <div className="h-52 animate-pulse rounded-lg border border-border/60 bg-muted/40" />
        </div>
      ) : state.status === "error" ? (
        <div className="flex flex-col items-center justify-center rounded-lg border border-border/80 bg-background px-6 py-12 text-center">
          <div className="flex size-9 items-center justify-center rounded-full border border-border/70 bg-muted/50 text-muted-foreground">
            <AlertTriangle className="size-4" aria-hidden />
          </div>
          <h3 className="mt-4 text-sm font-semibold text-foreground">
            Could not load evidence
          </h3>
          <p className="mt-1 max-w-sm text-sm text-muted-foreground">
            We could not load the evidence list for this case right now.
          </p>
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="mt-4"
            onClick={() => setReloadKey((k) => k + 1)}
          >
            Try again
          </Button>
        </div>
      ) : (
        <EvidenceList
          caseId={caseId}
          evidence={state.evidence}
          caseNumber={caseDetail.case_number}
          myRole={myRole}
          caseOpen={caseStatusOpen(caseDetail.status)}
          onSelect={onSelect}
          onReload={() => setReloadKey((k) => k + 1)}
        />
      )}
    </div>
  )
}

function caseStatusOpen(status: string): boolean {
  return status === "draft" || status === "active"
}