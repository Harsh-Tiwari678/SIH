"use client"

import {
  CaseTable,
  CouldNotLoadCases,
  EmptyCases,
  LoadingCases,
  SessionExpiredCases,
} from "@/components/cases/case-table"
import type { CaseRecord } from "@/components/cases/case-table"

export type DashboardCase = CaseRecord

type State =
  | { status: "loading" }
  | { status: "unauthorized" }
  | { status: "error" }
  | { status: "empty" }
  | { status: "ready"; cases: DashboardCase[] }

export function CaseTableContent({ state }: { state: State }) {
  if (state.status === "loading") {
    return <LoadingCases />
  }

  if (state.status === "unauthorized") {
    return <SessionExpiredCases />
  }

  if (state.status === "error") {
    return <CouldNotLoadCases />
  }

  if (state.status === "empty") {
    return <EmptyCases />
  }

  const { cases } = state

  return (
    <div className="overflow-hidden rounded-lg border border-border/80 bg-background shadow-sm">
      <div className="overflow-x-auto">
        <CaseTable cases={cases} />
      </div>
      <p className="border-t border-border/80 px-4 py-2 text-xs text-muted-foreground">
        {cases.length} {cases.length === 1 ? "case" : "cases"}
      </p>
    </div>
  )
}