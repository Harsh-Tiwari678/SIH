"use client"

import * as React from "react"
import { DashboardHeader } from "@/components/dashboard/dashboard-header"
import { SummaryStrip } from "@/components/dashboard/dashboard-summary"
import { CaseTableContent } from "@/components/dashboard/case-table"
import type { DashboardCase } from "@/components/dashboard/case-table"

type CasesState =
  | { status: "loading" }
  | { status: "unauthorized" }
  | { status: "error" }
  | { status: "empty" }
  | { status: "ready"; cases: DashboardCase[] }

export function DashboardOverview() {
  const [state, setState] = React.useState<CasesState>({ status: "loading" })
  const [reloadKey, setReloadKey] = React.useState(0)

  React.useEffect(() => {
    let cancelled = false

    async function load() {
      let res: Response
      try {
        res = await fetch("/api/cases", { cache: "no-store" })
      } catch {
        if (!cancelled) setState({ status: "error" })
        return
      }
      if (cancelled) return

      if (res.status === 401) {
        setState({ status: "unauthorized" })
        return
      }
      if (!res.ok) {
        setState({ status: "error" })
        return
      }

      const data = (await res.json().catch(() => ({ cases: [] }))) as {
        cases?: DashboardCase[]
      }
      if (cancelled) return

      const cases = Array.isArray(data.cases) ? data.cases : []
      if (cases.length === 0) {
        setState({ status: "empty" })
      } else {
        setState({ status: "ready", cases })
      }
    }

    load()
    return () => {
      cancelled = true
    }
  }, [reloadKey])

  const summary = React.useMemo(() => {
    if (state.status !== "ready" && state.status !== "empty") return null
    const cases =
      state.status === "ready" ? state.cases : []
    const byStatus: Record<string, number> = {}
    for (const c of cases) {
      byStatus[c.status] = (byStatus[c.status] ?? 0) + 1
    }
    return { total: cases.length, byStatus }
  }, [state])

  const headerCount =
    state.status === "ready"
      ? state.cases.length
      : state.status === "empty"
        ? 0
        : null

  return (
    <div className="space-y-6 sm:space-y-8">
      <DashboardHeader caseCount={headerCount} onCreated={handleCreated} />

      <SummaryStrip summary={summary} />

      <section aria-labelledby="your-cases-heading">
        <h2
          id="your-cases-heading"
          className="mb-2 text-base font-semibold text-foreground"
        >
          Your cases
        </h2>
        <CaseTableContent state={state} />
      </section>
    </div>
  )

  function handleCreated() {
    setReloadKey((k) => k + 1)
  }
}