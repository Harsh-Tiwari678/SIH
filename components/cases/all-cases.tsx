"use client"

import * as React from "react"
import { Search } from "lucide-react"
import { Input } from "@/components/ui/input"
import { NewCaseForm } from "@/components/cases/new-case-form"
import {
  CaseTable,
  CouldNotLoadCases,
  EmptyCases,
  LoadingCases,
  SessionExpiredCases,
} from "@/components/cases/case-table"
import type { CaseRecord } from "@/components/cases/case-table"
import { cn } from "@/lib/utils"

type CasesState =
  | { status: "loading" }
  | { status: "unauthorized" }
  | { status: "error" }
  | { status: "empty" }
  | { status: "ready"; cases: CaseRecord[] }

const STATUS_OPTIONS = [
  { value: "all", label: "All statuses" },
  { value: "draft", label: "Draft" },
  { value: "active", label: "Active" },
  { value: "closed", label: "Closed" },
  { value: "archived", label: "Archived" },
] as const

type StatusFilter = (typeof STATUS_OPTIONS)[number]["value"]

function matches(c: CaseRecord, query: string, status: StatusFilter): boolean {
  if (status !== "all" && c.status !== status) return false
  if (!query) return true
  const q = query.toLowerCase()
  return (
    c.case_number.toLowerCase().includes(q) ||
    c.title.toLowerCase().includes(q) ||
    (c.description ?? "").toLowerCase().includes(q)
  )
}

export function AllCases() {
  const [state, setState] = React.useState<CasesState>({ status: "loading" })
  const [reloadKey, setReloadKey] = React.useState(0)
  const [query, setQuery] = React.useState("")
  const [status, setStatus] = React.useState<StatusFilter>("all")

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
        cases?: CaseRecord[]
      }
      if (cancelled) return

      const cases = Array.isArray(data.cases) ? data.cases : []
      setState(
        cases.length === 0 ? { status: "empty" } : { status: "ready", cases },
      )
      setQuery("")
      setStatus("all")
    }

    load()
    return () => {
      cancelled = true
    }
  }, [reloadKey])

  const ready = state.status === "ready" ? state.cases : []
  const filtered = ready.filter((c) => matches(c, query, status))

  const subheading = React.useMemo(() => {
    if (state.status === "empty") {
      return "Create a case to begin recording evidence."
    }
    if (state.status === "ready") {
      const n = ready.length
      return `${n} ${n === 1 ? "case" : "cases"} you can access.`
    }
    return "Cases you created or are a member of."
  }, [state, ready.length])

  return (
    <div className="space-y-6 sm:space-y-8">
      <header className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-foreground">
            All Cases
          </h1>
          <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
            {subheading}
          </p>
        </div>
        <div className="shrink-0">
          <NewCaseForm onCreated={handleCreated} />
        </div>
      </header>

      {state.status === "ready" ? (
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div className="relative w-full sm:max-w-xs">
            <Search
              aria-hidden
              className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
            />
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search case number or title"
              aria-label="Search cases"
              className="pl-8"
            />
          </div>
          <label className="flex items-center gap-2 text-sm text-muted-foreground">
            <span className="sr-only">Status</span>
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value as StatusFilter)}
              className={cn(
                "h-8 rounded-md border border-input bg-background px-2.5 text-sm text-foreground shadow-sm outline-none transition-colors duration-150 ease-out-quick",
                "focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50",
              )}
            >
              {STATUS_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </label>
        </div>
      ) : null}

      <section aria-labelledby="cases-list-heading">
        <h2 id="cases-list-heading" className="sr-only">
          Cases
        </h2>
        {renderContent()}
      </section>
    </div>
  )

  function renderContent() {
    switch (state.status) {
      case "loading":
        return <LoadingCases />
      case "unauthorized":
        return <SessionExpiredCases />
      case "error":
        return <CouldNotLoadCases />
      case "empty":
        return <EmptyCases />
      default: {
        if (filtered.length === 0) {
          return (
            <p className="rounded-lg border border-border/80 bg-background px-4 py-6 text-sm text-muted-foreground">
              No cases match the current search or filter.
            </p>
          )
        }
        return (
          <div className="overflow-hidden rounded-lg border border-border/80 bg-background shadow-sm">
            <div className="overflow-x-auto">
              <CaseTable cases={filtered} />
            </div>
            <p className="border-t border-border/80 px-4 py-2 text-xs text-muted-foreground">
              {filtered.length} {filtered.length === 1 ? "case" : "cases"}
              {query || status !== "all"
                ? " shown"
                : ""}
            </p>
          </div>
        )
      }
    }
  }

  function handleCreated() {
    setReloadKey((k) => k + 1)
  }
}