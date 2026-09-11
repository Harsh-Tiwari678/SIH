"use client"

import * as React from "react"
import { FileText, Search, X } from "lucide-react"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { AddEvidenceDialog } from "@/components/cases/evidence/add-evidence-dialog"
import { EvidenceStatusBadge } from "@/components/cases/status-badge"
import {
  EVIDENCE_TYPES,
  type EvidenceListItem,
} from "@/lib/evidence-serialization"
import {
  humanize,
  shortHash,
} from "@/components/cases/evidence/evidence"
import { formatDate } from "@/lib/format"

const STATUS_OPTIONS: Array<{
  value: string
  label: string
}> = [
  { value: "received", label: "Received" },
  { value: "under_review", label: "Under review" },
  { value: "verified", label: "Verified" },
  { value: "rejected", label: "Rejected" },
  { value: "archived", label: "Archived" },
]

export function EvidenceList({
  caseId,
  evidence,
  caseNumber,
  myRole,
  caseOpen,
  onSelect,
  onReload,
}: {
  caseId: string
  evidence: EvidenceListItem[]
  caseNumber: string
  myRole: string | null
  caseOpen: boolean
  onSelect: (evidenceId: string) => void
  onReload: () => void
}) {
  const [query, setQuery] = React.useState("")
  const [typeFilter, setTypeFilter] = React.useState<string>("all")
  const [statusFilter, setStatusFilter] = React.useState<string>("all")
  const canAdd = caseOpen && (myRole === "lead" || myRole === "investigator")
  const filtered = React.useMemo(() => {
    const q = query.trim().toLowerCase()
    return evidence.filter((item) => {
      if (typeFilter !== "all" && item.type !== typeFilter) return false
      if (statusFilter !== "all" && item.status !== statusFilter) return false
      if (!q) return true
      return (
        item.evidence_number.toLowerCase().includes(q) ||
        item.title.toLowerCase().includes(q)
      )
    })
  }, [evidence, query, typeFilter, statusFilter])

  const hasFilters = typeFilter !== "all" || statusFilter !== "all"

  const typeCounts = React.useMemo(() => {
    const counts: Record<string, number> = {}
    for (const item of evidence) {
      counts[item.type] = (counts[item.type] ?? 0) + 1
    }
    return counts
  }, [evidence])

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-2">
        <h3 className="text-sm font-semibold text-foreground">
          Evidence
          <span className="ml-2 text-xs font-normal text-muted-foreground">
            {evidence.length} {evidence.length === 1 ? "item" : "items"}
          </span>
        </h3>
        {canAdd ? (
          <AddEvidenceDialog
            caseId={caseId}
            onCreated={onReload}
            onViewEvidence={onSelect}
          />
        ) : null}
      </div>

      {!caseOpen ? (
        <p className="text-xs text-muted-foreground">
          This case is closed; evidence cannot be added while it is closed.
        </p>
      ) : myRole !== "lead" && myRole !== "investigator" ? (
        <p className="text-xs text-muted-foreground">
          Only the case lead or an investigator can add evidence.
        </p>
      ) : null}

      <div className="flex flex-wrap items-center gap-2">
        <div className="relative min-w-0 flex-1">
          <Search
            aria-hidden
            className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground"
          />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={`Search evidence in case ${caseNumber}…`}
            aria-label="Search evidence"
            className="h-8 pl-8"
          />
        </div>

        <label className="sr-only" htmlFor="evidence-type-filter">
          Filter by type
        </label>
        <select
          id="evidence-type-filter"
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="h-8 rounded-md border border-input bg-background px-2 text-sm text-foreground shadow-sm outline-none transition-colors duration-150 ease-out-quick focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
        >
          <option value="all">All types</option>
          {EVIDENCE_TYPES.map((type) => (
            <option key={type} value={type}>
              {humanize(type)}
              {typeCounts[type] ? ` (${typeCounts[type]})` : ""}
            </option>
          ))}
        </select>

        <label className="sr-only" htmlFor="evidence-status-filter">
          Filter by status
        </label>
        <select
          id="evidence-status-filter"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="h-8 rounded-md border border-input bg-background px-2 text-sm text-foreground shadow-sm outline-none transition-colors duration-150 ease-out-quick focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
        >
          <option value="all">All statuses</option>
          {STATUS_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>

        {query || hasFilters ? (
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={() => {
              setQuery("")
              setTypeFilter("all")
              setStatusFilter("all")
            }}
          >
            <X aria-hidden className="size-3.5" />
            Clear
          </Button>
        ) : null}
      </div>

      {evidence.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-lg border border-border/80 bg-background px-6 py-12 text-center">
          <div className="flex size-9 items-center justify-center rounded-full border border-border/70 bg-muted/50 text-muted-foreground">
            <FileText className="size-4" aria-hidden />
          </div>
          <h4 className="mt-4 text-sm font-semibold text-foreground">
            No evidence yet
          </h4>
          <p className="mt-1 max-w-sm text-sm text-muted-foreground">
            This case has no evidence records. The case lead or an investigator
            can add the first item.
          </p>
        </div>
      ) : filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-lg border border-border/80 bg-background px-6 py-10 text-center">
          <Search className="size-4 text-muted-foreground" aria-hidden />
          <p className="mt-3 text-sm text-muted-foreground">
            No evidence matches the current search or filters.
          </p>
        </div>
      ) : (
        <div className="overflow-hidden rounded-lg border border-border/80 bg-background shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="border-b border-border/80 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                  <th scope="col" className="py-2 pl-4 pr-3 font-medium">
                    Evidence
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    Type
                  </th>
                  <th scope="col" className="hidden px-3 py-2 font-medium md:table-cell">
                    Status
                  </th>
                  <th scope="col" className="hidden px-3 py-2 font-medium lg:table-cell">
                    Integrity
                  </th>
                  <th scope="col" className="hidden px-3 py-2 font-medium lg:table-cell">
                    Added
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/70">
                {filtered.map((item) => (
                  <tr
                    key={item.id}
                    className="group cursor-pointer transition-colors duration-150 ease-out-quick hover:bg-muted/40 focus-within:bg-muted/40"
                  >
                    <td className="max-w-0 py-2.5 pl-4 pr-3">
                      <button
                        type="button"
                        onClick={() => onSelect(item.id)}
                        className="block w-full min-w-0 text-left focus:outline-none"
                      >
                        <span className="block truncate font-medium text-foreground">
                          {item.title}
                        </span>
                        <span className="block truncate font-mono text-xs text-muted-foreground">
                          {item.evidence_number}
                          {item.version_count > 0
                            ? ` · v${item.latest_version?.version ?? item.version_count}`
                            : ""}
                          {item.latest_version?.file_name
                            ? ` · ${item.latest_version.file_name}`
                            : ""}
                        </span>
                      </button>
                    </td>
                    <td className="whitespace-nowrap px-3 py-2.5 text-muted-foreground">
                      {humanize(item.type)}
                    </td>
                    <td className="hidden px-3 py-2.5 md:table-cell">
                      <EvidenceStatusBadge status={item.status} />
                    </td>
                    <td className="hidden px-3 py-2.5 lg:table-cell">
                      {item.latest_version ? (
                        <span className="whitespace-nowrap font-mono text-xs text-muted-foreground">
                          {shortHash(item.latest_version.sha256)}
                        </span>
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )}
                    </td>
                    <td className="hidden whitespace-nowrap px-3 py-2.5 text-right lg:table-cell">
                      <span className="font-mono text-xs text-muted-foreground">
                        {formatDate(item.created_at)}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {filtered.length > evidence.length ? (
            <div className="border-t border-border/70 px-4 py-2 text-xs text-muted-foreground">
              Showing {filtered.length} of {evidence.length} records.
            </div>
          ) : null}
        </div>
      )}

      <div
        className="sr-only"
        aria-live="polite"
      >
        {hasFilters
          ? `${filtered.length} evidence ${filtered.length === 1 ? "item" : "items"} match the current filters.`
          : ""}
      </div>
    </div>
  )
}