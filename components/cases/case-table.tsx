"use client"

import type { ReactNode } from "react"
import Link from "next/link"
import { AlertTriangle, FolderOpen } from "lucide-react"
import { CaseStatusBadge } from "@/components/cases/status-badge"
import { formatDate } from "@/lib/format"

export type CaseRecord = {
  id: string
  case_number: string
  title: string
  description: string | null
  status: string
  created_at: string
  updated_at: string
}

// ---------------------------------------------------------------------------
// Dense case table shared by the Dashboard overview and the All Cases page.
// Rows link to /cases/[caseId]. Case numbers and timestamps use mono type.
// ---------------------------------------------------------------------------
export function CaseTable({ cases }: { cases: CaseRecord[] }) {
  return (
    <table className="w-full border-collapse text-sm">
      <thead>
        <tr className="border-b border-border/80 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
          <th scope="col" className="py-2 pl-4 pr-3 font-medium">
            Case
          </th>
          <th scope="col" className="px-3 py-2 font-medium">
            Title
          </th>
          <th scope="col" className="px-3 py-2 font-medium">
            Status
          </th>
          <th scope="col" className="hidden py-2 pl-3 pr-4 text-right font-medium sm:table-cell">
            Created
          </th>
        </tr>
      </thead>
      <tbody className="divide-y divide-border/70">
        {cases.map((c) => (
          <tr
            key={c.id}
            className="transition-colors duration-150 ease-out-quick hover:bg-muted/40"
          >
            <td className="py-2.5 pl-4 pr-3 align-top">
              <Link
                href={`/cases/${c.id}`}
                className="font-mono text-[13px] font-medium text-primary transition-colors duration-150 ease-out-quick hover:underline hover:underline-offset-4"
              >
                {c.case_number}
              </Link>
            </td>
            <td className="px-3 py-2.5 align-top">
              <Link
                href={`/cases/${c.id}`}
                className="font-medium text-foreground transition-colors duration-150 ease-out-quick hover:underline hover:underline-offset-4"
              >
                {c.title}
              </Link>
              {c.description ? (
                <div className="truncate text-xs text-muted-foreground">
                  {c.description}
                </div>
              ) : null}
            </td>
            <td className="px-3 py-2.5 align-top">
              <CaseStatusBadge status={c.status} />
            </td>
            <td className="hidden py-2.5 pl-3 pr-4 text-right align-top sm:table-cell">
              <span className="whitespace-nowrap font-mono text-xs text-muted-foreground">
                {formatDate(c.created_at)}
              </span>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

// ---------------------------------------------------------------------------
// Shared list states: skeleton rows plus message panels for empty / error /
// session-expired.
// ---------------------------------------------------------------------------
export function LoadingCases({ rows = 4 }: { rows?: number }) {
  return (
    <div className="space-y-3" aria-busy="true" aria-label="Loading cases">
      {Array.from({ length: rows }).map((_, i) => (
        <div
          key={i}
          className="h-14 animate-pulse rounded-lg border border-border/60 bg-muted/40"
        />
      ))}
    </div>
  )
}

function MessagePanel({
  icon,
  title,
  children,
}: {
  icon: ReactNode
  title: string
  children: ReactNode
}) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-border/80 bg-background px-6 py-12 text-center">
      <div className="flex size-9 items-center justify-center rounded-full border border-border/70 bg-muted/50 text-muted-foreground">
        {icon}
      </div>
      <h3 className="mt-4 text-sm font-semibold text-foreground">{title}</h3>
      <div className="mt-1 max-w-sm text-sm text-muted-foreground">
        {children}
      </div>
    </div>
  )
}

export function EmptyCases() {
  return (
    <MessagePanel
      title="No cases yet"
      icon={<FolderOpen className="size-4" aria-hidden />}
    >
      <p>
        Cases group the members and evidence of an investigation. Use the New
        case button to start one.
      </p>
    </MessagePanel>
  )
}

export function SessionExpiredCases() {
  return (
    <MessagePanel
      title="Session expired"
      icon={<AlertTriangle className="size-4" aria-hidden />}
    >
      <p>
        Your session has expired. Sign in again to view your cases.
      </p>
    </MessagePanel>
  )
}

export function CouldNotLoadCases() {
  return (
    <MessagePanel
      title="Could not load cases"
      icon={<AlertTriangle className="size-4" aria-hidden />}
    >
      <p>
        We could not load your cases right now. Try refreshing the page.
      </p>
    </MessagePanel>
  )
}