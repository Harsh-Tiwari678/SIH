"use client"

import * as React from "react"
import Link from "next/link"
import { AlertTriangle, Building2 } from "lucide-react"
import { formatDate } from "@/lib/format"

export type OrganizationRecord = {
  id: string
  name: string
  slug: string
  created_at: string
}

type OrganizationsState =
  | { status: "loading" }
  | { status: "unauthorized" }
  | { status: "forbidden" }
  | { status: "error" }
  | { status: "empty" }
  | { status: "ready"; organizations: OrganizationRecord[] }

// ---------------------------------------------------------------------------
// Dense organization list. Each row links to the organization workspace and
// exposes name (primary anchor), slug (mono identifier), and creation date.
// Mirrors the cases list visual language: bordered container, mono slugs and
// timestamps, uppercase column headers, right-aligned date hidden on the
// smallest screens.
// ---------------------------------------------------------------------------
function OrganizationsTable({
  organizations,
}: {
  organizations: OrganizationRecord[]
}) {
  return (
    <table className="w-full border-collapse text-sm">
      <thead>
        <tr className="border-b border-border/80 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
          <th scope="col" className="py-2 pl-4 pr-3 font-medium">
            Organization
          </th>
          <th
            scope="col"
            className="hidden py-2 pl-3 pr-4 text-right font-medium sm:table-cell"
          >
            Created
          </th>
        </tr>
      </thead>
      <tbody className="divide-y divide-border/70">
        {organizations.map((org) => (
          <tr
            key={org.id}
            className="transition-colors duration-150 ease-out-quick hover:bg-muted/40"
          >
            <td className="max-w-0 py-2.5 pl-4 pr-3">
              <Link
                href={`/organizations/${org.id}`}
                className="font-medium text-foreground transition-colors duration-150 ease-out-quick hover:underline hover:underline-offset-4"
              >
                {org.name}
              </Link>
              <div className="truncate font-mono text-xs text-muted-foreground">
                {org.slug}
              </div>
            </td>
            <td className="hidden py-2.5 pl-3 pr-4 text-right align-top sm:table-cell">
              <span className="whitespace-nowrap font-mono text-xs text-muted-foreground">
                {formatDate(org.created_at)}
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
// session-expired / access-denied.
// ---------------------------------------------------------------------------
export function LoadingOrganizations({ rows = 4 }: { rows?: number }) {
  return (
    <div
      className="space-y-3"
      aria-busy="true"
      aria-label="Loading organizations"
    >
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
  icon: React.ReactNode
  title: string
  children: React.ReactNode
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

export function EmptyOrganizations() {
  return (
    <MessagePanel
      title="No organizations yet"
      icon={<Building2 aria-hidden className="size-4" />}
    >
      <p>
        You are not a member of any organizations yet. Organizations you join
        will appear here.
      </p>
    </MessagePanel>
  )
}

export function SessionExpiredOrganizations() {
  return (
    <MessagePanel
      title="Session expired"
      icon={<AlertTriangle aria-hidden className="size-4" />}
    >
      <p>Your session has expired. Sign in again to view your organizations.</p>
    </MessagePanel>
  )
}

export function AccessDeniedOrganizations() {
  return (
    <MessagePanel
      title="Access denied"
      icon={<AlertTriangle aria-hidden className="size-4" />}
    >
      <p>Your account does not have permission to view organizations.</p>
    </MessagePanel>
  )
}

export function CouldNotLoadOrganizations() {
  return (
    <MessagePanel
      title="Could not load organizations"
      icon={<AlertTriangle aria-hidden className="size-4" />}
    >
      <p>
        We could not load your organizations right now. Try refreshing the
        page.
      </p>
    </MessagePanel>
  )
}

// ---------------------------------------------------------------------------
// Page: fetches GET /api/organizations and renders the actual server response.
// RLS already limits the response to organizations the caller is a member of,
// so the client only renders what the API returns — authorization is never
// re-derived in the browser.
// ---------------------------------------------------------------------------
export function OrganizationsList() {
  const [state, setState] = React.useState<OrganizationsState>({
    status: "loading",
  })

  React.useEffect(() => {
    let cancelled = false

    async function load() {
      let res: Response
      try {
        res = await fetch("/api/organizations", { cache: "no-store" })
      } catch {
        if (!cancelled) setState({ status: "error" })
        return
      }
      if (cancelled) return

      if (res.status === 401) {
        setState({ status: "unauthorized" })
        return
      }
      if (res.status === 403) {
        setState({ status: "forbidden" })
        return
      }
      if (!res.ok) {
        setState({ status: "error" })
        return
      }

      const data = (await res.json().catch(() => ({}))) as {
        organizations?: OrganizationRecord[]
      }
      if (cancelled) return

      const organizations = Array.isArray(data.organizations)
        ? data.organizations
        : []
      setState(
        organizations.length === 0
          ? { status: "empty" }
          : { status: "ready", organizations },
      )
    }

    load()
    return () => {
      cancelled = true
    }
  }, [])

  const n = state.status === "ready" ? state.organizations.length : 0

  const subheading = React.useMemo(() => {
    if (state.status === "empty") {
      return "Organizations you join will appear here."
    }
    if (state.status === "ready") {
      return `${n} ${n === 1 ? "organization" : "organizations"} you can access.`
    }
    return "Organizations you are a member of."
  }, [state, n])

  return (
    <div className="space-y-6 sm:space-y-8">
      <header className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-foreground">
            Organizations
          </h1>
          <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
            {subheading}
          </p>
        </div>
      </header>

      <section aria-labelledby="organizations-list-heading">
        <h2 id="organizations-list-heading" className="sr-only">
          Organizations
        </h2>
        {renderContent()}
      </section>
    </div>
  )

  function renderContent() {
    switch (state.status) {
      case "loading":
        return <LoadingOrganizations />
      case "unauthorized":
        return <SessionExpiredOrganizations />
      case "forbidden":
        return <AccessDeniedOrganizations />
      case "error":
        return <CouldNotLoadOrganizations />
      case "empty":
        return <EmptyOrganizations />
      default: {
        return (
          <div className="overflow-hidden rounded-lg border border-border/80 bg-background shadow-sm">
            <div className="overflow-x-auto">
              <OrganizationsTable organizations={state.organizations} />
            </div>
            <p className="border-t border-border/80 px-4 py-2 text-xs text-muted-foreground">
              {n} {n === 1 ? "organization" : "organizations"}
            </p>
          </div>
        )
      }
    }
  }
}