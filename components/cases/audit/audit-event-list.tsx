"use client"

import type { LucideIcon } from "lucide-react"
import {
  Anchor,
  Briefcase,
  FileStack,
  FileText,
  User,
} from "lucide-react"
import { formatDateTime } from "@/lib/format"
import type { AuditEventItem } from "@/lib/audit-serialization"

const ENTITY_ICONS: Record<string, LucideIcon> = {
  case: Briefcase,
  case_member: User,
  evidence: FileText,
  document_version: FileStack,
  blockchain_anchor: Anchor,
}

// Shared presentational list for both audit read endpoints. Every field is a
// display-safe AuditEventItem produced by lib/audit-serialization (the DB RPC
// is the authorization boundary; this component never sees raw audit_logs).
export function AuditEventList({
  events,
  emptyText,
}: {
  events: AuditEventItem[]
  emptyText: string
}) {
  if (events.length === 0) {
    return (
      <p className="rounded-lg border border-border/80 bg-background px-4 py-6 text-sm text-muted-foreground">
        {emptyText}
      </p>
    )
  }

  return (
    <ol className="divide-y divide-border/70 overflow-hidden rounded-lg border border-border/80 bg-background shadow-sm">
      {events.map((event) => (
        <AuditEventRow key={event.id} event={event} />
      ))}
    </ol>
  )
}

function AuditEventRow({ event }: { event: AuditEventItem }) {
  const Icon = ENTITY_ICONS[event.entity_type] ?? FileText

  return (
    <li className="flex gap-3 px-4 py-3">
      <div className="mt-0.5 flex size-7 shrink-0 items-center justify-center rounded-full border border-border/70 bg-muted/50 text-muted-foreground">
        <Icon className="size-3.5" aria-hidden />
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
          <span className="text-sm font-medium text-foreground">
            {event.action_label}
          </span>
          {event.entity_label ? (
            <span className="max-w-full truncate text-xs text-muted-foreground">
              {event.entity_type_label}: {event.entity_label}
            </span>
          ) : null}
        </div>

        {event.meta.length > 0 ? (
          <div className="mt-1.5 flex flex-wrap gap-1.5">
            {event.meta.map((item) => (
              <span
                key={item.key}
                className="inline-flex items-baseline gap-1 rounded border border-border/70 bg-muted/30 px-1.5 py-0.5 text-[11px] text-muted-foreground"
              >
                <span className="font-medium uppercase tracking-wide">
                  {item.label}
                </span>
                <span className="max-w-52 break-all font-mono">{item.value}</span>
              </span>
            ))}
          </div>
        ) : null}

        <p className="mt-1.5 flex flex-wrap items-center gap-x-2 text-xs text-muted-foreground">
          <span className="font-medium text-foreground">
            {event.actor_name ?? "System"}
          </span>
          <span aria-hidden>·</span>
          <time dateTime={event.created_at} className="font-mono">
            {formatDateTime(event.created_at)}
          </time>
        </p>
      </div>
    </li>
  )
}