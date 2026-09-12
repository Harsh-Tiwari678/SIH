"use client"

import * as React from "react"
import { Check, History, UserPlus, Users } from "lucide-react"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"
import { formatDate } from "@/lib/format"
import { AuditEventList } from "@/components/cases/audit/audit-event-list"
import type { AuditEventItem } from "@/lib/audit-serialization"
import type { OrgMember } from "@/lib/organization-api/org-types"
import { ORG_ROLE_LABELS } from "@/lib/organization-api/organization-member-client"
import { AddMemberDialog } from "./add-member-dialog"
import { MemberActionsMenu, ChangeRoleDialog, RemoveMemberDialog } from "./member-actions"

type TabId = "members" | "audit"

const TABS: { id: TabId; label: string }[] = [
  { id: "members", label: "Members" },
  { id: "audit", label: "Audit" },
]

function isTabId(value: string | undefined): value is TabId {
  return value === "members" || value === "audit"
}

function WorkspaceMessage({
  icon: Icon,
  title,
  message,
}: {
  icon: React.ComponentType<{ className?: string }>
  title: string
  message: string
}) {
  return (
    <div className="flex flex-col items-start justify-center rounded-lg border border-border/80 bg-background px-6 py-10 text-left">
      <div className="flex size-9 items-center justify-center rounded-full border border-border/70 bg-muted/50 text-muted-foreground">
        <Icon aria-hidden className="size-4" />
      </div>
      <h3 className="mt-4 text-sm font-semibold text-foreground">{title}</h3>
      <p className="mt-1 max-w-md text-sm text-muted-foreground">{message}</p>
    </div>
  )
}

function OrgRoleBadge({ role }: { role: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2 py-0.5 text-xs",
        role === "admin"
          ? "border-amber-500/40 bg-amber-500/10 text-amber-700"
          : role === "investigator"
            ? "border-sky-500/40 bg-sky-500/10 text-sky-700"
            : "border-border/70 text-muted-foreground",
      )}
    >
      <span
        aria-hidden
        className={cn(
          "size-1.5 rounded-full",
          role === "admin"
            ? "bg-amber-500"
            : role === "investigator"
              ? "bg-sky-500"
              : "bg-muted-foreground/60",
        )}
      />
      {role === "admin" || role === "investigator" || role === "member"
        ? ORG_ROLE_LABELS[role]
        : role}
    </span>
  )
}

function MembersPanel({ orgId }: { orgId: string }) {
  const [state, setState] = React.useState<
    | { status: "loading" }
    | { status: "unauthorized" }
    | { status: "forbidden" }
    | { status: "not_found" }
    | { status: "error" }
    | { status: "ready"; members: OrgMember[] }
  >({ status: "loading" })

  const [statusMessage, setStatusMessage] = React.useState<string | null>(null)
  const [addOpen, setAddOpen] = React.useState(false)
  const [roleTarget, setRoleTarget] = React.useState<OrgMember | null>(null)
  const [removeTarget, setRemoveTarget] = React.useState<OrgMember | null>(null)
  const [reloadToken, setReloadToken] = React.useState(0)

  function refresh() {
    setReloadToken((t) => t + 1)
  }

  function openAdd() {
    setStatusMessage(null)
    setRoleTarget(null)
    setRemoveTarget(null)
    setAddOpen(true)
  }

  React.useEffect(() => {
    let canceled = false

    async function load() {
      let res: Response
      try {
        res = await fetch(`/api/organizations/${orgId}/members`, {
          cache: "no-store",
        })
      } catch {
        if (!canceled) setState({ status: "error" })
        return
      }
      if (canceled) return

      if (res.status === 401) {
        setState({ status: "unauthorized" })
        return
      }
      if (res.status === 403) {
        setState({ status: "forbidden" })
        return
      }
      if (res.status === 404) {
        setState({ status: "not_found" })
        return
      }
      if (!res.ok) {
        setState({ status: "error" })
        return
      }

      const data = (await res.json().catch(() => ({}))) as {
        members?: OrgMember[]
      }
      if (canceled) return
      if (!Array.isArray(data.members)) {
        setState({ status: "error" })
        return
      }
      setState({ status: "ready", members: data.members })
    }

    load()
    return () => {
      canceled = true
    }
  }, [orgId, reloadToken])

  if (state.status === "loading") {
    return (
      <div className="flex flex-col items-center justify-center rounded-lg border border-border/80 bg-background px-6 py-12 text-center">
        <div className="size-6 animate-pulse rounded-full border border-border/70 bg-muted/50" />
        <p className="mt-3 text-sm text-muted-foreground">
          Loading member roster…
        </p>
      </div>
    )
  }

  if (state.status === "unauthorized") {
    return (
      <WorkspaceMessage
        icon={Users}
        title="Authentication required"
        message="You must be signed in to view this organization's members. Sign in and try again."
      />
    )
  }

  if (state.status === "forbidden") {
    return (
      <WorkspaceMessage
        icon={Users}
        title="Access denied"
        message="Your account does not have permission to view this organization's members."
      />
    )
  }

  if (state.status === "not_found") {
    return (
      <WorkspaceMessage
        icon={Users}
        title="Organization not found"
        message="This organization does not exist, or you are not a member of it."
      />
    )
  }

  if (state.status === "error") {
    return (
      <WorkspaceMessage
        icon={Users}
        title="Failed to load members"
        message="The member roster could not be loaded. This could be a temporary problem — try again in a moment."
      />
    )
  }

  if (state.members.length === 0) {
    return (
      <>
        <div className="rounded-lg border border-border/80 bg-background px-6 py-10 text-left">
          <div className="flex size-9 items-center justify-center rounded-full border border-border/70 bg-muted/50 text-muted-foreground">
            <Users aria-hidden className="size-4" />
          </div>
          <h3 className="mt-4 text-sm font-semibold text-foreground">
            No members yet
          </h3>
          <p className="mt-1 max-w-md text-sm text-muted-foreground">
            This organization has no members yet. Add the first member to get
            started.
          </p>
          <Button
            variant="outline"
            size="sm"
            className="mt-4"
            onClick={openAdd}
          >
            <UserPlus aria-hidden className="size-4" />
            Add member
          </Button>
        </div>
        <AddMemberDialog
          orgId={orgId}
          open={addOpen}
          onOpenChange={setAddOpen}
          onMemberAdded={() => {
            setStatusMessage("Member added successfully.")
            refresh()
          }}
        />
        <ChangeRoleDialog
          key={roleTarget ? roleTarget.profile_id : "none"}
          orgId={orgId}
          member={roleTarget}
          open={!!roleTarget}
          onClose={() => setRoleTarget(null)}
          onChanged={(msg) => {
            setStatusMessage(msg)
            refresh()
          }}
        />
        <RemoveMemberDialog
          key={removeTarget ? removeTarget.profile_id : "none"}
          orgId={orgId}
          member={removeTarget}
          open={!!removeTarget}
          onClose={() => setRemoveTarget(null)}
          onChanged={(msg) => {
            setStatusMessage(msg)
            refresh()
          }}
        />
      </>
    )
  }

  return (
    <>
      <div className="flex items-center justify-between gap-4">
        <div className="min-w-0 flex-1">
          {statusMessage ? (
            <p
              role="status"
              className="flex items-center gap-1.5 text-sm text-muted-foreground"
            >
              <Check aria-hidden className="size-4 shrink-0 text-primary" />
              {statusMessage}
            </p>
          ) : null}
        </div>
        <Button
          variant="outline"
          size="sm"
          className="shrink-0"
          onClick={openAdd}
        >
          <UserPlus aria-hidden className="size-4" />
          Add member
        </Button>
      </div>

      <div className="overflow-hidden rounded-lg border border-border/80 bg-background shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-border/80 text-left text-xs font-medium uppercase tracking-wider text-muted-foreground">
                <th scope="col" className="py-2 pl-4 pr-3 font-medium">
                  Member
                </th>
                <th scope="col" className="px-3 py-2 font-medium">
                  Badge
                </th>
                <th scope="col" className="px-3 py-2 font-medium">
                  Role
                </th>
                <th
                  scope="col"
                  className="hidden px-3 py-2 font-medium md:table-cell"
                >
                  Added by
                </th>
                <th
                  scope="col"
                  className="hidden px-3 py-2 text-right font-medium lg:table-cell"
                >
                  Added
                </th>
                <th scope="col" className="w-10 px-2 py-2 text-right font-medium">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/70">
              {state.members.map((member) => (
                <tr
                  key={member.profile_id}
                  className="transition-colors duration-150 ease-out-quick hover:bg-muted/40"
                >
                  <td className="max-w-0 py-2.5 pl-4 pr-3">
                    <span className="block truncate font-medium text-foreground">
                      {member.full_name || "—"}
                    </span>
                    <span className="block truncate font-mono text-xs text-muted-foreground">
                      {member.profile_id}
                    </span>
                  </td>
                  <td className="whitespace-nowrap px-3 py-2.5">
                    <span className="font-mono text-xs text-muted-foreground">
                      {member.badge_number || "—"}
                    </span>
                  </td>
                  <td className="whitespace-nowrap px-3 py-2.5">
                    <OrgRoleBadge role={member.role_in_org} />
                  </td>
                  <td className="hidden whitespace-nowrap px-3 py-2.5 text-muted-foreground md:table-cell">
                    {member.added_by_name || "—"}
                  </td>
                  <td className="hidden whitespace-nowrap px-3 py-2.5 text-right lg:table-cell">
                    <span className="font-mono text-xs text-muted-foreground">
                      {formatDate(member.added_at)}
                    </span>
                  </td>
                  <td className="whitespace-nowrap px-2 py-1.5 text-right">
                    <MemberActionsMenu
                      member={member}
                      onEditRole={() => {
                        setStatusMessage(null)
                        setAddOpen(false)
                        setRemoveTarget(null)
                        setRoleTarget(member)
                      }}
                      onRemove={() => {
                        setStatusMessage(null)
                        setAddOpen(false)
                        setRoleTarget(null)
                        setRemoveTarget(member)
                      }}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <AddMemberDialog
        orgId={orgId}
        open={addOpen}
        onOpenChange={setAddOpen}
        onMemberAdded={() => {
          setStatusMessage("Member added successfully.")
          refresh()
        }}
      />
      <ChangeRoleDialog
        orgId={orgId}
        member={roleTarget}
        open={!!roleTarget}
        onClose={() => setRoleTarget(null)}
        onChanged={(msg) => {
          setStatusMessage(msg)
          refresh()
        }}
      />
      <RemoveMemberDialog
        orgId={orgId}
        member={removeTarget}
        open={!!removeTarget}
        onClose={() => setRemoveTarget(null)}
        onChanged={(msg) => {
          setStatusMessage(msg)
          refresh()
        }}
      />
    </>
  )
}

function AuditPanel({ orgId }: { orgId: string }) {
  const [state, setState] = React.useState<
    | { status: "loading" }
    | { status: "unauthorized" }
    | { status: "forbidden" }
    | { status: "not_found" }
    | { status: "error" }
    | { status: "ready"; events: AuditEventItem[] }
  >({ status: "loading" })

  React.useEffect(() => {
    let canceled = false

    async function load() {
      let res: Response
      try {
        res = await fetch(`/api/organizations/${orgId}/audit`, {
          cache: "no-store",
        })
      } catch {
        if (!canceled) setState({ status: "error" })
        return
      }
      if (canceled) return

      if (res.status === 401) {
        setState({ status: "unauthorized" })
        return
      }
      if (res.status === 403) {
        setState({ status: "forbidden" })
        return
      }
      if (res.status === 404) {
        setState({ status: "not_found" })
        return
      }
      if (!res.ok) {
        setState({ status: "error" })
        return
      }

      const data = (await res.json().catch(() => ({}))) as {
        events?: AuditEventItem[]
      }
      if (canceled) return
      if (!Array.isArray(data.events)) {
        setState({ status: "error" })
        return
      }
      setState({ status: "ready", events: data.events })
    }

    load()
    return () => {
      canceled = true
    }
  }, [orgId])

  if (state.status === "loading") {
    return (
      <div className="flex flex-col items-center justify-center rounded-lg border border-border/80 bg-background px-6 py-12 text-center">
        <div className="size-6 animate-pulse rounded-full border border-border/70 bg-muted/50" />
        <p className="mt-3 text-sm text-muted-foreground">
          Loading audit trail…
        </p>
      </div>
    )
  }

  if (state.status === "unauthorized") {
    return (
      <WorkspaceMessage
        icon={History}
        title="Authentication required"
        message="You must be signed in to view this organization's audit history. Sign in and try again."
      />
    )
  }

  if (state.status === "forbidden") {
    return (
      <WorkspaceMessage
        icon={History}
        title="Access denied"
        message="Your account does not have permission to view this organization's audit history."
      />
    )
  }

  if (state.status === "not_found") {
    return (
      <WorkspaceMessage
        icon={History}
        title="Organization not found"
        message="This organization does not exist, or you are not a member of it."
      />
    )
  }

  if (state.status === "error") {
    return (
      <WorkspaceMessage
        icon={History}
        title="Failed to load the audit trail"
        message="The audit history could not be loaded. This could be a temporary problem — try again in a moment."
      />
    )
  }

  return (
    <AuditEventList
      events={state.events}
      emptyText="No audit events have been recorded for this organization yet."
    />
  )
}

export function OrganizationWorkspace({
  orgId,
  initialTab,
}: {
  orgId: string
  initialTab?: string
}) {
  const [tab, setTab] = React.useState<TabId>(() =>
    isTabId(initialTab) ? initialTab : "members",
  )

  return (
    <div className="space-y-6 sm:space-y-8">
      <div>
        <p className="font-mono text-[13px] text-muted-foreground">{orgId}</p>
        <h1 className="mt-1 text-2xl font-semibold tracking-tight text-foreground">
          Organization
        </h1>
        <p className="mt-2 max-w-3xl text-sm text-muted-foreground">
          Manage the members and audit history for this organization.
        </p>
      </div>

      <div
        role="tablist"
        aria-label="Organization sections"
        className="flex gap-6 overflow-x-auto border-b border-border/70"
      >
        {TABS.map((t) => (
          <button
            key={t.id}
            role="tab"
            id={`tab-${t.id}`}
            aria-selected={tab === t.id}
            aria-controls={`panel-${t.id}`}
            onClick={() => setTab(t.id)}
            className={cn(
              "-mb-px border-b-2 px-1 pb-2 text-sm transition-colors duration-150 ease-out-quick",
              tab === t.id
                ? "border-primary font-medium text-foreground"
                : "border-transparent text-muted-foreground hover:text-foreground",
            )}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div className="min-w-0">
        {tab === "members" ? <MembersPanel orgId={orgId} /> : null}
        {tab === "audit" ? <AuditPanel orgId={orgId} /> : null}
      </div>
    </div>
  )
}
