"use client"

import * as React from "react"
import { AlertCircle, Ellipsis, Loader2, Trash2, UserCog } from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { OrgRolePicker } from "./org-role-picker"
import type { OrgMember } from "@/lib/organization-api/org-types"
import {
  type OrgMemberRole,
  ORG_ROLE_LABELS,
  changeMemberRole,
  removeOrganizationMember,
} from "@/lib/organization-api/organization-member-client"

// Per-row action menu for the member roster. Management controls are shown to
// every member who can read the roster; the SECURITY DEFINER RPCs behind the
// API are the authorization boundary and reject non-admins with a 403. The
// menu never performs a mutation itself — it opens the role or removal
// dialogue, which owns the request and its error state.
export function MemberActionsMenu({
  member,
  onEditRole,
  onRemove,
}: {
  member: OrgMember
  onEditRole: () => void
  onRemove: () => void
}) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="icon-sm"
          aria-label={`Actions for ${member.full_name || "member"}`}
        >
          <Ellipsis aria-hidden className="size-4" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuLabel className="max-w-56 truncate font-mono text-xs text-muted-foreground">
          {member.full_name || member.profile_id}
        </DropdownMenuLabel>
        <DropdownMenuItem onSelect={() => onEditRole()}>
          <UserCog aria-hidden className="size-4" />
          Change role
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem variant="destructive" onSelect={() => onRemove()}>
          <Trash2 aria-hidden className="size-4" />
          Remove member
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

// Deliberate role-selection dialogue. Only the three valid organization roles
// can be picked (the radio group cannot produce an invalid value), and the
// Save button is disabled until a different role is chosen. The PATCH body is
// exactly { role_in_org } — the actor is derived server-side from the session.
export function ChangeRoleDialog({
  orgId,
  member,
  open,
  onClose,
  onChanged,
}: {
  orgId: string
  member: OrgMember | null
  open: boolean
  onClose: () => void
  onChanged: (message: string) => void
}) {
  // Remount per member (parent keys the dialog by member id), so state is
  // initialized fresh from the target member on every open.
  const [role, setRole] = React.useState<OrgMemberRole>(
    (member?.role_in_org as OrgMemberRole) ?? "member",
  )
  const [pending, setPending] = React.useState(false)
  const [formError, setFormError] = React.useState<string | null>(null)

  if (!member) return null

  const target = member
  const unchanged = target.role_in_org === role

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (pending || unchanged) return

    setPending(true)
    setFormError(null)
    const result = await changeMemberRole(orgId, target.profile_id, role)
    setPending(false)
    if (!result.ok) {
      setFormError(result.message)
      return
    }
    onClose()
    onChanged(
      `${target.full_name || "Member"}'s role changed to ${ORG_ROLE_LABELS[role]}.`,
    )
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) onClose()
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Change role</DialogTitle>
          <DialogDescription>
            {member.full_name || "Member"}
            {member.badge_number ? ` · ${member.badge_number}` : ""}
          </DialogDescription>
        </DialogHeader>

        <form className="mt-4 space-y-4" onSubmit={handleSubmit}>
          <OrgRolePicker value={role} onChange={setRole} disabled={pending} />

          {formError ? (
            <p
              role="alert"
              className="flex items-center gap-1.5 text-sm text-danger"
            >
              <AlertCircle className="size-4 shrink-0" aria-hidden />
              {formError}
            </p>
          ) : null}

          <DialogFooter>
            <Button
              type="button"
              variant="ghost"
              disabled={pending}
              onClick={onClose}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={pending || unchanged}>
              {pending ? (
                <Loader2 className="size-4 animate-spin" aria-hidden />
              ) : null}
              {pending ? "Saving" : "Save role"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

// Confirmation dialogue for removal. The member being removed and the
// consequence — organization access is revoked — are stated in plain text, so
// the destructive intent is clear without relying on color. The DELETE
// request carries no body and no actor identity.
export function RemoveMemberDialog({
  orgId,
  member,
  open,
  onClose,
  onChanged,
}: {
  orgId: string
  member: OrgMember | null
  open: boolean
  onClose: () => void
  onChanged: (message: string) => void
}) {
  const [pending, setPending] = React.useState(false)
  const [formError, setFormError] = React.useState<string | null>(null)

  if (!member) return null

  const target = member

  async function handleConfirm() {
    if (pending) return

    setPending(true)
    setFormError(null)
    const result = await removeOrganizationMember(orgId, target.profile_id)
    setPending(false)
    if (!result.ok) {
      setFormError(result.message)
      return
    }
    onClose()
    onChanged(`${target.full_name || "Member"} removed from the organization.`)
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (!next) onClose()
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Remove {member.full_name || "member"}?</DialogTitle>
          <DialogDescription>
            {member.full_name || "This member"}
            {member.badge_number ? ` (${member.badge_number})` : ""} will
            immediately lose access to this organization and all of its cases
            and evidence. This action is recorded in the audit trail.
          </DialogDescription>
        </DialogHeader>

        {formError ? (
          <p
            role="alert"
            className="mt-2 flex items-center gap-1.5 text-sm text-danger"
          >
            <AlertCircle className="size-4 shrink-0" aria-hidden />
            {formError}
          </p>
        ) : null}

        <DialogFooter>
          <Button type="button" variant="ghost" disabled={pending} onClick={onClose}>
            Cancel
          </Button>
          <Button
            type="button"
            variant="destructive"
            disabled={pending}
            onClick={handleConfirm}
          >
            {pending ? (
              <Loader2 className="size-4 animate-spin" aria-hidden />
            ) : (
              <Trash2 aria-hidden className="size-4" />
            )}
            {pending ? "Removing" : "Remove member"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}