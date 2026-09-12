"use client"

import * as React from "react"
import { Check, ChevronDown, Loader2 } from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogClose,
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
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { cn } from "@/lib/utils"
import type { CaseDetail } from "@/components/cases/case-detail"

// The server-side transition matrix (update_case) is the source of truth:
//   draft    -> active
//   active   -> draft | closed
//   closed   -> active | archived     (reopen / archive)
//   archived -> closed                (restore; NOT active)
// The menu mirrors exactly those transitions; any other move is rejected by the
// server, so the UI never offers one.
const TRANSITIONS: Record<
  string,
  Array<{
    target: string
    label: string
    confirm?: "close" | "reopen" | "archive" | "restore"
  }>
> = {
  draft: [{ target: "active", label: "Active" }],
  active: [
    { target: "draft", label: "Draft" },
    { target: "closed", label: "Closed", confirm: "close" },
  ],
  closed: [
    { target: "active", label: "Active", confirm: "reopen" },
    { target: "archived", label: "Archived", confirm: "archive" },
  ],
  archived: [{ target: "closed", label: "Closed", confirm: "restore" }],
}

const STATUS_DOTS: Record<string, string> = {
  draft: "bg-muted-foreground/70",
  active: "bg-success",
  closed: "bg-muted-foreground/70",
  archived: "bg-muted-foreground/40",
}

const CONFIRM_COPY: Record<
  string,
  { title: string; body: string; action: string }
> = {
  close: {
    title: "Close this case?",
    body: "Closing a case marks it as no longer open. Members and evidence can no longer be added, and evidence, custody and anchoring actions are disabled until the case is reopened. The closed status is recorded in the audit trail.",
    action: "Close case",
  },
  reopen: {
    title: "Reopen this case?",
    body: "Reopening returns the case to active. Members and evidence can be added again and evidence actions are re-enabled. The previous close remains in the audit trail.",
    action: "Reopen case",
  },
  archive: {
    title: "Archive this case?",
    body: "Archiving moves the case out of the active workflow. The case is never deleted — its records, evidence and audit trail remain intact and readable.",
    action: "Archive case",
  },
  restore: {
    title: "Restore this case?",
    body: "Restoring returns an archived case to closed status. It stays closed until a lead reopens it. The case is never deleted and its records remain intact and readable.",
    action: "Restore to closed",
  },
}

export function CaseStatusMenu({
  caseDetail,
  onSaved,
}: {
  caseDetail: CaseDetail
  onSaved: () => void
}) {
  const [pending, setPending] = React.useState(false)
  const [confirmTarget, setConfirmTarget] = React.useState<
    "close" | "reopen" | "archive" | "restore" | null
  >(null)
  const [formError, setFormError] = React.useState<string | null>(null)

  const transitions = TRANSITIONS[caseDetail.status] ?? []

  async function applyStatus(value: string) {
    if (value === caseDetail.status || pending) return
    setPending(true)
    setFormError(null)
    try {
      const res = await fetch(`/api/cases/${caseDetail.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: value }),
      })
      if (!res.ok) {
        const data = (await res.json().catch(() => ({}))) as {
          error?: string
        }
        setFormError(labelStatusError(data.error ?? ""))
        return
      }
      setConfirmTarget(null)
      onSaved()
    } catch {
      setFormError("Could not change status. Try again.")
    } finally {
      setPending(false)
    }
  }

  function handleSelect(transition: (typeof transitions)[number]) {
    if (transition.target === caseDetail.status) return
    if (transition.confirm) {
      setConfirmTarget(transition.confirm)
      return
    }
    applyStatus(transition.target)
  }

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline" disabled={pending}>
            {pending ? (
              <Loader2 className="size-4 animate-spin" aria-hidden />
            ) : null}
            Change status
            <ChevronDown aria-hidden className="size-4" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuLabel>Move case to</DropdownMenuLabel>
          {transitions.map((transition) => {
            const active = transition.target === caseDetail.status
            return (
              <DropdownMenuItem
                key={transition.target}
                disabled={active}
                onSelect={() => handleSelect(transition)}
              >
                <span
                  aria-hidden
                  className={cn(
                    "size-1.5 rounded-full",
                    STATUS_DOTS[transition.target] ?? "bg-muted-foreground/70",
                  )}
                />
                {transition.label}
                {active ? (
                  <Check aria-hidden className="ml-auto size-4" />
                ) : null}
              </DropdownMenuItem>
            )
          })}
        </DropdownMenuContent>
      </DropdownMenu>

      <ConfirmStatusDialog
        caseNumber={caseDetail.case_number}
        target={confirmTarget}
        pending={pending}
        formError={formError}
        onCancel={() => setConfirmTarget(null)}
        onConfirm={() => {
          const transition = transitions.find((t) => t.confirm === confirmTarget)
          if (transition) applyStatus(transition.target)
        }}
      />

      {formError && !confirmTarget ? (
        <p role="alert" className="mt-2 text-sm text-danger">
          {formError}
        </p>
      ) : null}
    </>
  )
}

function ConfirmStatusDialog({
  caseNumber,
  target,
  pending,
  formError,
  onCancel,
  onConfirm,
}: {
  caseNumber: string
  target: "close" | "reopen" | "archive" | "restore" | null
  pending: boolean
  formError: string | null
  onCancel: () => void
  onConfirm: () => void
}) {
  const copy = target ? CONFIRM_COPY[target] : null
  return (
    <Dialog
      open={target !== null}
      onOpenChange={(open) => {
        if (!open) onCancel()
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{copy?.title}</DialogTitle>
          <DialogDescription>
            <span className="font-mono">{caseNumber}</span> — {copy?.body}
          </DialogDescription>
        </DialogHeader>
        {formError ? (
          <p role="alert" className="text-sm text-danger">
            {formError}
          </p>
        ) : null}
        <DialogFooter>
          <DialogClose asChild>
            <Button type="button" variant="ghost" disabled={pending}>
              Cancel
            </Button>
          </DialogClose>
          <Button
            type="button"
            variant="destructive"
            disabled={pending}
            onClick={onConfirm}
          >
            {pending ? (
              <Loader2 className="size-4 animate-spin" aria-hidden />
            ) : null}
            {copy?.action}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function labelStatusError(message: string): string {
  if (message.includes("Unauthorized")) {
    return "Your session has expired. Sign in again."
  }
  if (message.includes("Only the case lead")) {
    return "Only the case lead can change the status."
  }
  if (message.includes("status transition")) {
    return "That change is not allowed in the case's current status."
  }
  if (message.includes("status")) {
    return "That status is not allowed."
  }
  return "Could not change status. Try again."
}