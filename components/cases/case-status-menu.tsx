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

const STATUS_OPTIONS = [
  { value: "draft", label: "Draft", dot: "bg-muted-foreground/70" },
  { value: "active", label: "Active", dot: "bg-success" },
  { value: "closed", label: "Closed", dot: "bg-muted-foreground/70" },
  { value: "archived", label: "Archived", dot: "bg-muted-foreground/40" },
] as const

const CONFIRM_COPY: Record<string, { title: string; body: string }> = {
  closed: {
    title: "Close this case?",
    body: "Closing a case marks it as no longer open. Members and evidence can no longer be added, and the closed status is recorded in the audit trail.",
  },
  archived: {
    title: "Archive this case?",
    body: "Archiving moves the case out of the active workflow. The case is never deleted — its records and audit trail remain intact and readable.",
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
    "closed" | "archived" | null
  >(null)
  const [formError, setFormError] = React.useState<string | null>(null)

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

  function handleSelect(value: string) {
    if (value === caseDetail.status) return
    if (value === "closed" || value === "archived") {
      setConfirmTarget(value)
      return
    }
    applyStatus(value)
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
          {STATUS_OPTIONS.map((option) => {
            const active = option.value === caseDetail.status
            return (
              <DropdownMenuItem
                key={option.value}
                disabled={active}
                onSelect={() => handleSelect(option.value)}
              >
                <span
                  aria-hidden
                  className={cn("size-1.5 rounded-full", option.dot)}
                />
                {option.label}
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
        onConfirm={() => confirmTarget && applyStatus(confirmTarget)}
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
  target: "closed" | "archived" | null
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
            {target === "closed" ? "Close case" : "Archive case"}
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
  if (message.includes("status")) {
    return "That status is not allowed."
  }
  return "Could not change status. Try again."
}