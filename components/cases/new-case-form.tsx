"use client"

import * as React from "react"
import { AlertCircle, Loader2, Plus } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { cn } from "@/lib/utils"

function FieldLabel({
  htmlFor,
  children,
}: {
  htmlFor: string
  children: React.ReactNode
}) {
  return (
    <label
      htmlFor={htmlFor}
      className="block text-sm font-medium text-foreground"
    >
      {children}
    </label>
  )
}

function FieldError({ children }: { children: React.ReactNode }) {
  return (
    <p className="flex items-center gap-1.5 text-xs text-danger">
      <AlertCircle className="size-3.5 shrink-0" aria-hidden />
      <span>{children}</span>
    </p>
  )
}

function GenericError({ message }: { message: string }) {
  return (
    <p
      role="alert"
      className="flex items-center gap-1.5 text-sm text-danger"
    >
      <AlertCircle className="size-4 shrink-0" aria-hidden />
      <span>{message}</span>
    </p>
  )
}

type FieldErrors = {
  case_number?: string
  title?: string
}

function ServerErrorLabel(message: string): string {
  if (message.includes("Unauthorized")) {
    return "Your session has expired. Sign in again."
  }
  if (message.includes("Forbidden")) {
    return "Your account is not allowed to create cases."
  }
  if (
    message.includes("duplicate key") ||
    message.toLowerCase().includes("unique")
  ) {
    return "That case number is already in use."
  }
  if (
    message.includes("case_number") ||
    message.includes("title")
  ) {
    return "Please fill in the required fields."
  }
  return "Could not create the case. Try again."
}

export function NewCaseForm({
  onCreated,
}: {
  onCreated: () => void
}) {
  const [open, setOpen] = React.useState(false)
  const [pending, setPending] = React.useState(false)
  const [fieldErrors, setFieldErrors] = React.useState<FieldErrors>({})
  const [formError, setFormError] = React.useState<string | null>(null)

  function handleOpenChange(nextOpen: boolean) {
    setOpen(nextOpen)
    if (nextOpen) {
      setPending(false)
      setFieldErrors({})
      setFormError(null)
    }
  }

  function runAction(formData: FormData) {
    const caseNumber = (formData.get("case_number") as string | null)?.trim() ?? ""
    const title = (formData.get("title") as string | null)?.trim() ?? ""

    const next: FieldErrors = {}
    if (!caseNumber) next.case_number = "Case number is required."
    if (!title) next.title = "Title is required."
    setFieldErrors(next)
    setFormError(null)
    if (next.case_number || next.title) {
      return
    }

    const description = (formData.get("description") as string | null)?.trim() || null

    setPending(true)
    fetch("/api/cases", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ case_number: caseNumber, title, description }),
    })
      .then(async (res) => {
        const data = (await res.json().catch(() => ({}))) as {
          error?: string
        }
        if (!res.ok) {
          setFormError(ServerErrorLabel(data.error ?? ""))
          return
        }
        setOpen(false)
        onCreated()
      })
      .catch(() => {
        setFormError(ServerErrorLabel(""))
      })
      .finally(() => setPending(false))
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogTrigger asChild>
        <Button>
          <Plus aria-hidden className="size-4" />
          New case
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>New case</DialogTitle>
          <DialogDescription>
            Create a case to begin recording evidence and members.
          </DialogDescription>
        </DialogHeader>

        <form className="mt-4 space-y-4" action={runAction}>
          <div className="space-y-1.5">
            <FieldLabel htmlFor="case_number">Case number</FieldLabel>
            <Input
              id="case_number"
              name="case_number"
              placeholder="e.g. CI-2026-001"
              autoComplete="off"
              maxLength={100}
              aria-invalid={Boolean(fieldErrors.case_number)}
              className={cn(
                fieldErrors.case_number &&
                  "border-danger focus-visible:border-danger focus-visible:ring-danger/30",
              )}
            />
            {fieldErrors.case_number ? (
              <FieldError>{fieldErrors.case_number}</FieldError>
            ) : null}
          </div>

          <div className="space-y-1.5">
            <FieldLabel htmlFor="title">Title</FieldLabel>
            <Input
              id="title"
              name="title"
              placeholder="Short, descriptive title"
              autoComplete="off"
              maxLength={500}
              aria-invalid={Boolean(fieldErrors.title)}
              className={cn(
                fieldErrors.title &&
                  "border-danger focus-visible:border-danger focus-visible:ring-danger/30",
              )}
            />
            {fieldErrors.title ? (
              <FieldError>{fieldErrors.title}</FieldError>
            ) : null}
          </div>

          <div className="space-y-1.5">
            <FieldLabel htmlFor="description">Description</FieldLabel>
            <Textarea
              id="description"
              name="description"
              placeholder="Optional context for the investigation"
              rows={3}
              maxLength={5000}
            />
          </div>

          {formError ? <GenericError message={formError} /> : null}

          <DialogFooter>
            <DialogClose asChild>
              <Button type="button" variant="ghost" disabled={pending}>
                Cancel
              </Button>
            </DialogClose>
            <Button type="submit" disabled={pending}>
              {pending ? (
                <Loader2 className="size-4 animate-spin" aria-hidden />
              ) : null}
              {pending ? "Creating case" : "Create case"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}