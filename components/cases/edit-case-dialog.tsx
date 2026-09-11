"use client"

import * as React from "react"
import { AlertCircle, Loader2, Pencil } from "lucide-react"
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
import type { CaseDetail } from "@/components/cases/case-detail"

function UpdateError({ message }: { message: string }) {
  return (
    <p role="alert" className="flex items-center gap-1.5 text-sm text-danger">
      <AlertCircle className="size-4 shrink-0" aria-hidden />
      <span>{message}</span>
    </p>
  )
}

export function EditCaseDialog({
  caseDetail,
  onSaved,
}: {
  caseDetail: CaseDetail
  onSaved: () => void
}) {
  const [open, setOpen] = React.useState(false)
  const [pending, setPending] = React.useState(false)
  const [title, setTitle] = React.useState("")
  const [description, setDescription] = React.useState("")
  const [titleError, setTitleError] = React.useState<string | null>(null)
  const [formError, setFormError] = React.useState<string | null>(null)

  function handleOpenChange(nextOpen: boolean) {
    setOpen(nextOpen)
    if (nextOpen) {
      setTitle(caseDetail.title)
      setDescription(caseDetail.description ?? "")
      setTitleError(null)
      setFormError(null)
    }
  }

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault()
    const nextTitle = title.trim()
    const nextDescription = description.trim()

    if (!nextTitle) {
      setTitleError("Title is required.")
      return
    }
    if (nextTitle.length > 500) {
      setTitleError("Title must be 500 characters or fewer.")
      return
    }
    if (nextDescription.length > 5000) {
      setTitleError(null)
      setFormError("Description must be 5000 characters or fewer.")
      return
    }

    setTitleError(null)
    setFormError(null)
    setPending(true)
    try {
      const res = await fetch(`/api/cases/${caseDetail.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: nextTitle,
          description: nextDescription || null,
        }),
      })
      const data = (await res.json().catch(() => ({}))) as { error?: string }
      if (!res.ok) {
        setFormError(labelUpdateError(data.error ?? ""))
        return
      }
      setOpen(false)
      onSaved()
    } catch {
      setFormError("Could not save changes. Try again.")
    } finally {
      setPending(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogTrigger asChild>
        <Button variant="outline">
          <Pencil aria-hidden className="size-4" />
          Edit
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Edit case</DialogTitle>
          <DialogDescription>
            Update the case metadata. The case number cannot be changed.
          </DialogDescription>
        </DialogHeader>

        <form className="mt-4 space-y-4" onSubmit={handleSubmit}>
          <div className="space-y-1.5">
            <label
              htmlFor="case-title"
              className="block text-sm font-medium text-foreground"
            >
              Title
            </label>
            <Input
              id="case-title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              maxLength={500}
              aria-invalid={Boolean(titleError)}
              className={cn(
                titleError &&
                  "border-danger focus-visible:border-danger focus-visible:ring-danger/30",
              )}
            />
            {titleError ? (
              <p className="flex items-center gap-1.5 text-xs text-danger">
                <AlertCircle className="size-3.5 shrink-0" aria-hidden />
                <span>{titleError}</span>
              </p>
            ) : null}
          </div>

          <div className="space-y-1.5">
            <label
              htmlFor="case-description"
              className="block text-sm font-medium text-foreground"
            >
              Description
            </label>
            <Textarea
              id="case-description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={4}
              maxLength={5000}
              placeholder="Optional context for the investigation"
            />
          </div>

          <div className="space-y-1.5">
            <label
              htmlFor="case-number"
              className="block text-sm font-medium text-foreground"
            >
              Case number
            </label>
            <Input
              id="case-number"
              value={caseDetail.case_number}
              readOnly
              tabIndex={-1}
              aria-describedby="case-number-hint"
              className="font-mono text-[13px] text-muted-foreground"
            />
            <p
              id="case-number-hint"
              className="text-xs text-muted-foreground"
            >
              Assigned when the case is created. It cannot be changed.
            </p>
          </div>

          {formError ? <UpdateError message={formError} /> : null}

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
              {pending ? "Saving" : "Save changes"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function labelUpdateError(message: string): string {
  if (message.includes("Unauthorized")) {
    return "Your session has expired. Sign in again."
  }
  if (message.includes("Only the case lead")) {
    return "Only the case lead can edit this case."
  }
  if (message.includes("title")) return "Please check the title."
  if (message.includes("description")) {
    return "Description must be 5000 characters or fewer."
  }
  return "Could not save changes. Try again."
}