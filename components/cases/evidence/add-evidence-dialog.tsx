"use client"

import * as React from "react"
import { AlertCircle, CheckCircle2, FileUp, Loader2, Plus } from "lucide-react"
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
import { CopyButton } from "@/components/cases/evidence/copy-button"
import {
  ACCEPT_FILE_INPUT,
  EVIDENCE_TYPE_OPTIONS,
  MAX_EVIDENCE_FILE_SIZE_BYTES,
  formatBytes,
  humanize,
  isAllowedEvidenceMime,
  suggestedTypeForMime,
} from "@/components/cases/evidence/evidence"

type Phase =
  | "idle"
  | "uploading"
  | "finalizing"
  | "success"
  | "error"

type SuccessResult = {
  evidenceId: string
  evidenceNumber: string
  sha256: string
}

const UPLOAD_TIMEOUT_MS = 120_000

function FieldError({ message }: { message: string }) {
  return (
    <p className="flex items-center gap-1.5 text-xs text-danger">
      <AlertCircle className="size-3.5 shrink-0" aria-hidden />
      <span>{message}</span>
    </p>
  )
}

export function AddEvidenceDialog({
  caseId,
  onCreated,
  onViewEvidence,
}: {
  caseId: string
  onCreated: () => void
  onViewEvidence: (evidenceId: string) => void
}) {
  const [open, setOpen] = React.useState(false)
  const [file, setFile] = React.useState<File | null>(null)
  const [title, setTitle] = React.useState("")
  const [description, setDescription] = React.useState("")
  const [type, setType] = React.useState<string>("document")
  const [fileError, setFileError] = React.useState<string | null>(null)
  const [titleError, setTitleError] = React.useState<string | null>(null)
  const [descriptionError, setDescriptionError] = React.useState<string | null>(null)
  const [submitError, setSubmitError] = React.useState<string | null>(null)
  const [phase, setPhase] = React.useState<Phase>("idle")
  const [progress, setProgress] = React.useState(0)
  const [result, setResult] = React.useState<SuccessResult | null>(null)

  const busy = phase === "uploading" || phase === "finalizing"

  function openDialog() {
    setFile(null)
    setTitle("")
    setDescription("")
    setType("document")
    setFileError(null)
    setTitleError(null)
    setDescriptionError(null)
    setSubmitError(null)
    setPhase("idle")
    setProgress(0)
    setResult(null)
  }

  function handleOpenChange(nextOpen: boolean) {
    if (!nextOpen && busy) {
      // Never let the dialog be closed (via overlay/X) mid-upload: the request
      // is in flight and the server may already be creating evidence.
      return
    }
    setOpen(nextOpen)
    if (nextOpen) openDialog()
  }

  function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const picked = e.target.files?.[0] ?? null
    setFileError(null)
    if (!picked) {
      setFile(null)
      return
    }
    if (picked.size > MAX_EVIDENCE_FILE_SIZE_BYTES) {
      setFile(picked)
      setFileError("File exceeds the 50 MiB limit.")
      return
    }
    if (!isAllowedEvidenceMime(picked.type.toLowerCase())) {
      setFile(picked)
      setFileError("This file type is not allowed.")
      return
    }
    setFile(picked)
    setType(suggestedTypeForMime(picked.type))
  }

  function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault()
    const nextTitle = title.trim()
    const nextDescription = description.trim()

    let invalid = false
    if (!file) {
      setFileError("Choose a file to upload.")
      invalid = true
    }
    if (!nextTitle) {
      setTitleError("Title is required.")
      invalid = true
    } else if (nextTitle.length > 500) {
      setTitleError("Title must be 500 characters or fewer.")
      invalid = true
    }
    if (nextDescription.length > 5000) {
      setDescriptionError("Description must be 5000 characters or fewer.")
      invalid = true
    }
    if (invalid) return

    setFileError(null)
    setTitleError(null)
    setDescriptionError(null)
    setSubmitError(null)

    const formData = new FormData()
    formData.set("file", file as File)
    formData.set("title", nextTitle)
    formData.set("type", type)
    if (nextDescription) formData.set("description", nextDescription)

    const xhr = new XMLHttpRequest()
    xhr.open("POST", `/api/cases/${caseId}/evidence`)
    xhr.timeout = UPLOAD_TIMEOUT_MS

    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable) {
        const percent = Math.round((event.loaded / event.total) * 100)
        setProgress(Math.min(percent, 100))
      }
      setPhase("uploading")
    }
    xhr.upload.onload = () => {
      // The bytes have reached the server; the server now validates, hashes,
      // stores, and writes the evidence records before it replies.
      setPhase("finalizing")
    }
    xhr.onload = () => {
      let body: Record<string, unknown> = {}
      try {
        body = JSON.parse(xhr.responseText) as Record<string, unknown>
      } catch {
        // Non-JSON failure; report generically below.
      }
      if (xhr.status >= 200 && xhr.status < 300) {
        const evidence = body.evidence as
          | { id?: string; evidence_number?: string }
          | undefined
        const version = body.document_version as { sha256?: string } | undefined
        setResult({
          evidenceId: evidence?.id ?? "",
          evidenceNumber: evidence?.evidence_number ?? "",
          sha256: version?.sha256 ?? "",
        })
        setPhase("success")
        onCreated()
        return
      }
      setSubmitError(apiErrorText(String(body.error ?? "")))
      setPhase("error")
    }
    xhr.onerror = () => {
      setSubmitError("The upload failed. Check your connection and try again.")
      setPhase("error")
    }
    xhr.ontimeout = () => {
      setSubmitError("The upload timed out. Try a smaller file or try again.")
      setPhase("error")
    }

    setProgress(0)
    setPhase("uploading")
    xhr.send(formData)
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogTrigger asChild>
        <Button size="sm">
          <Plus aria-hidden className="size-4" />
          Add evidence
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Add evidence</DialogTitle>
          <DialogDescription>
            Attach an evidentiary file. The case lead or an investigator records
            the initial chain of custody.
          </DialogDescription>
        </DialogHeader>

        {phase === "success" && result ? (
          <div className="mt-4 space-y-4">
            <div
              role="status"
              className="flex gap-2.5 rounded-lg border border-border/80 bg-background p-3.5"
            >
              <CheckCircle2
                aria-hidden
                className="mt-0.5 size-4 shrink-0 text-success"
              />
              <div className="min-w-0 text-sm">
                <p className="font-medium text-foreground">
                  Evidence created
                </p>
                <p className="mt-0.5 text-muted-foreground">
                  {result.evidenceNumber || "Evidence"} was uploaded and its
                  integrity fingerprint computed by the server.
                </p>
              </div>
            </div>

            <div className="space-y-1.5">
              <p className="text-sm font-medium text-foreground">
                Integrity (SHA-256)
              </p>
              <div className="flex items-center gap-2 rounded-md border border-border/80 bg-muted/40 px-2.5 py-2">
                <code className="min-w-0 break-all font-mono text-[13px] text-foreground">
                  {result.sha256 || "—"}
                </code>
                {result.sha256 ? (
                  <span className="shrink-0">
                    <CopyButton value={result.sha256} label="SHA-256 hash" />
                  </span>
                ) : null}
              </div>
              <p className="text-xs text-muted-foreground">
                The fingerprint is shown only after the server has verified the
                uploaded bytes.
              </p>
            </div>

            <DialogFooter>
              <DialogClose asChild>
                <Button type="button" variant="ghost">
                  Close
                </Button>
              </DialogClose>
              {result.evidenceId ? (
                <Button
                  type="button"
                  onClick={() => {
                    setOpen(false)
                    onViewEvidence(result.evidenceId)
                  }}
                >
                  View evidence
                </Button>
              ) : null}
            </DialogFooter>
          </div>
        ) : (
          <form className="mt-4 space-y-4" onSubmit={handleSubmit}>
            <div className="space-y-1.5">
              <label
                htmlFor="evidence-file"
                className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-border bg-background px-2.5 text-sm font-medium text-foreground shadow-sm transition-colors duration-150 ease-out-quick hover:bg-muted focus-within:ring-3 focus-within:ring-ring/50"
              >
                <FileUp aria-hidden className="size-4" />
                Choose a file
              </label>
              <input
                id="evidence-file"
                type="file"
                className="sr-only"
                accept={ACCEPT_FILE_INPUT}
                disabled={busy}
                onChange={handleFileChange}
              />
              {file ? (
                <div className="flex flex-wrap items-baseline gap-x-2 rounded-md border border-border/80 bg-muted/40 px-2.5 py-2">
                  <span className="min-w-0 break-all font-mono text-[13px] text-foreground">
                    {file.name}
                  </span>
                  <span className="font-mono text-xs text-muted-foreground">
                    {formatBytes(file.size)}
                  </span>
                  <span className="font-mono text-xs text-muted-foreground">
                    {file.type}
                  </span>
                </div>
              ) : null}
              {fileError ? <FieldError message={fileError} /> : null}
              <p
                id="evidence-file-hint"
                className="text-xs text-muted-foreground"
              >
                Max 50 MiB. Allowed: PDF, PNG, JPEG, MP4, MP3, TXT.
              </p>
            </div>

            <div className="space-y-1.5">
              <label
                htmlFor="evidence-title"
                className="block text-sm font-medium text-foreground"
              >
                Title
              </label>
              <Input
                id="evidence-title"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                maxLength={500}
                disabled={busy}
                placeholder="What this evidence is"
                aria-invalid={Boolean(titleError)}
                className={cn(
                  titleError &&
                    "border-danger focus-visible:border-danger focus-visible:ring-danger/30",
                )}
              />
              {titleError ? <FieldError message={titleError} /> : null}
            </div>

            <div className="space-y-1.5">
              <label
                htmlFor="evidence-type"
                className="block text-sm font-medium text-foreground"
              >
                Type
              </label>
              <select
                id="evidence-type"
                value={type}
                onChange={(e) => setType(e.target.value)}
                disabled={busy}
                className="flex h-8 w-full rounded-md border border-input bg-background px-2.5 text-sm text-foreground shadow-sm outline-none transition-colors duration-150 ease-out-quick focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {EVIDENCE_TYPE_OPTIONS.map((option) => (
                  <option key={option} value={option}>
                    {humanize(option)}
                  </option>
                ))}
              </select>
            </div>

            <div className="space-y-1.5">
              <label
                htmlFor="evidence-description"
                className="block text-sm font-medium text-foreground"
              >
                Description
                <span className="ml-1 font-normal text-muted-foreground">
                  (optional)
                </span>
              </label>
              <Textarea
                id="evidence-description"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={4}
                maxLength={5000}
                disabled={busy}
                placeholder={
                  "Context about how or where the evidence was collected"
                }
                aria-invalid={Boolean(descriptionError)}
                className={cn(
                  descriptionError &&
                    "border-danger focus-visible:border-danger focus-visible:ring-danger/30",
                )}
              />
              {descriptionError ? (
                <FieldError message={descriptionError} />
              ) : null}
            </div>

            {busy ? (
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-medium text-foreground">
                    {phase === "uploading"
                      ? `Uploading ${progress}%`
                      : "Creating the evidence record…"}
                  </span>
                  {phase === "finalizing" ? (
                    <Loader2
                      aria-hidden
                      className="size-3.5 animate-spin text-muted-foreground"
                    />
                  ) : null}
                </div>
                <div
                  role="progressbar"
                  aria-valuenow={progress}
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-label="Upload progress"
                  className="h-1.5 overflow-hidden rounded-full bg-muted"
                >
                  <div
                    className="h-full rounded-full bg-primary transition-[width] duration-150 ease-out-quick"
                    style={{ width: `${phase === "uploading" ? progress : 100}%` }}
                  />
                </div>
              </div>
            ) : null}

            {phase === "error" && submitError ? (
              <p role="alert" className="flex items-center gap-1.5 text-sm text-danger">
                <AlertCircle className="size-4 shrink-0" aria-hidden />
                <span>{submitError}</span>
              </p>
            ) : null}

            <DialogFooter>
              <DialogClose asChild>
                <Button type="button" variant="ghost" disabled={busy}>
                  Cancel
                </Button>
              </DialogClose>
              <Button type="submit" disabled={busy}>
                {busy ? (
                  <Loader2 className="size-4 animate-spin" aria-hidden />
                ) : null}
                {busy
                  ? phase === "uploading"
                    ? "Uploading"
                    : "Creating"
                  : "Upload evidence"}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  )
}

// Map a server error body to a user-safe message. The endpoints already return
// user-safe text; this only collapses empty/unknown bodies to a generic line.
function apiErrorText(message: string): string {
  if (message) return message
  return "The upload failed. Try again."
}