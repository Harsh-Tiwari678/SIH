"use client"

import * as React from "react"
import {
  AlertCircle,
  Download,
  Eye,
  Loader2,
  RefreshCw,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import Image from "next/image"
import {
  type EvidenceAccessMode,
  type EvidenceAccessResponse,
  evidencePreviewKind,
  evidencePreviewKindLabel,
} from "@/lib/evidence-access"
import type { EvidenceVersion } from "@/lib/evidence-serialization"
import { formatBytes } from "@/components/cases/evidence/evidence"

type AccessState =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "ready"; access: EvidenceAccessResponse }
  | { status: "error"; message: string }

const ACCESS_ERROR_MESSAGES: Record<number, string> = {
  401: "Your session has expired. Sign in again to open evidence files.",
  403: "You don't have permission to open this file.",
  404: "This evidence or file version could not be found.",
  400: "This request is invalid.",
}

export function FileAccessPanel({
  caseId,
  evidenceId,
  versions,
}: {
  caseId: string
  evidenceId: string
  versions: EvidenceVersion[]
}) {
  const latest = versions[versions.length - 1]
  const [versionId, setVersionId] = React.useState<string | null>(
    latest?.id ?? null,
  )
  const [access, setAccess] = React.useState<AccessState>({ status: "idle" })
  const [previewFailed, setPreviewFailed] = React.useState(false)

  if (!latest) return null

  // If the selected version disappeared (e.g. after a reload) the latest one
  // is the safe fallback; the select's value always has a live option.
  const selected = versions.find((v) => v.id === versionId) ?? latest
  const kind = evidencePreviewKind(selected.mime_type)
  const renderKind: Exclude<ReturnType<typeof evidencePreviewKind>, "none"> | null =
    kind === "none" ? null : kind

  async function openAccess(mode: EvidenceAccessMode) {
    setAccess({ status: "loading" })
    setPreviewFailed(false)
    try {
      const res = await fetch(
        `/api/cases/${caseId}/evidence/${evidenceId}/access?mode=${mode}&version=${selected.id}`,
        { cache: "no-store" },
      )
      const data = (await res.json().catch(() => ({}))) as {
        access?: EvidenceAccessResponse
        error?: string
      }
      if (!res.ok || !data.access) {
        const message =
          ACCESS_ERROR_MESSAGES[res.status] ??
          data.error ??
          "We could not open the file right now. Try again."
        setAccess({ status: "error", message })
        return
      }
      setAccess({ status: "ready", access: data.access })
      if (mode === "download") {
        // A transient anchor: no persistent state, no cached link. The storage
        // URL already carries ?download=<name> so the server forces an
        // attachment with the real file name.
        triggerDownload(data.access.url, data.access.file_name)
        setAccess({ status: "idle" })
      }
    } catch {
      setAccess({
        status: "error",
        message: "We could not open the file right now. Try again.",
      })
    }
  }

  return (
    <div>
      <h4 className="flex items-center gap-1.5 text-sm font-semibold text-foreground">
        <Eye aria-hidden className="size-4 text-muted-foreground" />
        Open file
      </h4>
      <div className="mt-2 overflow-hidden rounded-lg border border-border/80 bg-background shadow-sm">
        <div className="flex flex-wrap items-center gap-3 px-4 py-3">
          {versions.length > 1 ? (
            <label className="flex items-center gap-2 text-xs text-muted-foreground">
              Version
              <select
                value={selected.id}
                onChange={(event) => {
                  setVersionId(event.target.value)
                  setAccess({ status: "idle" })
                  setPreviewFailed(false)
                }}
                className="h-9 rounded-md border border-border/80 bg-background px-2.5 text-sm text-foreground focus:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                {versions.map((v) => (
                  <option key={v.id} value={v.id}>
                    v{v.version}
                  </option>
                ))}
              </select>
            </label>
          ) : null}

          <span className="min-w-0 flex-1">
            <span className="block truncate font-mono text-[13px] text-foreground">
              {selected.file_name}
            </span>
            <span className="block font-mono text-xs text-muted-foreground">
              {selected.mime_type} · {formatBytes(selected.file_size_bytes)} ·
              v{selected.version}
            </span>
          </span>

          <div className="flex items-center gap-2">
            {renderKind ? (
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => openAccess("preview")}
                disabled={access.status === "loading"}
              >
                {access.status === "loading" ? (
                  <Loader2 className="size-3.5 animate-spin" aria-hidden />
                ) : (
                  <Eye aria-hidden className="size-3.5" />
                )}
                Preview
              </Button>
            ) : null}
            <Button
              type="button"
              size="sm"
              onClick={() => openAccess("download")}
              disabled={access.status === "loading"}
            >
              <Download aria-hidden className="size-3.5" />
              Download
            </Button>
          </div>
        </div>

        {access.status === "error" ? (
          <p
            role="alert"
            className="flex items-center gap-1.5 border-t border-border/70 px-4 py-2.5 text-sm text-danger"
          >
            <AlertCircle className="size-4 shrink-0" aria-hidden />
            <span>{access.message}</span>
          </p>
        ) : null}

        {previewFailed ? (
          <div className="flex flex-wrap items-center gap-2 border-t border-border/70 px-4 py-3">
            <p className="flex items-center gap-1.5 text-sm text-muted-foreground">
              <AlertCircle className="size-4 shrink-0" aria-hidden />
              That preview link expired. Get a fresh one.
            </p>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => openAccess("preview")}
            >
              <RefreshCw aria-hidden className="size-3.5" />
              Refresh preview
            </Button>
          </div>
        ) : null}

        {access.status === "ready" && access.access.mode === "preview" && renderKind ? (
          <PreviewBody
            kind={renderKind}
            url={access.access.url}
            fileName={access.access.file_name}
            onError={() => setPreviewFailed(true)}
          />
        ) : null}
      </div>
      <p className="mt-2 text-xs text-muted-foreground">
        {renderKind
          ? `Previewing as a ${evidencePreviewKindLabel(renderKind)}. `
          : "This file type can't be previewed in the browser. "}
        Files open through a short-lived authorized link; every preview or
        download is recorded in this case&apos;s audit trail.
      </p>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Preview rendering — the signed URL is transient component state, never
// persisted or rendered as a link. Bytes stay in the browser's renderer for
// iframes/objects or flow through media tags; nothing is copied server-side.
// ---------------------------------------------------------------------------

function PreviewBody({
  kind,
  url,
  fileName,
  onError,
}: {
  kind: "image" | "pdf" | "text" | "video" | "audio"
  url: string
  fileName: string
  onError: () => void
}) {
  if (kind === "image") {
    return (
      <div className="border-t border-border/70 bg-muted/30 p-4">
        <div className="relative mx-auto h-[32rem] w-full max-w-3xl overflow-hidden rounded-md border border-border/70 bg-background">
          <Image
            src={url}
            alt={`Preview of ${fileName}`}
            fill
            sizes="70rem"
            unoptimized
            onError={onError}
            className="object-contain p-2"
          />
        </div>
      </div>
    )
  }
  if (kind === "pdf" || kind === "text") {
    return (
      <div className="border-t border-border/70 bg-muted/30 p-4">
        <iframe
          src={url}
          title={`Preview of ${fileName}`}
          onError={onError}
          className="h-[32rem] w-full rounded-md border border-border/70 bg-background"
        />
      </div>
    )
  }
  if (kind === "video") {
    return (
      <div className="border-t border-border/70 bg-muted/30 p-4">
        <video
          controls
          preload="metadata"
          src={url}
          onError={onError}
          className="mx-auto max-h-[32rem] w-full max-w-3xl rounded-md border border-border/70 bg-background"
        >
          Your browser does not support video preview. Download the file instead.
        </video>
      </div>
    )
  }
  return (
    <div className="border-t border-border/70 bg-muted/30 p-4">
      <audio
        controls
        preload="metadata"
        src={url}
        onError={onError}
        className="mx-auto w-full max-w-md"
      >
        Your browser does not support audio preview. Download the file instead.
      </audio>
    </div>
  )
}

function triggerDownload(url: string, fileName: string) {
  const anchor = document.createElement("a")
  anchor.href = url
  anchor.download = fileName
  anchor.rel = "noopener"
  anchor.style.display = "none"
  document.body.appendChild(anchor)
  anchor.click()
  document.body.removeChild(anchor)
}