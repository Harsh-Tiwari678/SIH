"use client"

import * as React from "react"
import { Check, Copy } from "lucide-react"
import { Button } from "@/components/ui/button"

// Copies a technical value (SHA-256, transaction hash, contract address) with
// an always-labeled, keyboard-accessible action. The copied state is a
// transient visual confirmation only — the value itself is never transformed.
export function CopyButton({
  value,
  label,
}: {
  value: string
  label: string
}) {
  const [copied, setCopied] = React.useState(false)

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1500)
    } catch {
      // Clipboard access can be denied; leave the button in its idle state.
    }
  }

  return (
    <Button
      type="button"
      variant="ghost"
      size="icon-sm"
      aria-label={copied ? `Copied ${label}` : `Copy ${label}`}
      title={copied ? `Copied ${label}` : `Copy ${label}`}
      onClick={handleCopy}
    >
      {copied ? (
        <Check aria-hidden className="size-3.5" />
      ) : (
        <Copy aria-hidden className="size-3.5" />
      )}
    </Button>
  )
}