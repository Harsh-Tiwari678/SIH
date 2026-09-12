"use client"

import * as React from "react"
import { AlertCircle, Loader2, Plus } from "lucide-react"
import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
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
import { Input } from "@/components/ui/input"
import {
  createOrganization,
} from "@/lib/organization-api/organization-client"
import {
  deriveSlug,
  isValidSlug,
} from "@/lib/organization-api/organization-slug"

// Create an organization. The creator becomes its first admin member — the
// create_organization SECURITY DEFINER RPC derives the actor from the server
// session and enforces name validation, slug format/uniqueness, the admin
// membership and the organization.created audit entry atomically. This dialog
// only submits name + slug; no actor identity is mentioned here and none
// reaches the server.
export function NewOrganizationDialog({
  onCreated,
}: {
  onCreated: () => void
}) {
  const [open, setOpen] = React.useState(false)
  const [pending, setPending] = React.useState(false)
  const [name, setName] = React.useState("")
  const [slug, setSlug] = React.useState("")
  const [slugDirty, setSlugDirty] = React.useState(false)
  const [fieldErrors, setFieldErrors] = React.useState<{
    name?: string
    slug?: string
  }>({})
  const [formError, setFormError] = React.useState<string | null>(null)

  function handleOpenChange(nextOpen: boolean) {
    setOpen(nextOpen)
    if (nextOpen) {
      setName("")
      setSlug("")
      setSlugDirty(false)
      setPending(false)
      setFieldErrors({})
      setFormError(null)
    }
  }

  function handleNameChange(value: string) {
    setName(value)
    if (!slugDirty) {
      setSlug(deriveSlug(value))
    }
  }

  function handleSlugChange(value: string) {
    setSlugDirty(true)
    setSlug(value.trim().toLowerCase())
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    const trimmedName = name.trim()
    const trimmedSlug = slug.trim().toLowerCase()

    const next: { name?: string; slug?: string } = {}
    if (!trimmedName) next.name = "Organization name is required."
    if (!trimmedSlug) {
      next.slug = "Organization slug is required."
    } else if (!isValidSlug(trimmedSlug)) {
      next.slug =
        "Slug must be lowercase letters and digits separated by single hyphens (at most 63 characters)."
    }
    setFieldErrors(next)
    setFormError(null)
    if (next.name || next.slug) return

    setPending(true)
    const result = await createOrganization({
      name: trimmedName,
      slug: trimmedSlug,
    })
    setPending(false)
    if (!result.ok) {
      setFormError(result.message)
      return
    }
    setOpen(false)
    onCreated()
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogTrigger asChild>
        <Button>
          <Plus aria-hidden className="size-4" />
          New organization
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>New organization</DialogTitle>
          <DialogDescription>
            Create an organization. You will become its first admin.
          </DialogDescription>
        </DialogHeader>

        <form className="mt-4 space-y-4" onSubmit={handleSubmit}>
          <div className="space-y-1.5">
            <label
              htmlFor="organization-name"
              className="block text-sm font-medium text-foreground"
            >
              Name
            </label>
            <Input
              id="organization-name"
              type="text"
              placeholder="e.g. Cyber Crime Cell"
              value={name}
              onChange={(e) => handleNameChange(e.target.value)}
              disabled={pending}
              autoComplete="off"
              maxLength={500}
              aria-invalid={Boolean(fieldErrors.name)}
              className={cn(
                fieldErrors.name &&
                  "border-danger focus-visible:border-danger focus-visible:ring-danger/30",
              )}
            />
            {fieldErrors.name ? (
              <p className="flex items-center gap-1.5 text-xs text-danger">
                <AlertCircle className="size-3.5 shrink-0" aria-hidden />
                <span>{fieldErrors.name}</span>
              </p>
            ) : null}
          </div>

          <div className="space-y-1.5">
            <label
              htmlFor="organization-slug"
              className="block text-sm font-medium text-foreground"
            >
              Slug
            </label>
            <Input
              id="organization-slug"
              type="text"
              placeholder="cyber-crime-cell"
              value={slug}
              onChange={(e) => handleSlugChange(e.target.value)}
              disabled={pending}
              autoComplete="off"
              maxLength={63}
              spellCheck={false}
              aria-invalid={Boolean(fieldErrors.slug)}
              className={cn(
                "font-mono",
                fieldErrors.slug &&
                  "border-danger focus-visible:border-danger focus-visible:ring-danger/30",
              )}
            />
            <p className="text-xs text-muted-foreground">
              Unique and URL-safe. Generated from the name — edit if needed.
            </p>
            {fieldErrors.slug ? (
              <p className="flex items-center gap-1.5 text-xs text-danger">
                <AlertCircle className="size-3.5 shrink-0" aria-hidden />
                <span>{fieldErrors.slug}</span>
              </p>
            ) : null}
          </div>

          {formError ? (
            <p
              role="alert"
              className="flex items-center gap-1.5 text-sm text-danger"
            >
              <AlertCircle className="size-4 shrink-0" aria-hidden />
              <span>{formError}</span>
            </p>
          ) : null}

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
              {pending ? "Creating" : "Create organization"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}