"use client"

import * as React from "react"
import { AlertCircle, Check, Loader2, UserPlus } from "lucide-react"
import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { OrgRolePicker } from "./org-role-picker"
import {
  type OrgMemberRole,
  type LookupCandidate,
  fetchMemberLookup,
  addOrganizationMember,
} from "@/lib/organization-api/organization-member-client"

const DEBOUNCE_MS = 250
const MIN_QUERY_LENGTH = 2

type SearchState =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "results"; profiles: LookupCandidate[] }

// Add a profile to the organization roster. The profile must already exist;
// this dialog never creates one. Candidates come from the lookup RPC and the
// only typed input is the search term — profile ids are picked, never typed.
// Authorization is enforced by the add_organization_member RPC; a non-admin
// viewer receives a 403 mapped to a plain message here.
export function AddMemberDialog({
  orgId,
  open,
  onOpenChange,
  onMemberAdded,
}: {
  orgId: string
  open: boolean
  onOpenChange: (open: boolean) => void
  onMemberAdded: () => void
}) {
  const [query, setQuery] = React.useState("")
  const [searchState, setSearchState] = React.useState<SearchState>({
    kind: "idle",
  })
  const [selected, setSelected] = React.useState<LookupCandidate | null>(null)
  const [role, setRole] = React.useState<OrgMemberRole>("member")
  const [pending, setPending] = React.useState(false)
  const [formError, setFormError] = React.useState<string | null>(null)

  const controllerRef = React.useRef<AbortController | null>(null)
  const timerRef = React.useRef<ReturnType<typeof setTimeout> | null>(null)

  React.useEffect(() => {
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current)
      controllerRef.current?.abort()
    }
  }, [])

  function handleOpenChange(next: boolean) {
    onOpenChange(next)
    if (next) {
      setQuery("")
      setSearchState({ kind: "idle" })
      setSelected(null)
      setRole("member")
      setFormError(null)
      setPending(false)
    } else {
      if (timerRef.current) clearTimeout(timerRef.current)
      controllerRef.current?.abort()
    }
  }

  function handleQueryChange(value: string) {
    setQuery(value)
    setFormError(null)
    if (timerRef.current) clearTimeout(timerRef.current)
    controllerRef.current?.abort()

    const trimmed = value.trim()
    if (trimmed.length < MIN_QUERY_LENGTH) {
      setSearchState({ kind: "idle" })
      return
    }

    setSearchState({ kind: "loading" })
    const ac = new AbortController()
    controllerRef.current = ac
    timerRef.current = setTimeout(async () => {
      const result = await fetchMemberLookup(orgId, trimmed, ac.signal)
      if (ac.signal.aborted) return
      if (!result.ok) {
        setSearchState({ kind: "error", message: result.message })
        return
      }
      setSearchState({ kind: "results", profiles: result.profiles })
    }, DEBOUNCE_MS)
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!selected || pending) return

    setPending(true)
    setFormError(null)
    const result = await addOrganizationMember(orgId, {
      profile_id: selected.id,
      role_in_org: role,
    })
    setPending(false)
    if (!result.ok) {
      setFormError(result.message)
      return
    }
    onOpenChange(false)
    onMemberAdded()
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Add member</DialogTitle>
          <DialogDescription>
            Search for a profile and assign an organization role.
          </DialogDescription>
        </DialogHeader>

        <form className="mt-4 space-y-4" onSubmit={handleSubmit}>
          <div className="space-y-1.5">
            <label
              htmlFor="member-search"
              className="block text-sm font-medium text-foreground"
            >
              Profile
            </label>
            <Input
              id="member-search"
              type="search"
              placeholder="Search by name or badge"
              value={query}
              onChange={(e) => handleQueryChange(e.target.value)}
              disabled={pending}
              autoComplete="off"
            />
            {searchState.kind === "loading" ? (
              <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
                <Loader2 className="size-3 animate-spin" aria-hidden />
                Searching…
              </p>
            ) : null}
            {searchState.kind === "error" ? (
              <p
                role="alert"
                className="flex items-center gap-1.5 text-xs text-danger"
              >
                <AlertCircle className="size-3.5 shrink-0" aria-hidden />
                {searchState.message}
              </p>
            ) : null}
            {searchState.kind === "results" &&
            searchState.profiles.length === 0 ? (
              <p className="text-xs text-muted-foreground">
                No matching profiles found.
              </p>
            ) : null}
          </div>

          {searchState.kind === "results" && searchState.profiles.length > 0 ? (
            <div
              role="radiogroup"
              aria-label="Available profiles"
              className="max-h-48 divide-y divide-border/50 overflow-y-auto rounded-md border border-border/70"
            >
              {searchState.profiles.map((p) => {
                const isSelected = selected?.id === p.id
                return (
                  <label
                    key={p.id}
                    className={cn(
                      "flex cursor-pointer items-start gap-3 px-3 py-2.5 transition-colors duration-150",
                      isSelected ? "bg-muted" : "hover:bg-muted/50",
                    )}
                  >
                    <input
                      type="radio"
                      name="selected-profile"
                      value={p.id}
                      checked={isSelected}
                      onChange={() => setSelected(p)}
                      disabled={pending}
                      className="mt-0.5"
                    />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm font-medium text-foreground">
                        {p.full_name || "—"}
                      </span>
                      <span className="block truncate font-mono text-xs text-muted-foreground">
                        {p.badge_number ? `${p.badge_number} · ` : ""}
                        {p.id}
                      </span>
                    </span>
                    {isSelected ? (
                      <Check
                        aria-hidden
                        className="mt-0.5 size-4 shrink-0 text-primary"
                      />
                    ) : null}
                  </label>
                )
              })}
            </div>
          ) : null}

          {selected ? (
            <div className="flex items-center gap-2 rounded-md border border-primary/30 bg-primary/5 px-3 py-2 text-sm">
              <Check aria-hidden className="size-4 shrink-0 text-primary" />
              <span className="truncate font-medium text-foreground">
                {selected.full_name || selected.id}
              </span>
              <button
                type="button"
                onClick={() => setSelected(null)}
                className="ml-auto shrink-0 text-xs text-muted-foreground transition-colors duration-150 hover:text-foreground"
              >
                Clear
              </button>
            </div>
          ) : null}

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
              onClick={() => onOpenChange(false)}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={pending || !selected}>
              {pending ? (
                <Loader2 className="size-4 animate-spin" aria-hidden />
              ) : (
                <UserPlus aria-hidden className="size-4" />
              )}
              {pending ? "Adding" : "Add member"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}