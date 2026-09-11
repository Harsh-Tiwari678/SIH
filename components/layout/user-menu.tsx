"use client"

import { useFormStatus } from "react-dom"
import { ChevronDown, LogOut } from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { signOut } from "@/app/(app)/actions"

function initialsFromEmail(email: string): string {
  const local = (email.split("@")[0] ?? "").trim()
  if (!local) {
    return "U"
  }
  const parts = local.split(/[._-]+/).filter(Boolean)
  if (parts.length >= 2) {
    return `${parts[0][0]}${parts[1][0]}`.toUpperCase()
  }
  return local.slice(0, 2).toUpperCase()
}

function SignOutButton() {
  const { pending } = useFormStatus()

  return (
    <button
      type="submit"
      disabled={pending}
      className="flex w-full items-center gap-2 text-sm text-foreground disabled:pointer-events-none disabled:opacity-50"
    >
      <LogOut className="size-4 shrink-0" aria-hidden />
      <span>{pending ? "Signing out" : "Sign out"}</span>
    </button>
  )
}

function SignOutForm() {
  return (
    <form action={signOut} className="w-full">
      <SignOutButton />
    </form>
  )
}

export function UserMenu({ userEmail }: { userEmail: string }) {
  const initials = initialsFromEmail(userEmail)

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          className="gap-2 px-1.5 sm:px-2"
          aria-label="Account menu"
        >
          <span
            aria-hidden
            className="flex size-6 shrink-0 items-center justify-center rounded-full bg-primary text-[11px] font-semibold text-primary-foreground"
          >
            {initials}
          </span>
          <span className="hidden max-w-40 truncate text-sm font-medium text-foreground sm:block">
            {userEmail}
          </span>
          <ChevronDown
            aria-hidden
            className="size-3.5 shrink-0 text-muted-foreground"
          />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-60">
        <DropdownMenuLabel className="font-normal">
          <span className="block text-[13px] font-medium text-foreground">
            Signed in as
          </span>
          <span className="mt-0.5 block truncate text-xs font-normal text-muted-foreground">
            {userEmail}
          </span>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem>
          <SignOutForm />
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}