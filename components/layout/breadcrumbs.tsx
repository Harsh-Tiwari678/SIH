"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { ChevronRight } from "lucide-react"
import { cn } from "@/lib/utils"

const SEGMENT_LABELS: Record<string, string> = {
  dashboard: "Dashboard",
  cases: "Cases",
}

function isUuidLike(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
    value,
  )
}

function trailFromPathname(
  pathname: string,
): { href: string; label: string }[] {
  const segments = pathname.split("/").filter(Boolean)
  const trail: { href: string; label: string }[] = []
  let href = ""

  for (const raw of segments) {
    href += `/${raw}`
    const label = SEGMENT_LABELS[raw] ?? (isUuidLike(raw) ? "Case" : raw)
    trail.push({
      href,
      label: label.charAt(0).toUpperCase() + label.slice(1),
    })
  }

  return trail
}

export function Breadcrumbs({ className }: { className?: string }) {
  const pathname = usePathname()
  const trail = trailFromPathname(pathname)

  if (trail.length === 0) {
    return null
  }

  return (
    <nav aria-label="Breadcrumb" className={cn("min-w-0", className)}>
      <ol className="flex min-w-0 items-center gap-1.5 text-sm">
        {trail.map((crumb, index) => {
          const isLast = index === trail.length - 1
          return (
            <li
              key={crumb.href}
              className="flex min-w-0 items-center gap-1.5"
            >
              {index > 0 ? (
                <ChevronRight
                  aria-hidden
                  className="size-3.5 shrink-0 text-muted-foreground/60"
                />
              ) : null}
              {isLast ? (
                <span
                  aria-current="page"
                  className="truncate font-medium text-foreground"
                >
                  {crumb.label}
                </span>
              ) : (
                <Link
                  href={crumb.href}
                  className="shrink-0 truncate text-muted-foreground transition-colors duration-150 ease-out-quick hover:text-foreground"
                >
                  {crumb.label}
                </Link>
              )}
            </li>
          )
        })}
      </ol>
    </nav>
  )
}