"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import type { LucideIcon } from "lucide-react"
import { FolderOpen, LayoutDashboard } from "lucide-react"
import { cn } from "@/lib/utils"
import type { ComponentProps } from "react"

type NavItem = {
  label: string
  href: string
  icon: LucideIcon
}

const WORKSPACE_ITEM: NavItem = {
  label: "Dashboard",
  href: "/dashboard",
  icon: LayoutDashboard,
}

const CASE_ITEMS: NavItem[] = [
  { label: "All Cases", href: "/cases", icon: FolderOpen },
]

function isActive(pathname: string, href: string): boolean {
  if (href === "/") {
    return pathname === "/"
  }
  return pathname === href || pathname.startsWith(`${href}/`)
}

type SidebarNavLinkProps = Omit<ComponentProps<typeof Link>, "href"> & {
  item: NavItem
  onNavigate?: () => void
}

function SidebarNavLink({ item, onNavigate, ...props }: SidebarNavLinkProps) {
  const pathname = usePathname()
  const active = isActive(pathname, item.href)

  return (
    <Link
      href={item.href}
      data-active={active}
      onClick={onNavigate}
      className={cn(
        "group/navlink relative flex h-8 items-center gap-2 rounded-lg px-2 text-sm text-muted-foreground outline-none",
        "transition-colors duration-150 ease-out-quick",
        "hover:bg-muted/70 hover:text-foreground",
        "active:translate-y-px",
        "focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background",
        "data-[active=true]:bg-muted data-[active=true]:font-medium data-[active=true]:text-foreground",
      )}
      {...props}
    >
      {active ? (
        <span
          data-slot="nav-active-bar"
          aria-hidden
          className="absolute -left-3 top-1/2 h-4 w-0.5 -translate-y-1/2 rounded-full bg-primary"
        />
      ) : null}
      <item.icon
        aria-hidden
        className="size-4 shrink-0 text-current"
      />
      <span className="truncate">{item.label}</span>
    </Link>
  )
}

function SidebarNav({
  onNavigate,
}: {
  onNavigate?: () => void
}) {
  return (
    <nav aria-label="Primary">
      <ul className="space-y-0.5">
        <li>
          <SidebarNavLink item={WORKSPACE_ITEM} onNavigate={onNavigate} />
        </li>
      </ul>
      <p className="mb-1 mt-6 px-2 text-[13px] font-medium text-muted-foreground">
        Cases
      </p>
      <ul className="space-y-0.5">
        {CASE_ITEMS.map((item) => (
          <li key={item.href}>
            <SidebarNavLink item={item} onNavigate={onNavigate} />
          </li>
        ))}
      </ul>
    </nav>
  )
}

export { SidebarNav }