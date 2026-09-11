"use client"

import * as React from "react"
import { Menu } from "lucide-react"
import { Button } from "@/components/ui/button"
import { ProductMark } from "@/components/layout/product-mark"
import { SidebarNav } from "@/components/layout/sidebar-nav"
import { Breadcrumbs } from "@/components/layout/breadcrumbs"
import { UserMenu } from "@/components/layout/user-menu"
import { ThemeToggle } from "@/components/layout/theme-toggle"
import {
  Sheet,
  SheetContent,
  SheetTrigger,
} from "@/components/ui/sheet"

export function Topbar({ userEmail }: { userEmail: string }) {
  const [navOpen, setNavOpen] = React.useState(false)

  return (
    <header className="sticky top-0 z-30 flex h-14 shrink-0 items-center gap-2 border-b border-border/70 bg-background/85 px-4 backdrop-blur supports-[backdrop-filter]:bg-background/70 sm:px-6 lg:px-8">
      <Sheet open={navOpen} onOpenChange={setNavOpen}>
        <SheetTrigger asChild>
          <Button
            variant="ghost"
            size="icon"
            className="lg:hidden"
            aria-label="Open navigation"
          >
            <Menu className="size-5" aria-hidden />
          </Button>
        </SheetTrigger>
        <SheetContent
          side="left"
          className="w-72 gap-0 p-0"
          aria-label="Navigation"
        >
          <div className="flex h-14 shrink-0 items-center border-b border-border/70 px-4 pr-12">
            <ProductMark />
          </div>
          <div className="flex-1 overflow-y-auto px-3 py-4">
            <SidebarNav onNavigate={() => setNavOpen(false)} />
          </div>
          <div className="shrink-0 border-t border-border/70 px-3 py-3">
            <p className="px-2 text-xs leading-5 text-muted-foreground">
              Law enforcement use only
            </p>
          </div>
        </SheetContent>
      </Sheet>

      <Breadcrumbs className="hidden min-w-0 flex-1 sm:block" />

      <div className="ml-auto flex shrink-0 items-center gap-1.5 sm:ml-8">
        <ThemeToggle />
        <UserMenu userEmail={userEmail} />
      </div>
    </header>
  )
}