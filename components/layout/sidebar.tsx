import { ProductMark } from "@/components/layout/product-mark"
import { SidebarNav } from "@/components/layout/sidebar-nav"

export function AppSidebar() {
  return (
    <div className="flex h-full flex-col">
      <div className="flex h-14 shrink-0 items-center border-b border-border/70 px-4 pr-10">
        <ProductMark />
      </div>
      <div className="flex-1 overflow-y-auto px-3 py-4">
        <SidebarNav />
      </div>
      <div className="shrink-0 border-t border-border/70 px-3 py-3">
        <p className="px-2 text-xs leading-5 text-muted-foreground">
          Law enforcement use only
        </p>
      </div>
    </div>
  )
}