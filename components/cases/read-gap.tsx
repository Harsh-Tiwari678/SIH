import type { ReactNode } from "react"
import { FileText, Users } from "lucide-react"

function ReadGapPanel({
  icon,
  title,
  children,
}: {
  icon: ReactNode
  title: string
  children: ReactNode
}) {
  return (
    <div className="rounded-lg border border-border/80 bg-background px-6 py-10 text-center">
      <div className="mx-auto flex size-9 items-center justify-center rounded-full border border-border/70 bg-muted/50 text-muted-foreground">
        {icon}
      </div>
      <h4 className="mt-4 text-sm font-semibold text-foreground">{title}</h4>
      <p className="mx-auto mt-1 max-w-md text-sm text-muted-foreground">
        {children}
      </p>
    </div>
  )
}

export function EvidenceUnavailable() {
  return (
    <ReadGapPanel
      title="Evidence not available yet"
      icon={<FileText className="size-4" aria-hidden />}
    >
      There is no read API for this case&apos;s evidence in this phase, so no
      evidence can be listed or counted here. Uploads and version history are
      separate workflows.
    </ReadGapPanel>
  )
}

export function MembersNote() {
  return (
    <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
      <Users className="size-3.5 shrink-0" aria-hidden />
      Adding and removing members is not part of this surface yet.
    </p>
  )
}