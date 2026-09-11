import { cn } from "@/lib/utils"

type DashboardSummary = {
  total: number
  byStatus: Record<string, number>
}

function Stat({
  label,
  value,
  accent = false,
  last = false,
}: {
  label: string
  value: number
  accent?: boolean
  last?: boolean
}) {
  return (
    <div
      className={cn(
        "flex min-w-0 flex-col",
        !last && "border-r border-border/70 pr-4 sm:pr-6",
      )}
    >
      <dt
        className={cn(
          "text-lg font-semibold tabular-nums tracking-tight",
          accent && "text-primary",
        )}
      >
        {value}
      </dt>
      <dd className="mt-0.5 truncate text-sm text-muted-foreground">
        {label}
      </dd>
    </div>
  )
}

function PlaceholderStat({
  label,
  last = false,
}: {
  label: string
  last?: boolean
}) {
  return (
    <div
      className={cn(
        "flex min-w-0 flex-col",
        !last && "border-r border-border/70 pr-4 sm:pr-6",
      )}
    >
      <dt className="text-lg font-semibold tabular-nums tracking-tight text-muted-foreground">
        —
      </dt>
      <dd className="mt-0.5 truncate text-sm text-muted-foreground">
        {label}
      </dd>
    </div>
  )
}

export function SummaryStrip({
  summary,
  className,
}: {
  summary: DashboardSummary | null
  className?: string
}) {
  const placeholders = summary === null
  return (
    <div className={cn("overflow-x-auto", className)}>
      <div className="flex min-w-max items-start justify-between gap-6 rounded-lg border border-border/80 bg-background px-4 py-3 sm:px-6">
        {placeholders ? (
          <>
            <PlaceholderStat label="Active cases" />
            <PlaceholderStat label="Draft" />
            <PlaceholderStat label="Closed" />
            <PlaceholderStat label="Total cases" last />
          </>
        ) : (
          <>
            <Stat
              label="Active cases"
              value={summary.byStatus.active ?? 0}
              accent
            />
            <Stat label="Draft" value={summary.byStatus.draft ?? 0} />
            <Stat label="Closed" value={summary.byStatus.closed ?? 0} />
            <Stat label="Total cases" value={summary.total} last />
          </>
        )}
      </div>
    </div>
  )
}