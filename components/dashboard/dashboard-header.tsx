import { NewCaseForm } from "@/components/cases/new-case-form"

export function DashboardHeader({
  caseCount,
  onCreated,
}: {
  caseCount: number | null
  onCreated: () => void
}) {
  return (
    <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-foreground">
          Dashboard
        </h1>
        <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
          Operational overview of your cases and evidence.
          {caseCount === 0
            ? " Start by creating a case to begin recording evidence."
            : null}
        </p>
      </div>
      <div className="shrink-0">
        <NewCaseForm onCreated={onCreated} />
      </div>
    </div>
  )
}