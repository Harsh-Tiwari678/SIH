"use client"

import { CaseStatusBadge } from "@/components/cases/status-badge"
import { EditCaseDialog } from "@/components/cases/edit-case-dialog"
import { CaseStatusMenu } from "@/components/cases/case-status-menu"
import type { CaseDetail, CaseMemberDetail } from "@/components/cases/case-detail"
import { formatDate } from "@/lib/format"

function memberDisplayName(
  member: CaseMemberDetail | undefined,
): string | null {
  return member?.profiles?.full_name ?? null
}

function shortId(id: string): string {
  return id.slice(0, 8)
}

export function CaseHeader({
  caseDetail,
  myRole,
  onSaved,
}: {
  caseDetail: CaseDetail
  myRole: string | null
  onSaved: () => void
}) {
  const isLead = myRole === "lead"

  const creator = caseDetail.case_members?.find(
    (m) => m.profile_id === caseDetail.created_by,
  )
  const creatorName = memberDisplayName(creator) ?? shortId(caseDetail.created_by)

  const closedBy = caseDetail.case_members?.find(
    (m) => m.profile_id === caseDetail.closed_by,
  )
  const closedByName = memberDisplayName(closedBy) ?? shortId(caseDetail.closed_by ?? "")

  return (
    <header>
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0">
          <p className="font-mono text-[13px] text-muted-foreground">
            {caseDetail.case_number}
          </p>
          <div className="mt-1 flex flex-wrap items-center gap-3">
            <h1 className="text-2xl font-semibold tracking-tight text-foreground">
              {caseDetail.title}
            </h1>
            <CaseStatusBadge status={caseDetail.status} />
          </div>
          {caseDetail.description ? (
            <p className="mt-2 max-w-3xl text-sm text-muted-foreground">
              {caseDetail.description}
            </p>
          ) : null}
          <p className="mt-2 text-xs text-muted-foreground">
            <span>Created {formatDate(caseDetail.created_at)} by {creatorName}</span>
            <span aria-hidden> · </span>
            <span>Updated {formatDate(caseDetail.updated_at)}</span>
            {caseDetail.closed_at ? (
              <>
                <span aria-hidden> · </span>
                <span>
                  Closed {formatDate(caseDetail.closed_at)} by {closedByName}
                </span>
              </>
            ) : null}
          </p>
        </div>

        {isLead ? (
          <div className="flex shrink-0 flex-wrap items-center gap-2">
            <EditCaseDialog caseDetail={caseDetail} onSaved={onSaved} />
            <CaseStatusMenu caseDetail={caseDetail} onSaved={onSaved} />
          </div>
        ) : null}
      </div>
    </header>
  )
}