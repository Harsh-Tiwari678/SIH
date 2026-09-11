import { CaseWorkspace } from "@/components/cases/case-workspace";

export default async function CasePage({
  params,
  searchParams,
}: {
  params: Promise<{ caseId: string }>;
  searchParams: Promise<{ tab?: string; evidence?: string }>;
}) {
  const { caseId } = await params;
  const sp = await searchParams;
  const tab = sp.tab ?? "overview";
  const evidenceId = sp.evidence ?? undefined;
  return <CaseWorkspace caseId={caseId} initialTab={tab} initialEvidenceId={evidenceId} />;
}