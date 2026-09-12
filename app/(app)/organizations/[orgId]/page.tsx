import { OrganizationWorkspace } from "@/components/organizations/organization-workspace"

export default async function OrganizationPage({
  params,
  searchParams,
}: {
  params: Promise<{ orgId: string }>
  searchParams: Promise<{ tab?: string }>
}) {
  const { orgId } = await params
  const { tab } = await searchParams
  return <OrganizationWorkspace orgId={orgId} initialTab={tab} />
}
