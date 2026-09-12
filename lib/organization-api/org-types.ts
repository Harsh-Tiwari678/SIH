// Shared organization types, used by the workspace UI and the member
// management components. The shape mirrors the list_organization_members RPC.
export type OrgMember = {
  id: string
  profile_id: string
  full_name: string | null
  badge_number: string | null
  role_in_org: string
  added_by_name: string | null
  added_by: string | null
  added_at: string
}