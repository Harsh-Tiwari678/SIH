export type CaseMemberDetail = {
  profile_id: string
  role_in_case: string
  added_at: string
  profiles?: { id: string; full_name: string } | null
}

export type CaseDetail = {
  id: string
  case_number: string
  title: string
  description: string | null
  status: string
  created_at: string
  updated_at: string
  created_by: string
  closed_at: string | null
  closed_by: string | null
  case_members?: CaseMemberDetail[]
}