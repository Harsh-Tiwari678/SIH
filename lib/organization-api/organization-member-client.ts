// Client-side access to the organization member API. These helpers exist so
// the workspace UI stays free of raw server strings: every failure is mapped
// to a concise, user-facing message before it reaches a component.
//
// Authorization is never decided here. The SECURITY DEFINER RPCs behind the
// API are authoritative; a non-admin receives a 403 and the caller renders
// it. No actor identity is ever sent to the server in these requests — the
// routes derive it from the session cookies.
export const ORG_ROLES = ["admin", "investigator", "member"] as const
export type OrgMemberRole = (typeof ORG_ROLES)[number]

export const ORG_ROLE_LABELS: Record<OrgMemberRole, string> = {
  admin: "Admin",
  investigator: "Investigator",
  member: "Member",
}

export type LookupCandidate = {
  id: string
  full_name: string | null
  badge_number: string | null
}

export type MemberActionResult = { ok: true } | { ok: false; message: string }

export type LookupResult =
  | { ok: true; profiles: LookupCandidate[] }
  | { ok: false; message: string }

export async function fetchMemberLookup(
  orgId: string,
  query: string,
  signal?: AbortSignal,
): Promise<LookupResult> {
  const trimmed = query.trim()
  const params = new URLSearchParams()
  if (trimmed) params.set("q", trimmed)
  const qs = params.toString()
  const url = `/api/organizations/${orgId}/members/lookup${qs ? `?${qs}` : ""}`

  let res: Response
  try {
    res = await fetch(url, { cache: "no-store", signal })
  } catch {
    return { ok: false, message: "Profile search failed. Try again." }
  }

  if (res.status === 403) {
    return {
      ok: false,
      message: "You don't have permission to manage organization members.",
    }
  }
  if (res.status === 404) {
    return { ok: false, message: "This organization could not be found." }
  }
  if (!res.ok) {
    return { ok: false, message: "Profile search failed. Try again." }
  }

  const data = (await res.json().catch(() => ({}))) as {
    profiles?: LookupCandidate[]
  }
  return {
    ok: true,
    profiles: Array.isArray(data.profiles) ? data.profiles : [],
  }
}

export async function addOrganizationMember(
  orgId: string,
  input: { profile_id: string; role_in_org: OrgMemberRole },
): Promise<MemberActionResult> {
  let res: Response
  try {
    res = await fetch(`/api/organizations/${orgId}/members`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(input),
      cache: "no-store",
    })
  } catch {
    return { ok: false, message: "Something went wrong. Please try again." }
  }

  if (res.ok) return { ok: true }
  const body = (await res.json().catch(() => ({}))) as { error?: string }
  return {
    ok: false,
    message: mapActionError(res.status, body.error ?? "", "add"),
  }
}

export async function changeMemberRole(
  orgId: string,
  profileId: string,
  role_in_org: OrgMemberRole,
): Promise<MemberActionResult> {
  let res: Response
  try {
    res = await fetch(`/api/organizations/${orgId}/members/${profileId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role_in_org }),
      cache: "no-store",
    })
  } catch {
    return { ok: false, message: "Something went wrong. Please try again." }
  }

  if (res.ok) return { ok: true }
  const body = (await res.json().catch(() => ({}))) as { error?: string }
  return {
    ok: false,
    message: mapActionError(res.status, body.error ?? "", "change"),
  }
}

export async function removeOrganizationMember(
  orgId: string,
  profileId: string,
): Promise<MemberActionResult> {
  let res: Response
  try {
    res = await fetch(`/api/organizations/${orgId}/members/${profileId}`, {
      method: "DELETE",
      cache: "no-store",
    })
  } catch {
    return { ok: false, message: "Something went wrong. Please try again." }
  }

  if (res.ok) return { ok: true }
  const body = (await res.json().catch(() => ({}))) as { error?: string }
  return {
    ok: false,
    message: mapActionError(res.status, body.error ?? "", "remove"),
  }
}

// Known HTTP statuses become concise user-facing messages. Internal RPC codes
// and server error strings are never echoed to the UI.
function mapActionError(
  status: number,
  error: string,
  action: "add" | "change" | "remove",
): string {
  if (status === 401) return "Your session has expired. Sign in again."
  if (status === 403) {
    return "You don't have permission to manage organization members."
  }
  if (status === 404) return "That member or organization could not be found."
  if (status === 400) return "Please check the entered details and try again."
  if (status === 409) {
    if (action === "add" && /already/i.test(error)) {
      return "That profile is already a member of this organization."
    }
    if ((action === "change" || action === "remove") && /last/i.test(error)) {
      return "The last organization admin cannot be removed or demoted."
    }
    return "This operation conflicts with the current member state."
  }
  return "Something went wrong. Please try again."
}