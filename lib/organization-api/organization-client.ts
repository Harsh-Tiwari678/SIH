// Client-side access to the organization create API. The helper exists so the
// list UI stays free of raw server strings: every failure is mapped to a
// concise, user-facing message. Authorization is never decided here — the
// create_organization SECURITY DEFINER RPC behind the API is authoritative.
// No actor identity is ever sent to the server in this request; the route
// derives it from the session cookies.

export type CreateOrganizationResult =
  | { ok: true; organization: { id: string } }
  | { ok: false; message: string }

export async function createOrganization(input: {
  name: string
  slug: string
}): Promise<CreateOrganizationResult> {
  let res: Response
  try {
    res = await fetch("/api/organizations", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: input.name, slug: input.slug }),
      cache: "no-store",
    })
  } catch {
    return { ok: false, message: "Something went wrong. Please try again." }
  }

  if (res.ok) {
    const body = (await res.json().catch(() => ({}))) as {
      organization?: { id?: unknown }
    }
    const id =
      typeof body.organization?.id === "string" ? body.organization.id : ""
    if (!id) {
      return { ok: false, message: "Something went wrong. Please try again." }
    }
    return { ok: true, organization: { id } }
  }

  const body = (await res.json().catch(() => ({}))) as { error?: string }
  const error = body.error ?? ""
  if (res.status === 401) return { ok: false, message: "Your session has expired. Sign in again." }
  if (res.status === 403) {
    return { ok: false, message: "Your account is not allowed to create organizations." }
  }
  if (res.status === 400) return { ok: false, message: "Please check the entered details and try again." }
  if (res.status === 409 && /slug/i.test(error)) {
    return { ok: false, message: "That slug is already in use. Try another one." }
  }
  return { ok: false, message: "Something went wrong. Please try again." }
}