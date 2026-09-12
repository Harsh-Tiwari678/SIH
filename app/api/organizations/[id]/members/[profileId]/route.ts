import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export const runtime = "nodejs";

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const ORG_ROLES = ["admin", "investigator", "member"];

// PATCH /api/organizations/[id]/members/[profileId]
//   body: { role_in_org }
//
// Change an organization member's role. The caller's identity is never taken
// from the request: change_organization_member_role derives it from
// auth.uid() and requires the caller to be an existing admin of the org. This
// route never touches organization_members directly; the SECURITY DEFINER RPC
// performs the authorization, the last-admin invariant, and the audit entry
// atomically. The target profile_id comes from the route path.
export async function PATCH(
  request: Request,
  ctx: RouteContext<"/api/organizations/[id]/members/[profileId]">,
) {
  const { id: orgId, profileId: targetProfileId } = await ctx.params;

  const supabase = await createClient();

  // 1. authenticate — resolve the session from the request cookies.
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // 2. authorize — the user must have an application profile.
  const { data: profile } = await supabase
    .from("profiles")
    .select("id")
    .eq("id", user.id)
    .maybeSingle();
  if (!profile) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  // 3. validate — org id, target profile uuid, and body shape. The actor and
  //    the admin role are never read from the request; the RPC re-derives
  //    identity from auth.uid().
  if (!UUID_PATTERN.test(orgId)) {
    return NextResponse.json(
      { error: "Invalid organization id" },
      { status: 400 },
    );
  }
  if (!UUID_PATTERN.test(targetProfileId)) {
    return NextResponse.json(
      { error: "profileId must be a valid uuid" },
      { status: 400 },
    );
  }

  let body: { role_in_org?: unknown };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const roleInOrg =
    typeof body.role_in_org === "string" ? body.role_in_org.trim() : "";
  if (!ORG_ROLES.includes(roleInOrg)) {
    return NextResponse.json(
      { error: "role_in_org must be one of admin, investigator, member" },
      { status: 400 },
    );
  }

  // 4 & 5. business operation + audit — both run inside the trusted
  // change_organization_member_role SECURITY DEFINER RPC, atomically, with
  // identity derived from auth.uid() (never from client input). The RPC
  // re-checks the caller's admin role, the role vocabulary, target membership,
  // and the last-admin invariant, and writes the audit entry.
  const { data, error } = await supabase.rpc("change_organization_member_role", {
    p_org_id: orgId,
    p_profile_id: targetProfileId,
    p_new_role: roleInOrg,
  });

  if (error) {
    return NextResponse.json(
      { error: rpcMessage(error.message, "change") },
      { status: rpcStatus(error.message) },
    );
  }

  return NextResponse.json(
    { member: { profile_id: targetProfileId, role_in_org: data } },
    { status: 200 },
  );
}

// DELETE /api/organizations/[id]/members/[profileId]
//
// Remove a member from the organization. The caller's identity is never taken
// from the request: remove_organization_member derives it from auth.uid() and
// requires the caller to be an existing admin of the org. This route never
// touches organization_members directly; the SECURITY DEFINER RPC performs the
// authorization, the last-admin invariant, and the audit entry atomically.
export async function DELETE(
  _request: Request,
  ctx: RouteContext<"/api/organizations/[id]/members/[profileId]">,
) {
  const { id: orgId, profileId: targetProfileId } = await ctx.params;

  const supabase = await createClient();

  // 1. authenticate — resolve the session from the request cookies.
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // 2. authorize — the user must have an application profile.
  const { data: profile } = await supabase
    .from("profiles")
    .select("id")
    .eq("id", user.id)
    .maybeSingle();
  if (!profile) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  // 3. validate — org id and target profile uuid. No request body or query
  //    parameters are read: the actor and the admin role are never
  //    client-supplied.
  if (!UUID_PATTERN.test(orgId)) {
    return NextResponse.json(
      { error: "Invalid organization id" },
      { status: 400 },
    );
  }
  if (!UUID_PATTERN.test(targetProfileId)) {
    return NextResponse.json(
      { error: "profileId must be a valid uuid" },
      { status: 400 },
    );
  }

  // 4 & 5. business operation + audit — both run inside the trusted
  // remove_organization_member SECURITY DEFINER RPC, atomically, with identity
  // derived from auth.uid() (never from client input). The RPC re-checks the
  // caller's admin role, target membership, and the last-admin invariant, and
  // writes the audit entry.
  const { error } = await supabase.rpc("remove_organization_member", {
    p_org_id: orgId,
    p_profile_id: targetProfileId,
  });

  if (error) {
    return NextResponse.json(
      { error: rpcMessage(error.message, "remove") },
      { status: rpcStatus(error.message) },
    );
  }

  return NextResponse.json(
    { ok: true, profile_id: targetProfileId },
    { status: 200 },
  );
}

// RPC exceptions are exact, known codes; the includes-style checks follow the
// existing route convention.
function rpcStatus(message: string): number {
  if (message.includes("not_authenticated")) return 401;
  if (message.includes("not_org_admin")) return 403;
  if (message.includes("organization_not_found")) return 404;
  if (message.includes("member_not_found")) return 404;
  if (message.includes("role_not_allowed")) return 400;
  if (
    message.includes("last_org_admin_cannot_be_demoted") ||
    message.includes("last_org_admin_cannot_be_removed")
  ) {
    return 409;
  }
  return 500;
}

// Action-specific messages depend on whether the operation is a role change
// ("change") or a removal ("remove").
function rpcMessage(message: string, action: "change" | "remove"): string {
  if (message.includes("not_authenticated")) return "Unauthorized";
  if (message.includes("not_org_admin")) {
    return "Only an organization admin can manage members";
  }
  if (message.includes("organization_not_found")) {
    return "Organization not found";
  }
  if (message.includes("member_not_found")) return "Member not found";
  if (message.includes("role_not_allowed")) {
    return "role_in_org must be one of admin, investigator, member";
  }
  if (message.includes("last_org_admin_cannot_be_demoted")) {
    return "The last organization admin cannot be demoted";
  }
  if (message.includes("last_org_admin_cannot_be_removed")) {
    return "The last organization admin cannot be removed";
  }
  return action === "remove"
    ? "Failed to remove member"
    : "Failed to change member role";
}