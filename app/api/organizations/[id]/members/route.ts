import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export const runtime = "nodejs";

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const ORG_ROLES = ["admin", "investigator", "member"];

// GET /api/organizations/[id]/members
//
// Member roster for an organization. Authorization is enforced entirely inside
// the SECURITY DEFINER RPC list_organization_members: it re-derives the actor
// from the session (auth.uid(), never a client-supplied id) and requires the
// caller to be a member of the target org. An org the caller cannot see is
// reported identically to a nonexistent one (404), so existence is never
// leaked. No service-role key is used; profile names resolve only for rows this
// caller is already entitled to see.
export async function GET(
  _request: Request,
  ctx: RouteContext<"/api/organizations/[id]/members">,
) {
  const { id: orgId } = await ctx.params;

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

  // 3. validate — shape only. Membership is re-checked inside the RPC.
  if (!UUID_PATTERN.test(orgId)) {
    return NextResponse.json(
      { error: "Invalid organization id" },
      { status: 400 },
    );
  }

  // 4. the roster — org membership + visibility are re-checked inside the RPC.
  const { data, error } = await supabase.rpc("list_organization_members", {
    p_org_id: orgId,
  });

  if (error) {
    return NextResponse.json(
      { error: listRpcMessage(error.message) },
      { status: listRpcStatus(error.message) },
    );
  }

  return NextResponse.json({ members: data }, { status: 200 });
}

// POST /api/organizations/[id]/members
//
// Add a member to the organization. The caller's identity is never taken from
// the body: add_organization_member derives it from auth.uid() and requires
// the caller to be an existing admin of the org. This route never touches
// organization_members directly; the SECURITY DEFINER RPC performs the
// authorization, the last-admin/default-org invariants, and the audit entry
// atomically. profile_id and role_in_org are the only client-supplied inputs.
export async function POST(
  request: Request,
  ctx: RouteContext<"/api/organizations/[id]/members">,
) {
  const { id: orgId } = await ctx.params;

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

  // 3. validate — org id, body shape, target profile uuid, and role. The actor
  //    and the admin role are never read from the request; the RPC re-derives
  //    identity from auth.uid().
  if (!UUID_PATTERN.test(orgId)) {
    return NextResponse.json(
      { error: "Invalid organization id" },
      { status: 400 },
    );
  }

  let body: { profile_id?: unknown; role_in_org?: unknown };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const profileId =
    typeof body.profile_id === "string" ? body.profile_id.trim() : "";
  const roleInOrg =
    typeof body.role_in_org === "string" ? body.role_in_org.trim() : "";

  if (!profileId || !UUID_PATTERN.test(profileId)) {
    return NextResponse.json(
      { error: "profile_id must be a valid uuid" },
      { status: 400 },
    );
  }
  if (!ORG_ROLES.includes(roleInOrg)) {
    return NextResponse.json(
      { error: "role_in_org must be one of admin, investigator, member" },
      { status: 400 },
    );
  }

  // 4 & 5. business operation + audit — both run inside the trusted
  // add_organization_member SECURITY DEFINER RPC, atomically, with identity
  // derived from auth.uid() (never from client input). The RPC re-checks the
  // caller's admin role, the target profile, the role vocabulary, duplicates,
  // and writes the audit entry.
  const { data, error } = await supabase.rpc("add_organization_member", {
    p_org_id: orgId,
    p_profile_id: profileId,
    p_role: roleInOrg,
  });

  if (error) {
    return NextResponse.json(
      { error: rpcMessage(error.message) },
      { status: rpcStatus(error.message) },
    );
  }

  return NextResponse.json(
    {
      member: {
        organization_member_id: data,
        profile_id: profileId,
        role_in_org: roleInOrg,
      },
    },
    { status: 201 },
  );
}

// RPC exceptions are exact, known codes; the includes-style checks follow the
// existing route convention.

// GET roster — list_organization_members raises these codes.
function listRpcStatus(message: string): number {
  if (message.includes("not_authenticated")) return 401;
  if (message.includes("profile_not_found")) return 403;
  if (message.includes("org_not_found")) return 404;
  return 500;
}

function listRpcMessage(message: string): string {
  if (message.includes("not_authenticated")) return "Unauthorized";
  if (message.includes("profile_not_found")) return "Forbidden";
  if (message.includes("org_not_found")) return "Organization not found";
  return "Failed to load members";
}

// POST add — add_organization_member raises these codes.
function rpcStatus(message: string): number {
  if (message.includes("not_authenticated")) return 401;
  if (message.includes("profile_not_found")) return 404;
  if (message.includes("not_org_admin")) return 403;
  if (message.includes("organization_not_found")) return 404;
  if (message.includes("role_not_allowed")) return 400;
  if (message.includes("already_org_member")) return 409;
  return 500;
}

function rpcMessage(message: string): string {
  if (message.includes("not_authenticated")) return "Unauthorized";
  if (message.includes("profile_not_found")) return "Profile not found";
  if (message.includes("not_org_admin")) {
    return "Only an organization admin can add members";
  }
  if (message.includes("organization_not_found")) {
    return "Organization not found";
  }
  if (message.includes("role_not_allowed")) {
    return "role_in_org must be one of admin, investigator, member";
  }
  if (message.includes("already_org_member")) {
    return "User is already a member of this organization";
  }
  return "Failed to add member";
}