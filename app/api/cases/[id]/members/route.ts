import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export const runtime = "nodejs";

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const ASSIGNABLE_ROLES = ["member", "investigator", "viewer"];

export async function POST(
  request: Request,
  ctx: RouteContext<"/api/cases/[id]/members">,
) {
  const { id: caseId } = await ctx.params;

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

  // 3. validate — case id, body shape, target profile uuid, and role.
  if (!UUID_PATTERN.test(caseId)) {
    return NextResponse.json(
      { error: "Invalid case id" },
      { status: 400 },
    );
  }

  let body: { profile_id?: unknown; role_in_case?: unknown };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const profileId =
    typeof body.profile_id === "string" ? body.profile_id.trim() : "";
  const roleInCase =
    typeof body.role_in_case === "string" ? body.role_in_case.trim() : "";

  if (!profileId || !UUID_PATTERN.test(profileId)) {
    return NextResponse.json(
      { error: "profile_id must be a valid uuid" },
      { status: 400 },
    );
  }
  if (!ASSIGNABLE_ROLES.includes(roleInCase)) {
    return NextResponse.json(
      { error: "role_in_case must be one of member, investigator, viewer" },
      { status: 400 },
    );
  }

  // 4 & 5. business operation + audit — both run inside the trusted
  // add_case_member SECURITY DEFINER RPC, atomically, with identity derived
  // from auth.uid() (never from client input). added_by / actor_id are not
  // reachable by the client on this path, and the RPC re-checks visibility,
  // lead role, case status, target profile, self-add, and duplicates.
  const { data, error } = await supabase.rpc("add_case_member", {
    p_case_id: caseId,
    p_profile_id: profileId,
    p_role_in_case: roleInCase,
  });

  if (error) {
    return NextResponse.json(
      { error: rpcMessage(error.message) },
      { status: rpcStatus(error.message) },
    );
  }

  return NextResponse.json({ member: data }, { status: 201 });
}

// RPC exceptions are exact, known codes; the includes-style checks follow the
// existing route convention. Order matters: target_profile_not_found contains
// profile_not_found as a substring, so it must be tested first.
function rpcStatus(message: string): number {
  if (message.includes("target_profile_not_found")) return 400;
  if (message.includes("profile_not_found")) return 403;
  if (message.includes("not_authenticated")) return 401;
  if (message.includes("case_not_found")) return 404;
  if (message.includes("not_lead")) return 403;
  if (message.includes("case_not_open")) return 409;
  if (
    message.includes("self_add_not_allowed") ||
    message.includes("role_not_allowed")
  ) {
    return 400;
  }
  if (message.includes("duplicate key") || message.toLowerCase().includes("unique")) {
    return 409;
  }
  return 500;
}

function rpcMessage(message: string): string {
  if (message.includes("target_profile_not_found")) {
    return "Target profile not found";
  }
  if (message.includes("profile_not_found")) return "Forbidden";
  if (message.includes("not_authenticated")) return "Unauthorized";
  if (message.includes("case_not_found")) return "Case not found";
  if (message.includes("not_lead")) return "Only the case lead can add members";
  if (message.includes("case_not_open")) {
    return "Members can only be added to draft or active cases";
  }
  if (message.includes("self_add_not_allowed")) {
    return "You cannot add yourself to a case";
  }
  if (message.includes("role_not_allowed")) {
    return "role_in_case must be one of member, investigator, viewer";
  }
  if (message.includes("duplicate key") || message.toLowerCase().includes("unique")) {
    return "User is already a member of this case";
  }
  return "Failed to add member";
}
