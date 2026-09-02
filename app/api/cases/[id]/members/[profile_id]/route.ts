import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export const runtime = "nodejs";

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const ASSIGNABLE_ROLES = ["member", "investigator", "viewer"];

export async function PATCH(
  request: Request,
  ctx: RouteContext<"/api/cases/[id]/members/[profile_id]">,
) {
  const { id: caseId, profile_id: targetProfileId } = await ctx.params;

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

  // 3. validate — case id, target profile uuid, and body shape. The actor, the
  //    case role, and the case ownership are never taken from the body.
  if (!UUID_PATTERN.test(caseId)) {
    return NextResponse.json(
      { error: "Invalid case id" },
      { status: 400 },
    );
  }
  if (!UUID_PATTERN.test(targetProfileId)) {
    return NextResponse.json(
      { error: "profile_id must be a valid uuid" },
      { status: 400 },
    );
  }

  let body: { role_in_case?: unknown };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const roleInCase =
    typeof body.role_in_case === "string" ? body.role_in_case.trim() : "";
  if (!ASSIGNABLE_ROLES.includes(roleInCase)) {
    return NextResponse.json(
      { error: "role_in_case must be one of member, investigator, viewer" },
      { status: 400 },
    );
  }

  // 4 & 5. business operation + audit — both run inside the trusted
  // change_case_member_role SECURITY DEFINER RPC, atomically, with identity
  // derived from auth.uid() (never from client input). actor_id is not
  // reachable by the client on this path, and the RPC re-checks visibility,
  // lead role, case status, target membership, lead-target protection, and
  // the role whitelist.
  const { data, error } = await supabase.rpc("change_case_member_role", {
    p_case_id: caseId,
    p_profile_id: targetProfileId,
    p_role_in_case: roleInCase,
  });

  if (error) {
    return NextResponse.json(
      { error: rpcMessage(error.message) },
      { status: rpcStatus(error.message) },
    );
  }

  return NextResponse.json({ member: data }, { status: 200 });
}

// RPC exceptions are exact, known codes; the includes-style checks follow the
// existing route convention.
function rpcStatus(message: string): number {
  if (message.includes("not_authenticated")) return 401;
  if (message.includes("profile_not_found")) return 403;
  if (message.includes("case_not_found")) return 404;
  if (message.includes("not_lead")) return 403;
  if (message.includes("case_not_open")) return 409;
  if (message.includes("target_not_in_case")) return 404;
  if (message.includes("target_is_lead")) return 403;
  if (message.includes("role_not_allowed")) return 400;
  return 500;
}

function rpcMessage(message: string): string {
  if (message.includes("not_authenticated")) return "Unauthorized";
  if (message.includes("profile_not_found")) return "Forbidden";
  if (message.includes("case_not_found")) return "Case not found";
  if (message.includes("not_lead")) {
    return "Only the case lead can change member roles";
  }
  if (message.includes("case_not_open")) {
    return "Member roles can only be changed on draft or active cases";
  }
  if (message.includes("target_not_in_case")) return "Member not found";
  if (message.includes("target_is_lead")) {
    return "The case lead's role cannot be changed";
  }
  if (message.includes("role_not_allowed")) {
    return "role_in_case must be one of member, investigator, viewer";
  }
  return "Failed to change member role";
}
