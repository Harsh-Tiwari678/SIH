import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export const runtime = "nodejs";

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const QUERY_MAX = 200;

// GET /api/organizations/[id]/members/lookup?q=...
//
// Candidate search for the "add member" flow: profiles that are NOT already
// members of the target organization, searchable by full_name or badge_number
// (case-insensitive substring). Authorization is enforced entirely inside the
// SECURITY DEFINER RPC lookup_profiles_for_organization: it re-derives the
// actor from the session and requires the caller to be a member of the target
// org. An org the caller cannot see is reported identically to a nonexistent
// one (404). The RPC returns only id/full_name/badge_number (no auth internals,
// no role data) and caps results at 10; this route performs no broader profile
// query of its own.
export async function GET(
  request: NextRequest,
  ctx: RouteContext<"/api/organizations/[id]/members/lookup">,
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

  // 3. validate — the org id and the optional search term.
  if (!UUID_PATTERN.test(orgId)) {
    return NextResponse.json(
      { error: "Invalid organization id" },
      { status: 400 },
    );
  }

  const query = request.nextUrl.searchParams.get("q") ?? "";
  const trimmed = query.trim();
  if (trimmed.length > QUERY_MAX) {
    return NextResponse.json(
      { error: `q must be ${QUERY_MAX} characters or fewer` },
      { status: 400 },
    );
  }

  // 4. candidates — org membership + visibility are re-checked inside the RPC.
  //    An absent/blank query means "no filter": the RPC treats NULL p_query as
  //    a broad candidate list within the 10-result cap.
  const { data, error } = await supabase.rpc(
    "lookup_profiles_for_organization",
    {
      p_org_id: orgId,
      p_query: trimmed === "" ? null : trimmed,
    },
  );

  if (error) {
    return NextResponse.json(
      { error: rpcMessage(error.message) },
      { status: rpcStatus(error.message) },
    );
  }

  return NextResponse.json({ profiles: data }, { status: 200 });
}

// RPC exceptions are exact, known codes; the includes-style checks follow the
// existing route convention.
function rpcStatus(message: string): number {
  if (message.includes("not_authenticated")) return 401;
  if (message.includes("profile_not_found")) return 403;
  if (message.includes("org_not_found")) return 404;
  return 500;
}

function rpcMessage(message: string): string {
  if (message.includes("not_authenticated")) return "Unauthorized";
  if (message.includes("profile_not_found")) return "Forbidden";
  if (message.includes("org_not_found")) return "Organization not found";
  return "Failed to search profiles";
}