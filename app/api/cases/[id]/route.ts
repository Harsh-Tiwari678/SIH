import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export const runtime = "nodejs";

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const CASE_STATUSES = ["draft", "active", "closed", "archived"];

type CaseMember = {
  profile_id: string;
  role_in_case: string;
  added_at: string;
  profiles?: { id: string; full_name: string } | null;
};

type CaseRow = {
  id: string;
  case_number: string;
  title: string;
  description: string | null;
  status: string;
  created_at: string;
  updated_at: string;
  created_by: string;
  closed_at: string | null;
  closed_by: string | null;
  case_members?: CaseMember[];
};

export async function GET(
  _request: Request,
  ctx: RouteContext<"/api/cases/[id]">,
) {
  const { id } = await ctx.params;

  const supabase = await createClient();

  // 1. authenticate — resolve the session from the request cookies.
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // 2. fetch — query a single case through the authenticated session so the
  //    existing `cases_select_creator_or_member` RLS policy filters to only
  //    cases this user may see. When RLS hides the row, `.maybeSingle()`
  //    yields no data, which we deliberately report as 404 — the same response
  //    as a case that does not exist, so we never reveal whether an
//    inaccessible case exists. The embedded `case_members` relation (with
    //    each member's profile full name) is likewise constrained by RLS:
    //    `case_members_select_member_or_self` and
    //    `profiles_select_self_or_shared_case` — so only members of this same
    //    case resolve to named profiles. No service-role key is used. The
    //    `profiles!case_members_profile_id_fkey` hint disambiguates the embed:
    //    case_members has two FKs to profiles (profile_id and added_by), and
    //    an unqualified embed makes PostgREST fail the query.
  const { data: caseRow, error } = await supabase
    .from("cases")
    .select(
      "id, case_number, title, description, status, created_at, updated_at, created_by, closed_at, closed_by, case_members(profile_id, role_in_case, added_at, profiles!case_members_profile_id_fkey(id, full_name))",
    )
    .eq("id", id)
    .maybeSingle();

  if (error) {
    return NextResponse.json(
      { error: "Failed to load case" },
      { status: 500 },
    );
  }

  if (!caseRow) {
    return NextResponse.json(
      { error: "Case not found" },
      { status: 404 },
    );
  }

  // 3. caller's own role within the case, derived from the RLS-constrained
  //    roster (never from client input). Used only so the UI can decide which
  //    controls to render; authorization is always enforced server-side by
  //    the update_case RPC / RLS.
  const row = caseRow as unknown as CaseRow;
  const myRole =
    row.case_members?.find((m) => m.profile_id === user.id)?.role_in_case ??
    null;

  return NextResponse.json({ case: caseRow, my_role: myRole }, { status: 200 });
}

export async function PATCH(
  request: Request,
  ctx: RouteContext<"/api/cases/[id]">,
) {
  const { id } = await ctx.params;

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

  // 3. validate — case id and every client-supplied value. Authorization data
  //    (actor, lead role, closed_by) is never taken from the request; the RPC
  //    re-derives identity from auth.uid().
  if (!UUID_PATTERN.test(id)) {
    return NextResponse.json({ error: "Invalid case id" }, { status: 400 });
  }

  let body: { title?: unknown; description?: unknown; status?: unknown };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const hasTitle = "title" in body;
  const hasDescription = "description" in body;
  const hasStatus = "status" in body;
  if (!hasTitle && !hasDescription && !hasStatus) {
    return NextResponse.json(
      { error: "At least one of title, description or status is required" },
      { status: 400 },
    );
  }

  const title = hasTitle ? body.title : undefined;
  const description = hasDescription ? body.description : undefined;
  const status = hasStatus ? body.status : undefined;

  if (hasTitle && typeof title !== "string") {
    return NextResponse.json({ error: "title must be a string" }, { status: 400 });
  }
  if (hasDescription && description !== null && typeof description !== "string") {
    return NextResponse.json(
      { error: "description must be a string or null" },
      { status: 400 },
    );
  }
  if (hasStatus && typeof status !== "string") {
    return NextResponse.json({ error: "status must be a string" }, { status: 400 });
  }

  const trimmedTitle = hasTitle ? (title as string).trim() : undefined;
  if (trimmedTitle !== undefined && !trimmedTitle) {
    return NextResponse.json({ error: "title is required" }, { status: 400 });
  }
  if (trimmedTitle !== undefined && trimmedTitle.length > 500) {
    return NextResponse.json(
      { error: "title must be 500 characters or fewer" },
      { status: 400 },
    );
  }
  const trimmedDescription =
    hasDescription && description !== null
      ? (description as string).trim()
      : undefined;
  if (
    trimmedDescription !== undefined &&
    trimmedDescription.length > 5000
  ) {
    return NextResponse.json(
      { error: "description must be 5000 characters or fewer" },
      { status: 400 },
    );
  }
  if (status !== undefined && !CASE_STATUSES.includes(status as string)) {
    return NextResponse.json(
      { error: "status must be one of draft, active, closed, archived" },
      { status: 400 },
    );
  }

  // 4 & 5. business operation + audit — both run inside the trusted
  //    update_case SECURITY DEFINER RPC, atomically, with identity derived
  //    from auth.uid() (never from client input). Lead membership, the status
  //    vocabulary, the closed_at/closed_by invariant, and the audit entry are
  //    all enforced in the RPC. case_number is immutable here by design.
  const descriptionClears =
    hasDescription &&
    (description === null ||
      (typeof description === "string" && description.trim() === ""));
  const { data, error } = await supabase.rpc("update_case", {
    p_case_id: id,
    p_title: trimmedTitle ?? null,
    p_description: hasDescription
      ? (descriptionClears ? null : (description as string).trim())
      : null,
    p_set_description_null: descriptionClears,
    p_status: hasStatus ? (status as string) : null,
  });

  if (error) {
    // Log the real database/RPC failure for debugging; never echo its raw text
    // to the client. rpcStatus()/rpcMessage() translate known, exact error
    // codes into safe HTTP responses.
    console.error("[api/cases/[id]] update_case RPC failed", {
      code: error.code,
      message: error.message,
      details: error.details,
    });
    return NextResponse.json(
      { error: rpcMessage(error.message) },
      { status: rpcStatus(error.message) },
    );
  }

  return NextResponse.json({ case: data }, { status: 200 });
}

// RPC exceptions are exact, known codes; the includes-style checks follow the
// existing route convention.
function rpcStatus(message: string): number {
  if (message.includes("not_authenticated")) return 401;
  if (message.includes("profile_not_found")) return 403;
  if (message.includes("case_not_found")) return 404;
  if (message.includes("not_lead")) return 403;
  if (message.includes("transition_not_allowed")) return 409;
  if (
    message.includes("status_not_allowed") ||
    message.includes("title_required") ||
    message.includes("title_too_long") ||
    message.includes("description_too_long")
  ) {
    return 400;
  }
  return 500;
}

function rpcMessage(message: string): string {
  if (message.includes("not_authenticated")) return "Unauthorized";
  if (message.includes("profile_not_found")) return "Forbidden";
  if (message.includes("case_not_found")) return "Case not found";
  if (message.includes("not_lead")) {
    return "Only the case lead can edit this case";
  }
  if (message.includes("status_not_allowed")) {
    return "status must be one of draft, active, closed, archived";
  }
  if (message.includes("transition_not_allowed")) {
    return "That case status transition is not allowed";
  }
  if (message.includes("title_required")) return "title is required";
  if (message.includes("title_too_long")) {
    return "title must be 500 characters or fewer";
  }
  if (message.includes("description_too_long")) {
    return "description must be 5000 characters or fewer";
  }
  return "Failed to update case";
}