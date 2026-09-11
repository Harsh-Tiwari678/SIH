import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export const runtime = "nodejs";

export async function GET() {
  const supabase = await createClient();

  // 1. authenticate — resolve the session from the request cookies.
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // 2. list — query the cases table through the authenticated session so the
  //    existing `cases_select_member_or_org_admin` RLS policy filters to only
  //    the cases this user is allowed to see. No service-role key is used;
  //    access is enforced by the database, not the application.
  const { data: cases, error } = await supabase
    .from("cases")
    .select("id, case_number, title, description, status, created_at, updated_at")
    .order("created_at", { ascending: false });

  if (error) {
    return NextResponse.json(
      { error: "Failed to load cases" },
      { status: 500 },
    );
  }

  return NextResponse.json({ cases }, { status: 200 });
}

export async function POST(request: Request) {
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
    .select("id, role")
    .eq("id", user.id)
    .maybeSingle();
  if (!profile) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  // 3. validate input — parse and sanity-check the request body.
  let body: {
    case_number?: unknown;
    title?: unknown;
    description?: unknown;
    org_id?: unknown;
  };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const case_number =
    typeof body.case_number === "string" ? body.case_number.trim() : "";
  const title = typeof body.title === "string" ? body.title.trim() : "";
  const description =
    typeof body.description === "string" ? body.description.trim() : null;

  if (!case_number) {
    return NextResponse.json(
      { error: "case_number is required" },
      { status: 400 },
    );
  }
  if (!title) {
    return NextResponse.json({ error: "title is required" }, { status: 400 });
  }
  if (case_number.length > 100) {
    return NextResponse.json(
      { error: "case_number must be 100 characters or fewer" },
      { status: 400 },
    );
  }
  if (title.length > 500) {
    return NextResponse.json(
      { error: "title must be 500 characters or fewer" },
      { status: 400 },
    );
  }

  // 4. resolve the organization the case belongs to. A client-supplied
  // org_id is only a proposal: the create_case RPC validates that the caller
  // is a member of that organization before writing anything. When the caller
  // belongs to exactly one organization, it can be resolved automatically;
  // otherwise the request must say which organization the case is for.
  const org_id = typeof body.org_id === "string" ? body.org_id.trim() : "";
  let resolvedOrgId = org_id;
  if (!resolvedOrgId) {
    const { data: orgs } = await supabase
      .from("organizations")
      .select("id");
    if (!orgs || orgs.length !== 1) {
      return NextResponse.json(
        {
          error:
            orgs && orgs.length > 1
              ? "Multiple organizations: org_id is required"
              : "Must belong to an organization to create a case",
        },
        { status: orgs && orgs.length > 1 ? 400 : 403 },
      );
    }
    resolvedOrgId = orgs[0].id;
  }

  // 5 & 6. business operation + audit — both run inside the trusted
  // create_case SECURITY DEFINER RPC, atomically, with identity derived from
  // auth.uid() (never from client input). created_by / profile_id / role are
  // not reachable by the client on this path. The org membership check lives
  // in the RPC, so a forged org_id cannot create a case in another org.
  const { data, error } = await supabase.rpc("create_case", {
    p_org_id: resolvedOrgId,
    p_case_number: case_number,
    p_title: title,
    p_description: description,
  });

  if (error) {
    return NextResponse.json(
      { error: error.message },
      { status: rpcStatus(error.message) },
    );
  }

  return NextResponse.json({ case: data }, { status: 201 });
}

function rpcStatus(message: string): number {
  if (message.includes("not_authenticated")) return 401;
  if (message.includes("profile_not_found") || message.includes("not_org_member")) {
    return 403;
  }
  if (
    message.includes("case_number_required") ||
    message.includes("title_required") ||
    message.includes("org_required") ||
    message.includes("org_not_found")
  ) {
    return 400;
  }
  if (message.includes("duplicate key") || message.toLowerCase().includes("unique")) {
    return 409;
  }
  return 500;
}
