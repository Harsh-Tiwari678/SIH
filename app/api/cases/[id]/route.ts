import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export const runtime = "nodejs";

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
  //    inaccessible case exists. No service-role key is used.
  const { data: caseRow, error } = await supabase
    .from("cases")
    .select("id, case_number, title, description, status, created_at, updated_at")
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

  return NextResponse.json({ case: caseRow }, { status: 200 });
}
