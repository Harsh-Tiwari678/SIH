import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export const runtime = "nodejs";

// GET /api/organizations
//
// The organizations the signed-in user is a member of, newest first.
//
// SECURITY: this is a pure read through the authenticated session. The
// database is the authority — RLS policy `organizations_select_members` (and
// the SECURITY DEFINER is_org_member() helper it calls) filters to exactly the
// organizations where auth.uid() is a member. The route never receives or
// trusts a client-supplied organization id, never uses a service-role key, and
// never sees a row it is not entitled to. An organization the caller is not a
// member of is indistinguishable from one that does not exist: it is simply
// absent from the response.
//
// Response contract ({ organizations: [...] }):
//   id         uuid        primary key of the organization
//   name       string      display name
//   slug       string      unique URL-safe identifier
//   created_at timestamptz when the organization was created
// Only the fields the future organization list UI needs are returned;
// created_by / updated_at are internal and intentionally not exposed here.
export async function GET() {
  const supabase = await createClient();

  // 1. authenticate — resolve the session from the request cookies.
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // 2. authorize — the user must have an application profile, matching the
  //    other organization routes.
  const { data: profile } = await supabase
    .from("profiles")
    .select("id")
    .eq("id", user.id)
    .maybeSingle();
  if (!profile) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  // 3. list — through the authenticated session so RLS
  //    (organizations_select_members -> is_org_member) filters to only the
  //    caller's organizations. No service-role key; membership is enforced by
  //    the database, not the application. An authenticated user belonging to
  //    no organization gets a successful empty list.
  const { data: organizations, error } = await supabase
    .from("organizations")
    .select("id, name, slug, created_at")
    .order("created_at", { ascending: false });

  if (error) {
    return NextResponse.json(
      { error: "Failed to load organizations" },
      { status: 500 },
    );
  }

  return NextResponse.json(
    { organizations: organizations ?? [] },
    { status: 200 },
  );
}