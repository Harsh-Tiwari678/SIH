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

// Slug validation mirrors the create_organization RPC exactly: lowercase
// letters/digits, single hyphens between segments, at most 63 characters.
const SLUG_PATTERN = /^[a-z0-9]+(-[a-z0-9]+)*$/;
const SLUG_MAX_LENGTH = 63;

// POST /api/organizations
//
// Create an organization and make the caller its first (admin) member.
//
// SECURITY: identity is never taken from the body. create_organization is a
// SECURITY DEFINER RPC that derives the actor from auth.uid() (the session),
// requires the caller to have an application profile, validates name + slug,
// enforces slug uniqueness, writes the org + creator's admin membership + the
// organization.created audit entry in one transaction, and inserts with
// created_by set from auth.uid() only. This route performs the same
// authenticate -> authorize (profile) -> validate order the sibling routes
// use, then delegates the operation entirely to the RPC. no created_by /
// actor / user fields are ever read from the request; anything the client
// sends beyond name and slug is ignored. No service-role key is used.
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
    .select("id")
    .eq("id", user.id)
    .maybeSingle();
  if (!profile) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  // 3. validate — name and slug shape only. Uniqueness is re-checked inside
  //    the RPC, which is also where the writer role is asserted.
  let body: { name?: unknown; slug?: unknown };
  try {
    body = (await request.json()) as typeof body;
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const name = typeof body.name === "string" ? body.name.trim() : "";
  const slug = typeof body.slug === "string" ? body.slug.trim().toLowerCase() : "";

  if (!name) {
    return NextResponse.json(
      { error: "Organization name is required" },
      { status: 400 },
    );
  }
  if (!slug) {
    return NextResponse.json(
      { error: "Organization slug is required" },
      { status: 400 },
    );
  }
  if (slug.length > SLUG_MAX_LENGTH || !SLUG_PATTERN.test(slug)) {
    return NextResponse.json(
      {
        error:
          "Organization slug must be lowercase letters and digits separated by single hyphens, at most 63 characters",
      },
      { status: 400 },
    );
  }

  // 4 & 5. business operation + audit — both run inside the trusted
  // create_organization SECURITY DEFINER RPC, atomically, with identity
  // derived from auth.uid() (never from client input). created_by / role are
  // not reachable by the client on this path. Slugs are unique DB-side.
  const { data, error } = await supabase.rpc("create_organization", {
    p_name: name,
    p_slug: slug,
  });

  if (error) {
    return NextResponse.json(
      { error: createRpcMessage(error.message) },
      { status: createRpcStatus(error.message) },
    );
  }

  return NextResponse.json({ organization: { id: data } }, { status: 201 });
}

// create_organization raises exact, known codes; the includes-style checks
// follow the existing route convention. DB internals are never echoed to the
// client — each code maps to a fixed status and a safe message.

function createRpcStatus(message: string): number {
  if (message.includes("not_authenticated")) return 401;
  if (message.includes("profile_not_found")) return 403;
  if (
    message.includes("organization_name_required") ||
    message.includes("organization_slug_required") ||
    message.includes("invalid_slug")
  ) {
    return 400;
  }
  if (message.includes("slug_taken")) return 409;
  return 500;
}

function createRpcMessage(message: string): string {
  if (message.includes("not_authenticated")) return "Unauthorized";
  if (message.includes("profile_not_found")) return "Forbidden";
  if (message.includes("organization_name_required")) {
    return "Organization name is required";
  }
  if (message.includes("organization_slug_required")) {
    return "Organization slug is required";
  }
  if (message.includes("invalid_slug")) {
    return "Organization slug must be lowercase letters and digits separated by single hyphens, at most 63 characters";
  }
  if (message.includes("slug_taken")) {
    return "Organization slug is already in use";
  }
  return "Failed to create organization";
}