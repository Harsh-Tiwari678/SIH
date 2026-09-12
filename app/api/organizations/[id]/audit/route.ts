import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import {
  serializeAuditEvents,
  type AuditEventRawRow,
} from "@/lib/audit-serialization";

export const runtime = "nodejs";

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// GET /api/organizations/[id]/audit
//
// Organization-scoped audit trail, newest first: every operational event that
// belongs to the org (organization.*, organization_member.*, and the case /
// evidence / anchor events owned by the org), with actor, entity label and
// display-safe meta.
//
// SECURITY: authorization is enforced inside the SECURITY DEFINER RPC
// (list_organization_audit_events), which re-derives the actor from the
// session, requires the caller to be a member of the target org, and strips
// `storage_key` from meta. An org the caller cannot see is reported identically
// to a nonexistent one (404), so existence is never leaked. serialization is
// applied again here as a second allow-list: even a future DB event carrying an
// unexpected meta key is never rendered. No service-role key is used.
export async function GET(
  _request: Request,
  ctx: RouteContext<"/api/organizations/[id]/audit">,
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

  // 3. validate — shape only.
  if (!UUID_PATTERN.test(orgId)) {
    return NextResponse.json(
      { error: "Invalid organization id" },
      { status: 400 },
    );
  }

  // 4. the trail — org membership + visibility are re-checked inside the RPC.
  const { data, error } = await supabase.rpc("list_organization_audit_events", {
    p_org_id: orgId,
  });
  if (error) {
    switch (error.message) {
      case "not_authenticated":
        return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
      case "profile_not_found":
        return NextResponse.json({ error: "Forbidden" }, { status: 403 });
      case "org_not_found":
        return NextResponse.json(
          { error: "Organization not found" },
          { status: 404 },
        );
      default:
        return NextResponse.json(
          { error: "Failed to load the audit trail" },
          { status: 500 },
        );
    }
  }

  const events = serializeAuditEvents(
    (data ?? []) as unknown as AuditEventRawRow[],
  );
  return NextResponse.json({ events }, { status: 200 });
}