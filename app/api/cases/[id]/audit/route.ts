import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import {
  serializeAuditEvents,
  type AuditEventRawRow,
} from "@/lib/audit-serialization";

export const runtime = "nodejs";

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// GET /api/cases/[id]/audit
//
// Full audit trail for a case, newest first: every operational event written
// in the dotted vocabulary (case.*, case_member.*, evidence.*, anchor.*,
// verification.*), with actor, affected entity label and display-safe meta.
//
// SECURITY: authorization is enforced inside the SECURITY DEFINER RPC
// (list_case_audit_events), which re-derives the actor from the session,
// requires the caller to be the case creator or a member (the same boundary
// cases_select_creator_or_member uses for reads), resolves the polymorphic
// entity_type/entity_id, and strips `storage_key` from meta. audit_logs itself
// still has NO SELECT policy for ordinary members — the RPC is the only read
// path. A case the caller cannot see is reported identically to a nonexistent
// one (404), so existence is never leaked. No service-role key is used.
export async function GET(
  _request: Request,
  ctx: RouteContext<"/api/cases/[id]/audit">,
) {
  const { id: caseId } = await ctx.params;

  // 1. authenticate — resolve the session from the request cookies.
  const supabase = await createClient();
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
  if (!UUID_PATTERN.test(caseId)) {
    return NextResponse.json({ error: "Invalid ids" }, { status: 400 });
  }

  // 4. the trail — membership + visibility are re-checked inside the RPC.
  const { data, error } = await supabase.rpc("list_case_audit_events", {
    p_case_id: caseId,
  });
  if (error) {
    switch (error.message) {
      case "not_authenticated":
        return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
      case "profile_not_found":
        return NextResponse.json({ error: "Forbidden" }, { status: 403 });
      case "case_not_found":
        return NextResponse.json(
          { error: "Case not found" },
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