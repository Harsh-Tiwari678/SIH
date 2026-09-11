import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import {
  serializeAuditEvents,
  type AuditEventRawRow,
} from "@/lib/audit-serialization";

export const runtime = "nodejs";

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// GET /api/cases/[id]/evidence/[evidenceId]/audit
//
// Evidence-scoped audit trail, newest first: the evidence row itself, its
// document versions (anchoring + verification events live on the version) and
// its blockchain anchors.
//
// SECURITY: authorization is enforced inside the SECURITY DEFINER RPC
// (list_evidence_audit_events): actor re-derived from the session, caller must
// be a member of the evidence's owning case, meta scrubbed of storage_key. An
// inaccessible evidence is reported identically to a nonexistent one (404).
// The [evidenceId] segment is shape-validated only; the evidence row's own
// case is what authorizes. No service-role key is used.
export async function GET(
  _request: Request,
  ctx: RouteContext<"/api/cases/[id]/evidence/[evidenceId]/audit">,
) {
  const { id: caseId, evidenceId } = await ctx.params;

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
  if (!UUID_PATTERN.test(caseId) || !UUID_PATTERN.test(evidenceId)) {
    return NextResponse.json({ error: "Invalid ids" }, { status: 400 });
  }

  // 4. the trail — membership + visibility are re-checked inside the RPC.
  const { data, error } = await supabase.rpc("list_evidence_audit_events", {
    p_evidence_id: evidenceId,
  });
  if (error) {
    switch (error.message) {
      case "not_authenticated":
        return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
      case "profile_not_found":
        return NextResponse.json({ error: "Forbidden" }, { status: 403 });
      case "evidence_not_found":
        return NextResponse.json(
          { error: "Evidence not found" },
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