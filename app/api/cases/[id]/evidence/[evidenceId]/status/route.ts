import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export const runtime = "nodejs";

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const EVIDENCE_STATUSES = [
  "received",
  "under_review",
  "verified",
  "rejected",
  "archived",
] as const;

// PATCH /api/cases/[id]/evidence/[evidenceId]/status
// Request body: { "status": "<EvidenceStatus>" }
//
// The ONLY path that transitions evidence status. Direct UPDATE of the `status`
// column via RLS was revoked (see the audit read path migration), so status can
// no longer be clobbered by a lead/investigator hand-editing the table.
//
// SECURITY: authorization is enforced inside the SECURITY DEFINER RPC
// (update_evidence_status): actor re-derived from the session, only the case
// lead or an investigator may transition, the status must be in the existing
// CHECK vocabulary, identity is never taken from the request, and — the
// hardening — 'verified' is ONLY allowed when at least one document version of
// the evidence has a blockchain_anchors row in state 'anchored' whose
// evidence_sha256 exactly equals that version's sha256 (returned as 409).
// The transition is written to audit_logs as 'evidence.status_changed'.
// The [evidenceId] segment is shape-validated only; the evidence row's own
// case is what authorizes. No service-role key is used.
export async function PATCH(
  request: Request,
  ctx: RouteContext<"/api/cases/[id]/evidence/[evidenceId]/status">,
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

  // 4. validate the request body — the status vocabulary is re-asserted inside
  //    the RPC; this is shape validation only.
  let body: { status?: unknown };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid body" }, { status: 400 });
  }
  const status = typeof body.status === "string" ? body.status : null;
  if (
    !status ||
    !(EVIDENCE_STATUSES as readonly string[]).includes(status)
  ) {
    return NextResponse.json({ error: "Invalid status" }, { status: 400 });
  }

  // 5. business operation + audit — enforced inside the RPC (authorization,
  //    the verification gate for 'verified', and the status_changed audit row).
  const { data, error } = await supabase.rpc("update_evidence_status", {
    p_evidence_id: evidenceId,
    p_status: status,
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
      case "not_authorized_to_update":
        return NextResponse.json(
          { error: "Only the case lead or an investigator may update evidence" },
          { status: 403 },
        );
      case "status_not_allowed":
        return NextResponse.json({ error: "Status not allowed" }, { status: 400 });
      case "verification_required":
        return NextResponse.json(
          {
            error:
              "Evidence cannot be marked verified until a version is anchored and verified on chain",
          },
          { status: 409 },
        );
      default:
        return NextResponse.json(
          { error: "Failed to update evidence status" },
          { status: 500 },
        );
    }
  }

  // Return a slim, display-safe projection — never the whole evidence row.
  const row = (data ?? {}) as {
    id?: string;
    status?: string;
    updated_at?: string;
  };
  return NextResponse.json({
    evidence: {
      id: typeof row.id === "string" ? row.id : evidenceId,
      status:
        typeof row.status === "string" ? row.status : status,
      updated_at:
        typeof row.updated_at === "string" ? row.updated_at : null,
    },
  });
}