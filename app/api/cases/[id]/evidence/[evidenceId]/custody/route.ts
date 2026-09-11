import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";

export const runtime = "nodejs";

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Actions recordable through this endpoint. 'received' is intake-only
// (create_evidence) and 'archived' follows the status transition path, so
// neither is offered here as a free-form custody write.
const CUSTODY_ACTIONS = new Set(["transferred", "returned", "released", "verified"]);

interface CustodyRequestBody {
  action: string
  documentVersionId?: string | null
  fromProfileId?: string | null
  toProfileId?: string | null
  location?: string | null
  notes?: string | null
}

// POST /api/cases/[id]/evidence/[evidenceId]/custody
//
// Records a validated chain-of-custody event. Security contract:
//   * authentication is the request session (createClient), authorization,
//     action/shape/from-to validation and the audit mirror ALL live in the
//     record_custody_event SECURITY DEFINER RPC — never here, never in the UI.
//   * actor_id and occurred_at are never accepted from the body. The actor is
//     derived from auth.uid() inside the RPC and the timestamp is server-set
//     to now(), so a client can neither impersonate a handler nor backdate an
//     event.
//   * only a safe projection is returned; internal ids are limited to the
//     rows already exposed to members by the read path.
//   * RPC errors are mapped to explicit HTTP statuses; internal details are
//     never leaked to the client.
export async function POST(
  request: NextRequest,
  ctx: RouteContext<"/api/cases/[id]/evidence/[evidenceId]/custody">,
) {
  const { id: caseId, evidenceId } = await ctx.params;

  const supabase = await createClient();

  // 1. authenticate.
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  // 2. the user must have an application profile.
  const { data: profile } = await supabase
    .from("profiles")
    .select("id")
    .eq("id", user.id)
    .maybeSingle();
  if (!profile) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  // 3. validate ids.
  if (!UUID_PATTERN.test(caseId) || !UUID_PATTERN.test(evidenceId)) {
    return NextResponse.json({ error: "Invalid ids" }, { status: 400 });
  }

  // 4. parse + validate the body. Authorization data (actor, membership,
  //    timestamps) never comes from the request.
  let body: CustodyRequestBody
  try {
    body = (await request.json()) as CustodyRequestBody
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 })
  }
  if (
    typeof body.action !== "string" ||
    !CUSTODY_ACTIONS.has(body.action)
  ) {
    return NextResponse.json(
      { error: "action must be transferred, returned, released or verified" },
      { status: 400 },
    );
  }
  if (
    (body.documentVersionId !== undefined && body.documentVersionId !== null) ||
    (body.fromProfileId !== undefined && body.fromProfileId !== null) ||
    (body.toProfileId !== undefined && body.toProfileId !== null)
  ) {
    const invalid = [
      body.documentVersionId,
      body.fromProfileId,
      body.toProfileId,
    ].some((v) => typeof v !== "string" || !UUID_PATTERN.test(v));
    if (invalid) {
      return NextResponse.json(
        { error: "Invalid id in custody request" },
        { status: 400 },
      );
    }
  }
  const location =
    typeof body.location === "string" ? body.location.trim().slice(0, 500) : null
  const notes =
    typeof body.notes === "string" ? body.notes.trim().slice(0, 2000) : null

  // 5. business logic — the SECURITY DEFINER RPC performs authentication,
  //    authorization, action/shape validation, the verified anchor-gate and
  //    the same-transaction audit mirror. caseId stays server-side as the
  //    route's own sanity anchor; the RPC re-derives the case from evidence.
  const { data: custody, error } = await supabase.rpc("record_custody_event", {
    p_evidence_id: evidenceId,
    p_action: body.action,
    p_document_version_id: body.documentVersionId ?? null,
    p_from_profile_id: body.fromProfileId ?? null,
    p_to_profile_id: body.toProfileId ?? null,
    p_location: location,
    p_notes: notes,
  });

  if (error) {
    return NextResponse.json(
      { error: rpcMessage(error.message) },
      { status: rpcStatus(error.message) },
    );
  }

  return NextResponse.json({
    custody: {
      id: custody.id,
      action: custody.action,
      actor_id: custody.actor_id,
      from_profile_id: custody.from_profile_id,
      to_profile_id: custody.to_profile_id,
      location: custody.location,
      notes: custody.notes,
      occurred_at: custody.occurred_at,
    },
  });
}

// RPC exceptions are exact, known codes (dotted, so the includes-style checks
// below follow the existing route convention; order matters where one code
// contains another).
function rpcStatus(message: string): number {
  if (
    message.includes("not_authenticated") ||
    message.includes("profile_not_found")
  ) {
    return 401;
  }
  if (
    message.includes("evidence_not_found") ||
    message.includes("case_not_found")
  ) {
    return 404;
  }
  if (message.includes("not_authorized_for_custody")) return 403;
  if (message.includes("verification_required")) return 409;
  return 400;
}

function rpcMessage(message: string): string {
  if (message.includes("not_authenticated")) return "Unauthorized";
  if (message.includes("profile_not_found")) return "Forbidden";
  if (message.includes("evidence_not_found")) return "Evidence not found";
  if (message.includes("case_not_found")) return "Case not found";
  if (message.includes("not_authorized_for_custody")) {
    return "Only the case lead or an investigator can record custody events";
  }
  if (message.includes("verification_required")) {
    return "Verified requires a matching on-chain anchor for this evidence";
  }
  if (message.includes("received_created_on_intake")) {
    return "Custody receipt is recorded automatically on evidence intake";
  }
  if (message.includes("to_profile_required")) {
    return "A receiving member is required for this action";
  }
  if (message.includes("to_profile_not_allowed")) {
    return "This action does not take a receiving member";
  }
  if (message.includes("to_profile_is_actor")) {
    return "You cannot hand custody to yourself";
  }
  if (message.includes("document_version_not_found")) {
    return "The document version does not belong to this evidence";
  }
  if (message.includes("from_to_same_profile")) {
    return "From and to must be different members";
  }
  if (message.includes("from_profile_not_in_case")) {
    return "From must be a member of this case";
  }
  if (message.includes("to_profile_not_in_case")) {
    return "To must be a member of this case";
  }
  if (message.includes("action_not_allowed")) {
    return "Denied: that custody action is not permitted";
  }
  return "Could not record the custody event";
}