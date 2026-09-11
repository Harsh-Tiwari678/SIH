import { NextResponse } from "next/server";
import {
  verificationAuditOutcome,
} from "@/lib/audit-serialization";
import { createClient } from "@/lib/supabase/server";
import {
  verificationBody,
  verificationErrorStatus,
  verifyDocumentVersion,
} from "@/lib/blockchain/verification";

export const runtime = "nodejs";

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// GET /api/cases/[id]/evidence/[evidenceId]/verification
//
// NOTE: the [evidenceId] segment carries the document version id (the value
// this route verifies); the segment is named after the evidence route it now
// lives under. The version's own case is what authorizes.
//
// Read-only, on-chain integrity verification of a document version.
//
// The response's `verification.status` is one of:
//   verified              — a matching anchor exists on-chain for THIS version's
//                           (evidence_id_hash, version_id_hash) slot holding
//                           EXACTLY the database SHA-256; verify() returned true.
//   not_anchored          — the on-chain slot is empty (clearly distinct from a
//                           failure; the version is simply not anchored yet).
//   hash_mismatch         — an anchor exists but holds a different SHA-256 (an
//                           integrity problem; nothing here rewrites the DB).
//   verification_ambiguous — the blockchain could not be read reliably
//                           (RPC/network/provider failure); no verdict is
//                           concluded.
//
// The result is derived from an INDEPENDENT contract read — the database's
// blockchain_anchors.status is never trusted as proof of anchoring. The
// database anchor row is returned only as permit-listed context.
//
// SECURITY: the case id in the URL is part of the REST shape and is only
// shape-validated. Authorization is enforced server-side by
// verifyDocumentVersion: the version -> evidence -> case relationship is
// resolved through RLS for the session user, and only members of the version's
// OWN case can read it. No client-supplied case id is used for authorization.
// No blockchain write, no signer private key, no service-role key.
export async function GET(
  _request: Request,
  ctx: RouteContext<"/api/cases/[id]/evidence/[evidenceId]/verification">,
) {
  const { id: caseId, evidenceId } = await ctx.params;

  // validate — shape only; the version's own case is what authorizes, never
  // the case id from the path.
  if (!UUID_PATTERN.test(caseId) || !UUID_PATTERN.test(evidenceId)) {
    return NextResponse.json({ error: "Invalid ids" }, { status: 400 });
  }

  let frame;
  try {
    frame = await verifyDocumentVersion(evidenceId);
  } catch (raw) {
    const mapped = verificationErrorStatus(raw);
    return NextResponse.json({ error: mapped.error }, { status: mapped.status });
  }

  // Best-effort audit of the read itself: 'requested' is always recorded, and a
  // definitive verdict records 'passed' / 'failed'. A logging failure must
  // never break the read, so these calls swallow errors and continue.
  await recordVerificationAudit(evidenceId, "requested", frame.status);
  const outcome = verificationAuditOutcome(frame.status);
  if (outcome) {
    await recordVerificationAudit(evidenceId, outcome.result, outcome.verdict);
  }

  // A verification outcome — including not_anchored / hash_mismatch /
  // verification_ambiguous — is a successful read of an integral verdict, so
  // the endpoint returns 200 with the structured verification body.
  return NextResponse.json({ verification: verificationBody(frame) });
}

// Writes the event through the SECURITY DEFINER RPC (record_verification_event),
// which re-derives the actor from the session and enforces membership of the
// version's own case. Identity never comes from this module.
async function recordVerificationAudit(
  documentVersionId: string,
  result: string,
  verdict: string,
): Promise<void> {
  try {
    const supabase = await createClient();
    const { error } = await supabase.rpc("record_verification_event", {
      p_document_version_id: documentVersionId,
      p_result: result,
      p_verdict: verdict,
    });
    if (error) {
      console.error(
        `[audit] record_verification_event failed (${result}/${verdict}): ${error.message}`,
      );
    }
  } catch (err) {
    console.error(
      "[audit] unexpected error recording verification event:",
      err,
    );
  }
}