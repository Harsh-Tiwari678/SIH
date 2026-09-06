import { NextResponse } from "next/server";
import {
  anchorErrorStatus,
  anchorOutcomeBody,
  anchorOutcomeHttpStatus,
} from "@/lib/blockchain/upload-integration";
import { anchorDocumentVersion } from "@/lib/blockchain/orchestrator";

export const runtime = "nodejs";

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// POST /api/cases/[id]/evidence/[documentVersionId]/anchor
//
// Separately-triggerable on-chain submission for a document version whose
// blockchain_anchors row is 'pending' (created synchronously by the evidence
// upload). Runs the full DB -> Ethereum -> verification -> DB lifecycle
// (anchorDocumentVersion) synchronously inside this request, so it is NOT
// subject to serverless teardown and nothing is deferred. Retrying this
// endpoint is idempotent:
//   * the DB row is authoritative — a pending row is reused, a failed row is
//     reset to pending, and an anchored row short-circuits to
//     'already_anchored' before any transaction is sent;
//   * the deployed EvidenceAnchor contract reverts AlreadyAnchored if the
//     (evidence_id_hash, version_id_hash) pair is already set, which is the
//     second line of defense against duplicate transactions.
// Authorization is enforced server-side inside the orchestrator: the SECURITY
// DEFINER RPCs re-derive auth.uid() from the request session and require the
// actor to be the case lead or an investigator on the version's case. The case
// id in the URL is part of the REST shape; the version's own case is what the
// RPCs authorize against.
export async function POST(
  _request: Request,
  ctx: RouteContext<"/api/cases/[id]/evidence/[documentVersionId]/anchor">,
) {
  const { id: caseId, documentVersionId } = await ctx.params;

  // validate — shape only; every authorization is re-derived by the RPCs from
  // the session, never trusted from the path.
  if (!UUID_PATTERN.test(caseId) || !UUID_PATTERN.test(documentVersionId)) {
    return NextResponse.json({ error: "Invalid ids" }, { status: 400 });
  }

  // business operation + audit — the orchestrator re-checks authentication and
  // authorization, reuses/resets the anchor slot, transmits and verifies the
  // transaction, and records the outcome via the mark_* RPCs (which write the
  // audit logs). Thrown AnchorOrchestrationError maps to a status; handled
  // outcomes return their machine state.
  let outcome;
  try {
    outcome = await anchorDocumentVersion(documentVersionId);
  } catch (raw) {
    const mapped = anchorErrorStatus(raw);
    return NextResponse.json({ error: mapped.error }, { status: mapped.status });
  }

  return NextResponse.json(
    { anchor: anchorOutcomeBody(outcome) },
    { status: anchorOutcomeHttpStatus(outcome) },
  );
}