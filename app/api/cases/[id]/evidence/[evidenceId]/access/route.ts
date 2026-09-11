import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import { EVIDENCE_BUCKET } from "@/lib/storage";
import {
  type EvidenceAccessMode,
  buildAccessResponse,
  isEvidenceAccessMode,
  signedUrlExpiry,
  SIGNED_URL_LIFETIME_SECONDS,
} from "@/lib/evidence-access";

export const runtime = "nodejs";

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

interface ResolveResult {
  case_id: string;
  evidence_id: string;
  document_version_id: string;
  version: number;
  file_name: string;
  mime_type: string;
  file_size_bytes: number;
  storage_key: string;
}

// GET /api/cases/[id]/evidence/[evidenceId]/access?mode=preview|download
//                                                       &version=<documentVersionId>
//
// Secure preview/download of an evidence file. The endpoint never streams or
// copies file bytes. It:
//   1. authenticates via the request session,
//   2. authorizes through resolve_evidence_access (a SECURITY DEFINER RPC that
//      derives the actor from auth.uid() and requires case membership; an
//      inaccessible evidence is identical to a nonexistent one, 404),
//   3. resolves the requested (or latest) document version server-side,
//   4. mints a SHORT-LIVED signed URL through the authenticated server client,
//      so Supabase Storage re-checks the storage.objects SELECT RLS policy for
//      the exact object (defense in depth; no service-role key),
//   5. records the 'evidence.accessed' audit event — REQUIRED before the URL
//      may be returned. If the audit cannot be recorded the access FAILS
//      CLOSED: the signed URL is not delivered (it is discarded and expires on
//      its own), the route logs only safe operational metadata and answers 500.
//      The audit must succeed for the access to succeed.
//   6. returns ONLY the url + minimal display metadata. storage_key never
//      leaves the server; the signed URL is never logged nor persisted.
//
// The signed URL necessarily encodes the object path, but only as a
// time-limited capability: it expires after SIGNED_URL_LIFETIME_SECONDS and
// every open requires a fresh, server-authorized token.
export async function GET(
  request: NextRequest,
  ctx: RouteContext<"/api/cases/[id]/evidence/[evidenceId]/access">,
) {
  const { id: caseId, evidenceId } = await ctx.params;

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

  // 3. validate — ids and the mode vocabulary. Authorization data (actor,
  //    membership) never comes from the request.
  if (!UUID_PATTERN.test(caseId) || !UUID_PATTERN.test(evidenceId)) {
    return NextResponse.json({ error: "Invalid ids" }, { status: 400 });
  }

  const searchParams = request.nextUrl.searchParams;
  const modeValue = searchParams.get("mode");
  // Absent mode defaults to preview; an explicit non-vocabulary value is a
  // bad request, never silently coerced.
  if (modeValue !== null && !isEvidenceAccessMode(modeValue)) {
    return NextResponse.json(
      { error: "mode must be preview or download" },
      { status: 400 },
    );
  }
  const mode: EvidenceAccessMode = isEvidenceAccessMode(modeValue)
    ? modeValue
    : "preview";

  const versionValue = searchParams.get("version");
  if (
    versionValue !== null &&
    (versionValue === "" || !UUID_PATTERN.test(versionValue))
  ) {
    return NextResponse.json(
      { error: "version must be a valid document version id" },
      { status: 400 },
    );
  }

  // 4. business logic (authorization + resolution) — the SECURITY DEFINER RPC
  //    enforces case visibility, mode vocabulary and version ownership.
  const { data: resolvedUntyped, error: resolveError } = await supabase.rpc(
    "resolve_evidence_access",
    {
      p_evidence_id: evidenceId,
      p_document_version_id: versionValue ?? null,
      p_mode: mode,
    },
  );
  const resolved = resolvedUntyped as ResolveResult | null;

  if (resolveError) {
    const mapped = rpcStatusMessage(resolveError.message);
    if (mapped) return mapped;
    console.error(
      JSON.stringify({
        event: "evidence_access_resolve_failed",
        case_id: caseId,
        evidence_id: evidenceId,
        mode,
      }),
    );
    return NextResponse.json(
      { error: "Failed to resolve the file" },
      { status: 500 },
    );
  }

  // URL consistency: the evidence's real case must be the one in the path. An
  // evidence under a different case is reported identically as not found.
  if (!resolved || resolved.case_id !== caseId) {
    return NextResponse.json(
      { error: "Evidence not found" },
      { status: 404 },
    );
  }

  // 5. mint the short-lived signed URL through the authenticated session
  //    client. The Storage API independently re-checks that this user may
  //    SELECT the object before issuing the token.
  const { data: signed, error: signError } = await supabase.storage
    .from(EVIDENCE_BUCKET)
    .createSignedUrl(resolved.storage_key, SIGNED_URL_LIFETIME_SECONDS, {
      // 'download' forces a Content-Disposition attachment with the real name.
      download: mode === "download" ? resolved.file_name : false,
    });

  if (signError || !signed?.signedUrl) {
    console.error(
      JSON.stringify({
        event: "evidence_signed_url_failed",
        case_id: caseId,
        evidence_id: evidenceId,
        document_version_id: resolved.document_version_id,
        mode,
      }),
    );
    return NextResponse.json(
      { error: "Failed to open the file" },
      { status: 500 },
    );
  }

  // 6. audit — record who accessed which version, in which mode. This MUST
  //    succeed before the signed URL is returned (fail closed): an accessed
  //    evidence file is only ever delivered alongside its recorded audit row.
  //    The already-minted URL (if any) is discarded and expires naturally; it
  //    is never returned, logged or persisted, and it cannot be "rolled back".
  const { error: auditError } = await supabase.rpc("record_evidence_access", {
    p_document_version_id: resolved.document_version_id,
    p_mode: mode,
  });
  if (auditError) {
    // Safe operational metadata only: identifiers, never the signed URL,
    // never the storage key, never the audit failure internals.
    console.error(
      JSON.stringify({
        event: "evidence_access_audit_failed",
        case_id: caseId,
        evidence_id: evidenceId,
        document_version_id: resolved.document_version_id,
        mode,
      }),
    );
    return NextResponse.json(
      { error: "Failed to open the file" },
      { status: 500 },
    );
  }

  const access = buildAccessResponse(
    {
      file_name: resolved.file_name,
      mime_type: resolved.mime_type,
      version: resolved.version,
    },
    mode,
    signed.signedUrl,
    signedUrlExpiry(),
  );
  if (!access) {
    // Defensive: the shaped response invariant must hold for a storage URL.
    return NextResponse.json({ error: "Failed to open the file" }, { status: 500 });
  }

  // Signed URLs are capabilities: never cache them in a shared layer.
  return NextResponse.json({ access }, {
    status: 200,
    headers: { "Cache-Control": "no-store" },
  });
}

// RPC exceptions are exact, known codes; the includes-style checks follow the
// existing route convention (see POST /api/cases/[id]/evidence).
function rpcStatusMessage(message: string): NextResponse | null {
  if (message.includes("not_authenticated")) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  if (message.includes("profile_not_found")) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }
  if (message.includes("invalid_mode")) {
    return NextResponse.json(
      { error: "mode must be preview or download" },
      { status: 400 },
    );
  }
  if (
    message.includes("evidence_not_found") ||
    message.includes("document_version_not_found")
  ) {
    return NextResponse.json({ error: "Evidence not found" }, { status: 404 });
  }
  return null;
}