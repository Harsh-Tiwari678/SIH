import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import {
  serializeEvidenceDetail,
  type AnchorRawRow,
  type CustodyRawRow,
  type EvidenceCoreRawRow,
  type VersionRawRow,
} from "@/lib/evidence-serialization";

export const runtime = "nodejs";

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// GET /api/cases/[id]/evidence/[evidenceId]
//
// Evidence detail: the evidence record, every immutable document version
// (mimetype/size/SHA-256), each version's blockchain_anchors context, and the
// chain-of-custody possession trail.
//
// SECURITY: the same additive read model as the list endpoint. Authentication
// comes from the request session; the visible scope is enforced by RLS
// (evidence_select_case_members, document_versions_select_member_of_evidence_case,
// chain_of_custody_select_member_of_evidence_case,
// blockchain_anchors_select_case_members, profiles_select_self_or_shared_case).
// An evidence outside the caller's cases resolves identically to a nonexistent
// one (404). The case id in the URL is shape-validated only; the evidence row's
// own case is what the policies authorize against. No service-role key is used.
export async function GET(
  _request: Request,
  ctx: RouteContext<"/api/cases/[id]/evidence/[evidenceId]">,
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

  // 3. validate — shape only.
  if (!UUID_PATTERN.test(caseId) || !UUID_PATTERN.test(evidenceId)) {
    return NextResponse.json({ error: "Invalid ids" }, { status: 400 });
  }

  // 4. evidence record (with creator name). RLS hides rows the caller may not
  //    see; a hidden or missing row is reported identically as 404 so we never
  //    reveal whether the evidence exists.
  const { data: core, error: coreError } = await supabase
    .from("evidence")
    .select(
      "id, case_id, evidence_number, title, description, type, status, created_by, created_at, updated_at, creator:profiles!evidence_created_by_fkey(id, full_name)",
    )
    .eq("id", evidenceId)
    .eq("case_id", caseId)
    .maybeSingle();

  if (coreError) {
    return NextResponse.json(
      { error: "Failed to load evidence" },
      { status: 500 },
    );
  }
  if (!core) {
    return NextResponse.json(
      { error: "Evidence not found" },
      { status: 404 },
    );
  }

  // 5. document versions, oldest first (evidence is versioned, never
  //    overwritten; every immutable version is returned).
  const { data: versionRows, error: versionsError } = await supabase
    .from("document_versions")
    .select(
      "id, version, prev_version_id, file_name, mime_type, file_size_bytes, sha256, uploaded_by, uploaded_at, notes, uploader:profiles!document_versions_uploaded_by_fkey(id, full_name)",
    )
    .eq("evidence_id", evidenceId)
    .order("version", { ascending: true });
  if (versionsError) {
    return NextResponse.json(
      { error: "Failed to load evidence versions" },
      { status: 500 },
    );
  }

  // 6. blockchain anchor context for each version (one per version by the
  //    UNIQUE(document_version_id) constraint). Permit-listed + defensively
  //    re-validated by parseAnchorContext.
  const versionIds = (versionRows ?? []).map((row) => row.id);
  let anchorRows: AnchorRawRow[] = [];
  if (versionIds.length > 0) {
    const { data, error } = await supabase
      .from("blockchain_anchors")
      .select(
        "id, document_version_id, status, tx_hash, block_number, anchored_at, network, chain_id, contract_address, error_message",
      )
      .in("document_version_id", versionIds);
    if (error) {
      return NextResponse.json(
        { error: "Failed to load anchor records" },
        { status: 500 },
      );
    }
    anchorRows = (data ?? []) as unknown as AnchorRawRow[];
  }

  // 7. chain of custody, chronological. The three profiles embeds are
  //    disambiguated because chain_of_custody has three FKs into profiles.
  const { data: custodyRows, error: custodyError } = await supabase
    .from("chain_of_custody")
    .select(
      "id, action, actor_id, from_profile_id, to_profile_id, location, notes, occurred_at, actor:profiles!chain_of_custody_actor_id_fkey(id, full_name), from_profile:profiles!chain_of_custody_from_profile_id_fkey(id, full_name), to_profile:profiles!chain_of_custody_to_profile_id_fkey(id, full_name)",
    )
    .eq("evidence_id", evidenceId)
    .order("occurred_at", { ascending: true });
  if (custodyError) {
    return NextResponse.json(
      { error: "Failed to load the chain of custody" },
      { status: 500 },
    );
  }

  const detail = serializeEvidenceDetail(
    core as unknown as EvidenceCoreRawRow,
    (versionRows ?? []) as unknown as VersionRawRow[],
    anchorRows,
    (custodyRows ?? []) as unknown as CustodyRawRow[],
  );

  return NextResponse.json(detail, { status: 200 });
}