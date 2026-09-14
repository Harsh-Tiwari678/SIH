import { NextResponse } from "next/server";
import { createClient } from "@/lib/supabase/server";
import {
  ALLOWED_EVIDENCE_MIME_TYPES,
  EVIDENCE_BUCKET,
  MAX_EVIDENCE_FILE_SIZE_BYTES,
  bytesMatchMimeType,
  isAllowedEvidenceMime,
  isEvidenceType,
  sanitizeFileName,
  sha256Hex,
} from "@/lib/storage";
import {
  persistedVersionIdFromResponse,
  requestPendingAnchor,
} from "@/lib/blockchain/upload-integration";
import { evidenceRegistrationToken } from "@/lib/evidence-registration";
import {
  serializeEvidenceListItem,
  type EvidenceListRawRow,
} from "@/lib/evidence-serialization";

export const runtime = "nodejs";

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const MAX_TITLE_LENGTH = 500;
const MAX_DESCRIPTION_LENGTH = 5000;
const MAX_NOTES_LENGTH = 2000;

// Read a bounded text form field. Returns undefined for absent/empty fields.
function formText(form: FormData, name: string, maxLength: number): string | undefined {
  const value = form.get(name);
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  return trimmed.slice(0, maxLength);
}

export async function GET(
  _request: Request,
  ctx: RouteContext<"/api/cases/[id]/evidence">,
) {
  const { id: caseId } = await ctx.params;

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

  // 3. validate — shape only. Authorization for the listed rows is enforced by
  //    the existing evidence_select_case_members RLS policy: an actor outside
  //    the case sees an empty list (indistinguishable from a case with no
  //    evidence), so nothing about the case leaks. The embedded creator/
  //    uploader names resolve through profiles_select_self_or_shared_case; the
  //    FK hints disambiguate the profiles embeds the same way the case detail
  //    query does.
  if (!UUID_PATTERN.test(caseId)) {
    return NextResponse.json({ error: "Invalid case id" }, { status: 400 });
  }

  const { data, error } = await supabase
    .from("evidence")
    .select(
      "id, case_id, evidence_number, title, description, type, status, created_by, created_at, updated_at, creator:profiles!evidence_created_by_fkey(id, full_name), document_versions(id, version, file_name, mime_type, file_size_bytes, sha256, uploaded_at)",
    )
    .eq("case_id", caseId)
    .order("created_at", { ascending: false });

  if (error) {
    return NextResponse.json(
      { error: "Failed to load evidence" },
      { status: 500 },
    );
  }

  const evidence = (data ?? []).map((row) =>
    serializeEvidenceListItem(row as unknown as EvidenceListRawRow),
  );
  return NextResponse.json({ evidence }, { status: 200 });
}

export async function POST(
  request: Request,
  ctx: RouteContext<"/api/cases/[id]/evidence">,
) {
  const { id: caseId } = await ctx.params;

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

  // 3. validate — case id, multipart shape, and every client-supplied value.
  //    Authorization data (actor, case role, case ownership) is never taken
  //    from the request. The hash is computed here, from the exact bytes.
  if (!UUID_PATTERN.test(caseId)) {
    return NextResponse.json({ error: "Invalid case id" }, { status: 400 });
  }

  let form: FormData;
  try {
    form = await request.formData();
  } catch {
    return NextResponse.json(
      { error: "Invalid multipart form data" },
      { status: 400 },
    );
  }

  const uploaded = form.get("file");
  if (!(uploaded instanceof File) || uploaded.size === 0) {
    return NextResponse.json(
      { error: "file must be a non-empty upload" },
      { status: 400 },
    );
  }
  if (uploaded.size > MAX_EVIDENCE_FILE_SIZE_BYTES) {
    return NextResponse.json(
      { error: "File exceeds the 50 MiB limit" },
      { status: 400 },
    );
  }

  const fileName = sanitizeFileName(uploaded.name || "");
  if (!fileName) {
    return NextResponse.json(
      { error: "file must have a valid name" },
      { status: 400 },
    );
  }

  const mimeType = (uploaded.type || "").toLowerCase();
  if (!isAllowedEvidenceMime(mimeType)) {
    return NextResponse.json(
      {
        error: `mime type must be one of ${ALLOWED_EVIDENCE_MIME_TYPES.join(", ")}`,
      },
      { status: 400 },
    );
  }

  const title = formText(form, "title", MAX_TITLE_LENGTH);
  if (!title) {
    return NextResponse.json(
      { error: "title is required" },
      { status: 400 },
    );
  }
  const description = formText(form, "description", MAX_DESCRIPTION_LENGTH);
  const notes = formText(form, "notes", MAX_NOTES_LENGTH);

  const typeValue = formText(form, "type", 20) ?? "document";
  if (!isEvidenceType(typeValue)) {
    return NextResponse.json(
      { error: "type must be one of document, image, video, audio, other" },
      { status: 400 },
    );
  }

  // Hash and magic-check the exact bytes received. A declared type that does
  // not match the content is rejected before anything is stored.
  const bytes = new Uint8Array(await uploaded.arrayBuffer());
  if (!bytesMatchMimeType(bytes, mimeType)) {
    return NextResponse.json(
      { error: "File content does not match its declared type" },
      { status: 400 },
    );
  }
  const sha256 = await sha256Hex(bytes);

  // Opaque storage key: {case_id}/{evidence_id}/{document_version_id}, never
  // the filename. The ids are generated here only so the key can be built
  // before upload; the RPC re-derives the actor and re-checks every
  // authorization, and the DB enforces the key/ids consistency.
  const evidenceId = crypto.randomUUID();
  const documentVersionId = crypto.randomUUID();
  const storageKey = `${caseId}/${evidenceId}/${documentVersionId}`;

  // 4a. business operation (object) — upload FIRST, through the authenticated
  //     server client, so the case-scoped storage RLS policies apply. If this
  //     fails, no database rows exist yet.
  const { error: uploadError } = await supabase.storage
    .from(EVIDENCE_BUCKET)
    .upload(storageKey, bytes, {
      contentType: mimeType,
      cacheControl: "3600",
      upsert: false,
    });

  if (uploadError) {
    // Structured server-side log of the actual Storage error (name, message,
    // HTTP status, storage error code). Storage RLS rejections surface here
    // as 403 — e.g. a plain member/viewer of the case, whose insert the
    // evidence_files_insert_lead_or_investigator policy denies. The response
    // itself stays generic and never echoes Supabase internals.
    console.error(
      JSON.stringify({
        event: "evidence_object_upload_failed",
        case_id: caseId,
        bucket: EVIDENCE_BUCKET,
        storage: uploadError.toJSON(),
      }),
    );

    if (uploadError.status === 403 || uploadError.statusCode === "403") {
      return NextResponse.json(
        { error: "You are not allowed to upload files to this case" },
        { status: 403 },
      );
    }
    return NextResponse.json(
      { error: "Failed to upload file" },
      { status: 500 },
    );
  }

  // 4b. business operation + audit (database) — one atomic SECURITY DEFINER
  //     transaction creating the evidence row, document version 1, the
  //     initial chain_of_custody entry, and the audit_logs record.
  const { data, error } = await supabase.rpc("create_evidence", {
    p_case_id: caseId,
    p_evidence_id: evidenceId,
    p_document_version_id: documentVersionId,
    p_title: title,
    p_description: description ?? null,
    p_type: typeValue,
    p_file_name: fileName,
    p_mime_type: mimeType,
    p_file_size_bytes: uploaded.size,
    p_sha256: sha256,
    p_storage_key: storageKey,
    p_notes: notes ?? null,
    p_confirmation_token: await evidenceRegistrationToken(),
  });

  if (error) {
    // The object now exists without any database rows. Cleanup is delegated to
    // the server-controlled delete_evidence_object() RPC; the storage API
    // DELETE path is closed (see
    // supabase/migrations/20260920000000_harden_storage_delete.sql). Because no
    // document_versions row was created, that RPC rejects the orphan key by
    // design, so the object simply remains an immutable leftover. A leftover
    // object is harmless; a DB row without its object is not. Failures are
    // logged, never surfaced as a success.
    const { error: cleanupError } = await supabase.rpc(
      "delete_evidence_object",
      { p_storage_key: storageKey },
    );
    if (cleanupError) {
      console.error(
        JSON.stringify({
          event: "evidence_orphan_cleanup_rejected",
          case_id: caseId,
          bucket: EVIDENCE_BUCKET,
        }),
      );
    }
    return NextResponse.json(
      { error: rpcMessage(error.message) },
      { status: rpcStatus(error.message) },
    );
  }

  // 4c. produce the blockchain anchor's PENDING intent, synchronously inside
  //     this request and BEFORE the 201 returns. This is a plain DB-only RPC
  //     (Ethereum is never contacted here): it commits the durable fact that
  //     this version is to be anchored, so "pending" cannot be lost if the
  //     process dies after the response. NO work is ever fired in the
  //     background after the response — serverless runtimes may tear down the
  //     context (and with it the request-scoped session) the moment the
//     response is sent, so deferred work must not be relied upon. On-chain
//     submission happens later through a separate, retriable trigger
//     (POST /api/cases/[id]/evidence/[evidenceId]/anchor).
  const persistedVersionId = persistedVersionIdFromResponse(data);

  let anchorField: Record<string, unknown> | undefined;
  if (persistedVersionId) {
    const pendingAnchor = await requestPendingAnchor(
      supabase,
      persistedVersionId,
    );
    if (pendingAnchor) {
      // The anchor id (and its 'pending' state) came from the RPC response,
      // i.e. from the actually committed row, never from the request.
      anchorField =
        pendingAnchor.status === "pending"
          ? {
              status: "pending",
              anchor_id: pendingAnchor.anchorId,
              document_version_id: persistedVersionId,
            }
          : {
              status: "already_anchored",
              document_version_id: persistedVersionId,
            };
    }
  }

  // Convention: POST endpoints return the created row(s). Both the evidence
  // record and its first version are returned (create_evidence returns a
  // single jsonb containing both); when a pending anchor row was committed,
  // its honest DB state is reported — never "scheduled", since nothing was
  // deferred. If the anchor row could not be created, the evidence is still
  // valid and the anchor is simply not reported (a later trigger creates it).
  const body = anchorField ? { ...data, anchor: anchorField } : data;
  return NextResponse.json(body, { status: 201 });
}

// RPC exceptions are exact, known codes; the includes-style checks follow the
// existing route convention.
function rpcStatus(message: string): number {
  if (message.includes("not_authenticated")) return 401;
  if (message.includes("profile_not_found")) return 403;
  if (message.includes("case_not_found")) return 404;
  if (message.includes("not_authorized_to_upload")) return 403;
  if (message.includes("case_not_open")) return 409;
  if (message.includes("evidence_type_not_allowed")) return 400;
  if (message.includes("invalid_file_metadata")) return 400;
  if (message.includes("storage_key_mismatch")) return 400;
  if (message.includes("storage_object_not_found")) return 404;
  if (message.includes("invalid_confirmation")) return 500;
  return 500;
}

function rpcMessage(message: string): string {
  if (message.includes("not_authenticated")) return "Unauthorized";
  if (message.includes("profile_not_found")) return "Forbidden";
  if (message.includes("case_not_found")) return "Case not found";
  if (message.includes("not_authorized_to_upload")) {
    return "Only the case lead or an investigator can upload evidence";
  }
  if (message.includes("case_not_open")) {
    return "Evidence can only be added to draft or active cases";
  }
  if (message.includes("evidence_type_not_allowed")) {
    return "type must be one of document, image, video, audio, other";
  }
  if (message.includes("invalid_file_metadata")) return "Invalid file metadata";
  if (message.includes("storage_key_mismatch")) {
    return "Storage key does not match the evidence identifiers";
  }
  if (message.includes("storage_object_not_found")) {
    return "The uploaded file could not be verified in secure storage";
  }
  if (message.includes("invalid_confirmation")) {
    return "Evidence hash registration configuration error";
  }
  return "Failed to create evidence";
}
