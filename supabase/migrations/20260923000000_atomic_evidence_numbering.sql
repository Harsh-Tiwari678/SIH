-- =============================================================================
-- SIH26190 Secure Evidence — L2: atomic evidence numbering
--
-- AUDIT FINDING
--   create_evidence() allocated the per-case next evidence number as
--   count(existing rows) + 1 with a bounded retry on the UNIQUE(case_id,
--   evidence_number) violation. Under concurrency two transactions can
--   compute the same candidate, and the five-attempt retry cap could then
--   fail the whole upload or leave the allocation dependent on lock-churn
--   races. Allocation was NOT atomic: the number was derived from a
--   speculative count, not from a serialized allocation point.
--
-- FIX (this migration)
--   Same-case evidence creation is serialized by a transaction-scoped
--   advisory lock keyed on the case uuid, taken BEFORE the count is read.
--   PostgreSQL-native, per-case (separate cases never contend), and released
--   at commit (the RPC is a single transaction). The count therefore reflects
--   every committed predecessor at allocation time, numbers stay gap-free and
--   sequential, and the retry-on-unique-violation loop is no longer needed —
--   it is removed rather than "catch a unique violation and retry blindly".
--   The UNIQUE(case_id, evidence_number) constraint REMAINS as the ultimate
--   backstop against any out-of-band writer, and document_versions /
--   custody / audit behavior is byte-for-byte preserved.
--
-- WHY THE LOCK IS SAFE
--   * pg_advisory_xact_lock is session/transaction-scoped: the holder is the
--     in-progress create_evidence transaction, and the lock dies with it
--     (no leaked-key or deadlock-with-abort window).
--   * A second same-case creator waits for the first transaction to finish
--     (commit or abort) before reading the count, so it can never compute a
--     duplicate or a gap against an in-flight peer.
--   * Different cases use different keys: cross-case creation is fully
--     parallel (L2-T4).
--   * The lock is intentionally NOT the evidence row or table lock — no
--     serialization of unrelated same-case reads.
--   * The discriminator constant 766442187 + hashtextextended(case_id) makes
--     the key namespace collision-resistant against any other advisory-lock
--     user in the application.
-- =============================================================================

create or replace function public.create_evidence(
    p_case_id              uuid,
    p_evidence_id          uuid,
    p_document_version_id  uuid,
    p_title                text,
    p_description          text,
    p_type                 text,
    p_file_name            text,
    p_mime_type            text,
    p_file_size_bytes      bigint,
    p_sha256               text,
    p_storage_key          text,
    p_notes                text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
    v_actor   uuid := auth.uid();
    v_case    public.cases;
    v_evidence public.evidence;
    v_version public.document_versions;
    v_seq     integer;
begin
    -- authenticate: derive the actor from the session, never from arguments.
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;

    -- authorize: the actor must have an application profile.
    if not exists (select 1 from public.profiles p where p.id = v_actor) then
        raise exception 'profile_not_found';
    end if;

    -- HARDENING (M1-era): use org-aware case visibility. The old check
    -- (c.created_by = v_actor OR explicit case_members) let stale members
    -- through. is_case_member enforces the org boundary.
    select c.*
    into v_case
    from public.cases c
    where c.id = p_case_id
      and public.is_case_member(c.id);
    if not found then
        raise exception 'case_not_found';
    end if;

    -- authorize: only the case lead or an investigator may upload evidence.
    -- The is_case_member check above ensures the actor is an org member;
    -- this check ensures the actor has the explicit role.
    if not exists (
        select 1
        from public.case_members m
        where m.case_id = p_case_id
          and m.profile_id = v_actor
          and m.role_in_case in ('lead', 'investigator')
    ) then
        raise exception 'not_authorized_to_upload';
    end if;

    -- business rule: evidence may only be added to open cases.
    if v_case.status not in ('draft', 'active') then
        raise exception 'case_not_open';
    end if;

    -- validate: metadata handed over by the route handler (which already
    -- enforced size/MIME/filename rules before uploading the object). The DB
    -- re-asserts the invariants so no write path can bypass them.
    if p_evidence_id is null or p_document_version_id is null then
        raise exception 'invalid_file_metadata';
    end if;
    if p_title is null or btrim(p_title) = '' or char_length(p_title) > 500 then
        raise exception 'invalid_file_metadata';
    end if;
    if p_description is not null and char_length(p_description) > 5000 then
        raise exception 'invalid_file_metadata';
    end if;
    if p_type not in ('document', 'image', 'video', 'audio', 'other') then
        raise exception 'evidence_type_not_allowed';
    end if;
    if p_file_name is null or btrim(p_file_name) = '' or char_length(p_file_name) > 255 then
        raise exception 'invalid_file_metadata';
    end if;
    if p_mime_type is null or btrim(p_mime_type) = '' then
        raise exception 'invalid_file_metadata';
    end if;
    if p_file_size_bytes is null or p_file_size_bytes < 1 then
        raise exception 'invalid_file_metadata';
    end if;
    if p_sha256 !~ '^[0-9a-f]{64}$' then
        raise exception 'invalid_file_metadata';
    end if;

    -- validate: the storage key must be exactly the opaque key for THIS case,
    -- evidence and version. The DB can never point at a foreign object.
    if p_storage_key is distinct from
       p_case_id || '/' || p_evidence_id || '/' || p_document_version_id
    then
        raise exception 'storage_key_mismatch';
    end if;

    -- business operation: allocate the per-case sequential evidence number
    -- ATOMICALLY (L2). The transaction-scoped advisory lock serializes
    -- same-case creators before the count is read, so the count always
    -- reflects every committed predecessor and the number is gap-free.
    -- Evidence rows are never deleted, so the count remains a valid base.
    perform pg_advisory_xact_lock(
        (766442187)::int,
        mod(hashtextextended(p_case_id::text, 0), 2147483647)::int
    );
    v_seq := (select count(*) from public.evidence where case_id = p_case_id) + 1;
    insert into public.evidence (
        id, case_id, evidence_number, title, description, type, status, created_by
    ) values (
        p_evidence_id,
        p_case_id,
        'EV-' || lpad(v_seq::text, 3, '0'),
        btrim(p_title),
        p_description,
        p_type,
        'received',
        v_actor
    )
    returning * into v_evidence;

    -- business operation: the immutable first file version.
    insert into public.document_versions (
        id, evidence_id, version, prev_version_id, file_name, mime_type,
        file_size_bytes, sha256, storage_key, uploaded_by, notes
    ) values (
        p_document_version_id,
        v_evidence.id,
        1,
        null,
        p_file_name,
        p_mime_type,
        p_file_size_bytes,
        p_sha256,
        p_storage_key,
        v_actor,
        p_notes
    )
    returning * into v_version;

    -- business operation: initial possession entry. The uploader takes
    -- custody; the origin (from_profile_id) is outside the system.
    insert into public.chain_of_custody (
        evidence_id, document_version_id, action, actor_id,
        from_profile_id, to_profile_id, notes
    ) values (
        v_evidence.id,
        v_version.id,
        'received',
        v_actor,
        null,
        v_actor,
        p_notes
    );

    -- audit: record the events in the same transaction as the inserts.
    -- audit_logs has no direct INSERT policy; only SECURITY DEFINER system
    -- paths may write it. Possession itself is recorded above in
    -- chain_of_custody — the two concepts stay separate.

    -- the SHA-256 fingerprint was just computed and bound to the version.
    insert into public.audit_logs (actor_id, action, entity_type, entity_id, meta)
    values (
        v_actor,
        'evidence.hash_generated',
        'evidence',
        v_evidence.id,
        jsonb_build_object(
            'case_id', v_case.id,
            'case_number', v_case.case_number,
            'document_version_id', v_version.id,
            'sha256', v_version.sha256
        )
    );

    -- custody was taken by the uploader (mirrors chain_of_custody 'received').
    insert into public.audit_logs (actor_id, action, entity_type, entity_id, meta)
    values (
        v_actor,
        'evidence.custody_received',
        'evidence',
        v_evidence.id,
        jsonb_build_object(
            'case_id', v_case.id,
            'case_number', v_case.case_number,
            'evidence_id', v_evidence.id,
            'evidence_number', v_evidence.evidence_number,
            'title', v_evidence.title,
            'document_version_id', v_version.id,
            'file_name', v_version.file_name
        )
    );

    insert into public.audit_logs (actor_id, action, entity_type, entity_id, after, meta)
    values (
        v_actor,
        'evidence.created',
        'evidence',
        v_evidence.id,
        to_jsonb(v_evidence),
        jsonb_build_object(
            'case_id', v_case.id,
            'case_number', v_case.case_number,
            'evidence_id', v_evidence.id,
            'evidence_number', v_evidence.evidence_number,
            'title', v_evidence.title,
            'document_version_id', v_version.id,
            'file_name', v_version.file_name,
            'mime_type', v_version.mime_type,
            'file_size_bytes', v_version.file_size_bytes,
            'sha256', v_version.sha256,
            'storage_key', v_version.storage_key
        )
    );

    return jsonb_build_object(
        'evidence', to_jsonb(v_evidence),
        'document_version', to_jsonb(v_version)
    );
end;
$function$;

alter function public.create_evidence(
    uuid, uuid, uuid, text, text, text, text, text, bigint, text, text, text
) owner to postgres;
revoke execute on function public.create_evidence(
    uuid, uuid, uuid, text, text, text, text, text, bigint, text, text, text
) from public, anon;
grant execute on function public.create_evidence(
    uuid, uuid, uuid, text, text, text, text, text, bigint, text, text, text
) to authenticated;