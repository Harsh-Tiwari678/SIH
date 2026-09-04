-- =============================================================================
-- SIH26190 Secure Evidence — evidence creation with initial file upload
--
-- Adds the private evidence-files storage bucket (with server-enforced size
-- and MIME limits) plus case-scoped storage policies, and a SECURITY DEFINER
-- RPC that atomically creates the four rows an upload produces:
--
--   1. evidence            — the evidentiary record (status 'received')
--   2. document_versions   — version 1 of the file (prev_version_id null)
--   3. chain_of_custody    — the initial 'received' possession entry
--   4. audit_logs          — the 'evidence.created' operational audit event
--
-- Why an RPC (and not direct client INSERTs through RLS):
--   * audit_logs has NO INSERT policy by design; only trusted system paths may
--     write it. The four rows must also be atomic — a partial failure would
--     leave evidence with no version, no custody trail, or no audit record.
--   * The RPC runs as its owner (postgres) and re-implements every
--     authorization check internally; SECURITY DEFINER bypasses RLS, so no
--     check may be assumed from the policies. The RLS insert policies on
--     evidence, document_versions and chain_of_custody remain in force for
--     every direct client path (defense in depth).
--
-- Ordering contract with the caller (app/api/cases/[id]/evidence/route.ts):
--   the file bytes are uploaded to object storage FIRST, under the opaque key
--   {case_id}/{evidence_id}/{document_version_id}, and this RPC is called
--   SECOND. A DB row therefore never exists without its object. If the RPC
--   fails, the caller best-effort deletes the orphaned object; an object
--   without rows is harmless, a row without an object is not.
--
-- Identity: p_evidence_id and p_document_version_id are generated app-side
-- (crypto.randomUUID) purely so the storage key can be built before upload.
-- They carry no authorization meaning: created_by/uploaded_by/actor_id are
-- ALWAYS derived from auth.uid() inside this function, never from arguments.
--
-- Storage policy notes:
--   * storage.objects policies scope access by the FIRST path segment
--     (the case uuid) using the existing is_case_member / case_role helpers,
--     so only members of the owning case can read objects and only lead /
--     investigator can write them. No owner-column checks: the only real
--     write path is this app, and avoiding the deprecated owner column keeps
--     the policies version-stable.
--   * The bucket is private (public = false); no anon access to storage.
--   * file_size_limit and allowed_mime_types on the bucket are enforced by
--     the storage service itself, independent of the application's own checks.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1) Private storage bucket with server-enforced limits
-- -----------------------------------------------------------------------------
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
    'evidence-files',
    'evidence-files',
    false,
    52428800, -- 50 MiB
    array[
        'application/pdf',
        'image/png',
        'image/jpeg',
        'video/mp4',
        'audio/mpeg',
        'text/plain'
    ]
)
on conflict (id) do nothing;

-- -----------------------------------------------------------------------------
-- 2) Case-scoped storage policies (storage.objects already has RLS enabled)
--
-- The first path segment must be a uuid before it is cast — a non-uuid name
-- evaluates to false rather than raising a cast error.
-- -----------------------------------------------------------------------------

drop policy if exists "evidence_files_select_case_members" on storage.objects;
create policy "evidence_files_select_case_members"
on storage.objects
for select
to authenticated
using (
    bucket_id = 'evidence-files'
    and name ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/'
    and public.is_case_member((split_part(name, '/', 1))::uuid)
);

drop policy if exists "evidence_files_insert_lead_or_investigator" on storage.objects;
create policy "evidence_files_insert_lead_or_investigator"
on storage.objects
for insert
to authenticated
with check (
    bucket_id = 'evidence-files'
    and name ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/'
    and public.case_role((split_part(name, '/', 1))::uuid) in ('lead', 'investigator')
);

-- DELETE exists only so the caller can best-effort clean up an orphaned
-- object when the database RPC fails after a successful upload. It is scoped
-- to lead/investigator of the owning case — the same roles that may upload.
drop policy if exists "evidence_files_delete_lead_or_investigator" on storage.objects;
create policy "evidence_files_delete_lead_or_investigator"
on storage.objects
for delete
to authenticated
using (
    bucket_id = 'evidence-files'
    and name ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/'
    and public.case_role((split_part(name, '/', 1))::uuid) in ('lead', 'investigator')
);

-- UPDATE: no policy -> denied. Objects are immutable once uploaded.

-- -----------------------------------------------------------------------------
-- 3) SECURITY DEFINER RPC: atomic evidence + version + custody + audit
-- -----------------------------------------------------------------------------
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
    v_done    boolean := false;
begin
    -- authenticate: derive the actor from the session, never from arguments.
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;

    -- authorize: the actor must have an application profile.
    if not exists (select 1 from public.profiles p where p.id = v_actor) then
        raise exception 'profile_not_found';
    end if;

    -- authorize (visibility): the case must exist AND be visible to the actor
    -- (creator or member), matching cases_select_creator_or_member RLS, so an
    -- inaccessible case is reported identically to a nonexistent one.
    select c.*
    into v_case
    from public.cases c
    where c.id = p_case_id
      and (
          c.created_by = v_actor
          or exists (
              select 1
              from public.case_members m
              where m.case_id = c.id
                and m.profile_id = v_actor
          )
      );
    if not found then
        raise exception 'case_not_found';
    end if;

    -- authorize: only the case lead or an investigator may upload evidence.
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

    -- business operation: allocate the per-case sequential evidence number.
    -- Evidence rows are never deleted, so count(*) + 1 with a retry on the
    -- unique (case_id, evidence_number) constraint converges under races.
    v_seq := (select count(*) from public.evidence where case_id = p_case_id) + 1;
    for attempt in 1 .. 5 loop
        begin
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
            v_done := true;
            exit;
        exception when unique_violation then
            v_seq := v_seq + 1;
        end;
    end loop;
    if not v_done then
        raise exception 'evidence_number_allocation_failed';
    end if;

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

    -- audit: record the event in the same transaction as the inserts.
    -- audit_logs has no direct INSERT policy; only SECURITY DEFINER system
    -- paths may write it. Possession itself is recorded above in
    -- chain_of_custody — the two concepts stay separate.
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

-- Owned by the trusted role; guarantees the RLS bypass runs as postgres, not a
-- lower-privilege owner, matching the pattern of the existing helpers.
alter function public.create_evidence(
    uuid, uuid, uuid, text, text, text, text, text, bigint, text, text, text
) owner to postgres;

-- The RPC is callable only by authenticated users, never anon/PUBLIC.
revoke execute on function public.create_evidence(
    uuid, uuid, uuid, text, text, text, text, text, bigint, text, text, text
) from public;
revoke execute on function public.create_evidence(
    uuid, uuid, uuid, text, text, text, text, text, bigint, text, text, text
) from anon;

grant execute on function public.create_evidence(
    uuid, uuid, uuid, text, text, text, text, text, bigint, text, text, text
) to authenticated;
