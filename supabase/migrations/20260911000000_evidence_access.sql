-- =============================================================================
-- SIH26190 Secure Evidence — evidence file access (preview / download)
--
-- Secure preview and download of evidence files, built on two SECURITY
-- DEFINER RPCs following the existing helpers' pattern (search_path = '',
-- owner postgres, EXECUTE only for authenticated):
--
--   1) resolve_evidence_access(p_evidence_id, p_document_version_id, p_mode)
--      Returns the server-side file access intent (mime type, name, size and
--      -- critically -- the storage key) for a given version, defaulting to
--      the LATEST version when no version id is given. The caller route uses
--      this to mint a short-lived signed URL. The returned jsonb is consumed
--      only by the route handler; storage_key NEVER reaches the client.
--
--   2) record_evidence_access(p_document_version_id, p_mode)
--      Writes the operational audit event 'evidence.accessed' with the access
--      mode ('preview' | 'download') in meta. Preview and download share one
--      event; the mode distinguishes them. The audit row records WHO accessed
--      WHICH version WHEN; it never contains file contents, storage keys or
--      signed URLs.
--
-- Authorization model (the same boundary every read path uses):
--   * reads are gated by membership on the evidence's case (the actor must
--     be a member / creator). An inaccessible evidence resolves identically
--     to a nonexistent one ('evidence_not_found') so existence never leaks.
--   * a version id that does not belong to the evidence is indistinguishable
--     from a nonexistent version ('document_version_not_found'), so a caller
--     cannot probe other evidence through this endpoint.
--   * files in closed cases stay readable by members, matching the existing
--     evidence SELECT RLS; access restrictions by case status are a separate
--     product decision and are not fabricated here.
--
-- Defense in depth below the database layer: the route mints the signed URL
-- through the authenticated session client, so Supabase Storage re-checks the
-- storage.objects SELECT RLS policy for the exact object before it issues the
-- token. A signed URL can therefore only ever be created for an object the
-- caller is already allowed to read.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1) resolve_evidence_access — authorize + resolve the file access intent
-- -----------------------------------------------------------------------------
create or replace function public.resolve_evidence_access(
    p_evidence_id          uuid,
    p_document_version_id  uuid,
    p_mode                 text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
    v_actor    uuid := auth.uid();
    v_evidence public.evidence;
    v_version  public.document_versions;
begin
    -- authenticate: derive the actor from the session, never from arguments.
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;

    -- authorize: the actor must have an application profile.
    if not exists (select 1 from public.profiles p where p.id = v_actor) then
        raise exception 'profile_not_found';
    end if;

    -- validate: the access mode is part of a fixed vocabulary.
    if p_mode not in ('preview', 'download') then
        raise exception 'invalid_mode';
    end if;

    -- authorize (visibility): the evidence must exist AND its case must be
    -- visible to the actor (creator or member), matching
    -- cases_select_creator_or_member RLS, so an inaccessible evidence is
    -- reported identically to a nonexistent one.
    select e.* into v_evidence
    from public.evidence e
    where e.id = p_evidence_id
      and (
          (select c.created_by from public.cases c where c.id = e.case_id) = v_actor
          or public.is_case_member(e.case_id)
      );
    if not found then
        raise exception 'evidence_not_found';
    end if;

    -- resolve the version: the requested one, or the latest by default.
    if p_document_version_id is null then
        select dv.* into v_version
        from public.document_versions dv
        where dv.evidence_id = v_evidence.id
        order by dv.version desc
        limit 1;
    else
        select dv.* into v_version
        from public.document_versions dv
        where dv.id = p_document_version_id
          and dv.evidence_id = v_evidence.id;
    end if;
    if not found then
        -- An unknown version, or a version of ANOTHER evidence: identical.
        raise exception 'document_version_not_found';
    end if;

    -- Return the server-only access intent. storage_key stays on the server;
    -- the caller turns it into a short-lived signed URL and the client sees
    -- only the URL plus display metadata. No file bytes, no audit, no writes.
    return jsonb_build_object(
        'case_id', v_evidence.case_id,
        'evidence_id', v_evidence.id,
        'document_version_id', v_version.id,
        'version', v_version.version,
        'file_name', v_version.file_name,
        'mime_type', v_version.mime_type,
        'file_size_bytes', v_version.file_size_bytes,
        'storage_key', v_version.storage_key
    );
end;
$function$;

alter function public.resolve_evidence_access(uuid, uuid, text) owner to postgres;

revoke execute on function public.resolve_evidence_access(uuid, uuid, text) from public;
revoke execute on function public.resolve_evidence_access(uuid, uuid, text) from anon;

grant execute on function public.resolve_evidence_access(uuid, uuid, text) to authenticated;

-- -----------------------------------------------------------------------------
-- 2) record_evidence_access — operational audit for preview / download
-- -----------------------------------------------------------------------------
create or replace function public.record_evidence_access(
    p_document_version_id  uuid,
    p_mode                 text
)
returns void
language plpgsql
security definer
set search_path = ''
as $function$
declare
    v_actor    uuid := auth.uid();
    v_version  public.document_versions;
    v_evidence public.evidence;
    v_case     public.cases;
begin
    -- authenticate / authorize.
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;
    if not exists (select 1 from public.profiles p where p.id = v_actor) then
        raise exception 'profile_not_found';
    end if;

    -- validate: the access mode is part of a fixed vocabulary.
    if p_mode not in ('preview', 'download') then
        raise exception 'invalid_mode';
    end if;

    -- validate / derive: the version, its evidence and its case.
    select dv.* into v_version from public.document_versions dv where dv.id = p_document_version_id;
    if not found then
        raise exception 'document_version_not_found';
    end if;
    select e.* into v_evidence from public.evidence e where e.id = v_version.evidence_id;
    if not found then
        raise exception 'evidence_not_found';
    end if;
    select c.* into v_case from public.cases c where c.id = v_evidence.case_id;
    if not found then
        raise exception 'case_not_found';
    end if;

    -- authorize: only a member of the version's case may access its file
    -- (same boundary as the read path).
    if not public.is_case_member(v_case.id) then
        raise exception 'not_case_member';
    end if;

    -- audit: record who accessed which version, when, in which mode. The meta
    -- holds identifiers and display metadata only — never file contents,
    -- storage keys or signed URLs. audit_logs has no direct INSERT policy;
    -- only SECURITY DEFINER system paths may write it.
    insert into public.audit_logs (actor_id, action, entity_type, entity_id, meta)
    values (
        v_actor,
        'evidence.accessed',
        'document_version',
        v_version.id,
        jsonb_build_object(
            'case_id', v_case.id,
            'case_number', v_case.case_number,
            'evidence_id', v_evidence.id,
            'evidence_number', v_evidence.evidence_number,
            'title', v_evidence.title,
            'document_version_id', v_version.id,
            'file_name', v_version.file_name,
            'mime_type', v_version.mime_type,
            'mode', p_mode
        )
    );
end;
$function$;

alter function public.record_evidence_access(uuid, text) owner to postgres;

revoke execute on function public.record_evidence_access(uuid, text) from public;
revoke execute on function public.record_evidence_access(uuid, text) from anon;

grant execute on function public.record_evidence_access(uuid, text) to authenticated;