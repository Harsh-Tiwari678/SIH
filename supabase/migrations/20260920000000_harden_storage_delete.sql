-- =============================================================================
-- SIH26190 Secure Evidence — H1: evidence file destruction / storage DELETE
-- hardening
--
-- Vulnerability: evidence files could be deleted through the storage API by a
-- user whose organization membership was REVOKED but whose case_members row
-- survived (the orphan label "remove an evidence object from any case where
-- the case_members row still claims lead/investigator"). The OLD coverage:
--
--   * 20260903000000_create_evidence.sql  adds the storage.objects DELETE
--     policy "evidence_files_delete_lead_or_investigator", which authorizes
--     purely from the FIRST path segment (the case uuid) via case_role() —
--     an authorization path that ignores organization membership entirely.
--   * 20260911000000_evidence_access.sql  grants creator-only read access in
--     resolve_evidence_access via `created_by = actor` even when the creator
--     is no longer a member of the case's organization.
--
-- This migration removes BOTH attack surfaces and replaces direct object
-- deletion with a single, server-controlled cleanup RPC:
--
--   1) DROP the storage.objects DELETE policy. No client (storage API or
--      direct SQL) may delete evidence objects any more. The table-level
--      DELETE grant on storage.objects is also revoked from
--      public / anon / authenticated, so a re-added policy alone could never
--      restore the capability (defense in depth).
--   2) The storage service (service_role / storage-admins) keeps its own
--      DELETE capability for bucket maintenance; the application never
--      delegates it to the browser.
--   3) NEW public.delete_evidence_object(p_storage_key) — the ONLY deletion
--      path for evidence objects. SECURITY DEFINER (owner postgres), gated on
--      CURRENT organization membership, case role on the REAL case row, an
--      OPEN case, and a real document_versions row that claims exactly this
--      key. It performs the object delete and writes the audit event. The
--      legacy best-effort orphan cleanup in the POST route now calls this RPC
--      instead of the storage API; orphaned objects become immutable leftovers
--      and are logged (delete of a key no row claims is REJECTED on purpose).
--   4) resolve_evidence_access loses its `created_by = actor` branch. The
--      creator of a case is ALWAYS an explicit 'lead' case_member (create_case
--      guarantees it), so org-aware is_case_member() covers every legitimate
--      creator; the stale-membership creator branch is gone.
--
-- No evidence, version or case DB rows are ever deleted; only the storage
-- object is removed, with full audit coverage.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1) No DELETE policy on storage.objects for clients
-- -----------------------------------------------------------------------------
drop policy if exists "evidence_files_delete_lead_or_investigator"
    on storage.objects;

-- Defense in depth: even if a DELETE policy were re-added later, an
-- authenticated/anon role would still lack the table-level DELETE privilege.
-- The storage service operates as service_role and is unaffected. Table owner
-- (postgres) is unaffected, which is what the SECURITY DEFINER RPC below uses.
revoke delete on storage.objects from public;
revoke delete on storage.objects from anon;
revoke delete on storage.objects from authenticated;

-- -----------------------------------------------------------------------------
-- 2) resolve_evidence_access — org-aware only (creator branch removed)
--
-- CREATE OR REPLACE preserves existing ACLs; they are re-asserted anyway.
-- The former visibility predicate was:
--
--   ( (select c.created_by from public.cases c where c.id = e.case_id) = v_actor
--     or public.is_case_member(e.case_id) )
--
-- The creator-only alternative let a user with a STALE case_members row and
-- no organization membership still resolve/download evidence files. The
-- creator is always a lead member (create_case guarantees it), so the org-aware
-- is_case_member() alone is the entire boundary.
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
    -- org-visible to the actor (member of the case's organization, or an org
    -- admin of it). An inaccessible evidence is reported identically to a
    -- nonexistent one ('evidence_not_found') so existence never leaks. There
    -- is deliberately NO creator-only bypass: stale case_members rows must
    -- never grant access after organization membership is revoked.
    select e.* into v_evidence
    from public.evidence e
    where e.id = p_evidence_id
      and public.is_case_member(e.case_id);
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
-- 3) delete_evidence_object — the ONLY evidence-object deletion path
--
-- A single, fully-validated SECURITY DEFINER RPC. The checks below are order
-- aware (authenticate, authorize, validate, operate, audit) and no check is
-- optional or skippable by the caller:
--
--   * not_authenticated / profile_not_found  — actor must be a real profile.
--   * invalid_storage_key                    — exact {case}/{evidence}/{version}
--                                              uuid/key shape.
--   * object_not_found_in_document_versions  — the key must be claimed by a
--                                              REAL document_versions row.
--                                              Orphaned objects (no DB row)
--                                              are immutable leftovers.
--   * storage_key_case_mismatch              — the case segment of the key must
--                                              match the evidence's real case.
--                                              Never trust the text prefix alone;
--                                              it only indexes real rows below.
--   * case_not_found / not_org_member        — CURRENT organization membership
--                                              only. Stale case_members rows
--                                              grant nothing.
--   * not_authorized_to_delete               — 'lead' / 'investigator' role on
--                                              the REAL case, as a current
--                                              member.
--   * case_not_open                          — cleanup only in 'draft'/'active'
--                                              cases.
-- The storage object itself is removed under the same mechanism the storage
-- service uses (local session GUC storage.allow_delete_query = true), scoped
-- to this transaction only. The audit event 'evidence.object_deleted' is the
-- durable record; audit_logs has no direct INSERT policy.
-- -----------------------------------------------------------------------------
create or replace function public.delete_evidence_object(
    p_storage_key text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
    v_actor        uuid := auth.uid();
    v_case_id      uuid;
    v_evidence_id  uuid;
    v_version_id   uuid;
    v_version      public.document_versions;
    v_evidence     public.evidence;
    v_case         public.cases;
    v_deleted      bigint;
begin
    -- authenticate / authorize (actor).
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;
    if not exists (select 1 from public.profiles p where p.id = v_actor) then
        raise exception 'profile_not_found';
    end if;

    -- validate: the key must be exactly {case}/{evidence}/{version} uuid-uuids.
    -- Authorization is NEVER derived from the textual prefix alone; these
    -- identifiers only index the real rows validated below.
    if p_storage_key !~
        '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' then
        raise exception 'invalid_storage_key';
    end if;
    v_case_id     := (split_part(p_storage_key, '/', 1))::uuid;
    v_evidence_id := (split_part(p_storage_key, '/', 2))::uuid;
    v_version_id  := (split_part(p_storage_key, '/', 3))::uuid;

    -- validate: the version must be a REAL document_versions row, owned by the
    -- evidence named by the key, that claims exactly this storage key. A key
    -- no row claims can never be cleaned up.
    select dv.* into v_version
    from public.document_versions dv
    where dv.id = v_version_id
      and dv.evidence_id = v_evidence_id
      and dv.storage_key = p_storage_key;
    if not found then
        raise exception 'object_not_found_in_document_versions';
    end if;

    -- validate: the evidence must exist and belong to the case named by the
    -- key. A key that claims a case different from its version's real case
    -- fails here (cross-case key forgery).
    select e.* into v_evidence
    from public.evidence e
    where e.id = v_evidence_id
      and e.case_id = v_case_id;
    if not found then
        raise exception 'storage_key_case_mismatch';
    end if;

    -- authorize (organization): the case must exist and the actor must be a
    -- CURRENT member of its organization. Users whose organization membership
    -- was revoked fail here regardless of any surviving case_members row.
    select c.* into v_case from public.cases c where c.id = v_case_id;
    if not found then
        raise exception 'case_not_found';
    end if;
    if not public.is_org_member(v_case.org_id) then
        raise exception 'not_org_member';
    end if;

    -- authorize (case role): lead or investigator on this case, as a current
    -- member (is_org_member already passed, so staleness cannot creep in).
    if not exists (
        select 1
        from public.case_members m
        where m.case_id = v_case.id
          and m.profile_id = v_actor
          and m.role_in_case in ('lead', 'investigator')
    ) then
        raise exception 'not_authorized_to_delete';
    end if;

    -- business rule: files may only be cleaned up from open cases.
    if v_case.status not in ('draft', 'active') then
        raise exception 'case_not_open';
    end if;

    -- operate: remove the object. storage.objects carries a trigger that only
    -- permits deletion when the storage service lifts the guard, so this
    -- trusted function lifts the SAME guard, transaction-local, in the same
    -- statement scope. The delete name is bound to the case bucket.
    perform set_config('storage.allow_delete_query', 'true', true);
    delete from storage.objects
    where bucket_id = 'evidence-files'
      and name = p_storage_key;
    get diagnostics v_deleted = row_count;
    if v_deleted < 1 then
        raise exception 'object_not_found_in_storage';
    end if;

    -- audit: record the destructive cleanup. This is an operational audit
    -- event on the document version; chain-of-custody is a separate concept
    -- and deliberately NOT touched here (nothing moved custody). The read
    -- RPCs (list_case_audit_events / evidence audit) scrub storage_key from
    -- meta; audit_logs has no direct INSERT policy.
    insert into public.audit_logs (actor_id, action, entity_type, entity_id, meta)
    values (
        v_actor,
        'evidence.object_deleted',
        'document_version',
        v_version.id,
        jsonb_build_object(
            'case_id', v_case.id,
            'case_number', v_case.case_number,
            'evidence_id', v_evidence.id,
            'evidence_number', v_evidence.evidence_number,
            'document_version_id', v_version.id,
            'file_name', v_version.file_name,
            'mime_type', v_version.mime_type,
            'file_size_bytes', v_version.file_size_bytes,
            'sha256', v_version.sha256,
            'storage_key', p_storage_key
        )
    );

    return jsonb_build_object(
        'deleted', true,
        'case_id', v_case.id,
        'evidence_id', v_evidence.id,
        'document_version_id', v_version.id
    );
end;
$function$;

alter function public.delete_evidence_object(text) owner to postgres;

revoke execute on function public.delete_evidence_object(text) from public;
revoke execute on function public.delete_evidence_object(text) from anon;

grant execute on function public.delete_evidence_object(text) to authenticated;