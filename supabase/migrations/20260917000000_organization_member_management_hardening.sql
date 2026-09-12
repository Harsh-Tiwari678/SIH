-- =============================================================================
-- SIH26190 Secure Evidence — organization member management hardening
--
-- Fourth hardening pass. Closes three categories of gaps:
--
--   1. GRANT SURFACE: the default Supabase schema grants leave TRUNCATE,
--      blanket INSERT/UPDATE/DELETE on most core tables, and column-level
--      UPDATE on identity/provenance columns that must be server-controlled
--      only. This migration revokes every dangerous grant and re-asserts the
--      narrow column-level UPDATE set that was documented by earlier
--      migrations.
--
--   2. WRITE RPC STALE-MEMBER GAP: four SECURITY DEFINER write RPCs
--      (update_case, update_evidence_status, create_evidence,
--      create_blockchain_anchor) authorize via explicit case_members rows
--      alone. A stale case_members row (whose organization membership was
--      removed) still passes those checks. Adding the org-aware
--      is_case_member(p_case_id) predicate closes this at the RPC level,
--      matching the org boundary established in 20260914.
--
--      record_verification_event already uses is_case_member(v_case.id) and
--      is NOT touched by this migration.
--
--   3. READ PATH GAPS: three read RPCs required by the org-management
--      workflow do not yet exist:
--        * list_organization_members  (admin-scoped member roster)
--        * list_organization_audit_events (org-scoped audit trail)
--        * lookup_profiles_for_organization (name search within the org)
--
-- Security decisions:
--   * All new RPCs are SECURITY DEFINER, set search_path = '', owner postgres.
--   * EXECUTE revoked from public/anon, granted to authenticated only.
--   * Identity derived from auth.uid(), never parameters.
--   * table-level UPDATE grant is revoked first, then column-level grants on
--     provenance/identity columns are revoked, then the narrow safe set is
--     re-granted. Column-level REVOKE is explicit per column to clean up any
--     stray grants from Supabase's default schema setup.
--   * No changes to SELECT, REFERENCES, or TRIGGER grants.
--   * No changes to record_verification_event or chain_of_custody RPCs.
--   * No changes to RLS policies.
--   * No new tables or columns.
-- =============================================================================

-- =============================================================================
-- PART 1: Revoke dangerous DML grants from authenticated
--
-- Pattern: follow chain_of_custody_workflow (20260916) which did
--   revoke update, delete, truncate on table public.chain_of_custody from authenticated;
-- for the same defense-in-depth rationale.
--
-- Tables with INSERT revoked by earlier migrations (cases, case_members,
-- chain_of_custody, organizations, organization_members) are re-asserted
-- here for completeness and auditability.
-- =============================================================================

-- profiles: revoke INSERT, DELETE, TRUNCATE (RPC-only writes)
revoke insert, delete, truncate on table public.profiles from authenticated;

-- cases: revoke INSERT, DELETE, TRUNCATE (RPC-only writes; INSERT already
-- revoked by 20260914 but re-asserted here)
revoke insert, delete, truncate on table public.cases from authenticated;

-- case_members: revoke TRUNCATE (INSERT/UPDATE/DELETE already revoked by
-- 20260914)
revoke truncate on table public.case_members from authenticated;

-- evidence: revoke INSERT, DELETE, TRUNCATE (RPC-only writes)
revoke insert, delete, truncate on table public.evidence from authenticated;

-- document_versions: revoke INSERT, DELETE, TRUNCATE (RPC-only writes)
revoke insert, delete, truncate on table public.document_versions from authenticated;

-- chain_of_custody: no action needed (INSERT/UPDATE/DELETE/TRUNCATE already
-- revoked by 20260916)

-- audit_logs: revoke INSERT, DELETE, TRUNCATE (RPC-only writes via SECURITY
-- DEFINER; no direct INSERT policy)
revoke insert, delete, truncate on table public.audit_logs from authenticated;

-- blockchain_anchors: revoke INSERT, DELETE, TRUNCATE (RPC-only writes via
-- SECURITY DEFINER RPCs; no direct INSERT policy)
revoke insert, delete, truncate on table public.blockchain_anchors from authenticated;

-- organizations: revoke DELETE, TRUNCATE (INSERT already revoked by 20260913;
-- RPC-only writes)
revoke delete, truncate on table public.organizations from authenticated;

-- organization_members: revoke TRUNCATE (INSERT/UPDATE/DELETE already revoked
-- by 20260913)
revoke truncate on table public.organization_members from authenticated;

-- =============================================================================
-- PART 2: Revoke table-level UPDATE and column-level UPDATE on
--         provenance/identity columns, then re-grant only the safe set.
--
-- After Supabase's default schema setup, authenticated holds both a
-- table-level UPDATE grant AND column-level grants on ALL columns for most
-- tables. The table-level grant alone gives blanket UPDATE, so it must be
-- revoked first. Then column-level grants on identity/provenance columns
-- are revoked explicitly to clean up any stray per-column entries, and the
-- documented safe set is re-granted.
-- =============================================================================

-- ---- profiles ----------------------------------------------------------------
-- Safe columns (from 20260830000000_rls_policies.sql:125):
--   full_name, badge_number, updated_at
-- Revoke table-level + all stray column-level, then re-grant safe set.
revoke update on table public.profiles from authenticated;
revoke update (id) on public.profiles from authenticated;
revoke update (role) on public.profiles from authenticated;
revoke update (created_at) on public.profiles from authenticated;
grant update (full_name, badge_number, updated_at) on public.profiles to authenticated;

-- ---- cases -------------------------------------------------------------------
-- Safe columns (from 20260830000000_rls_policies.sql:129):
--   title, description, status, closed_at, closed_by, updated_at
revoke update on table public.cases from authenticated;
revoke update (id) on public.cases from authenticated;
revoke update (case_number) on public.cases from authenticated;
revoke update (created_by) on public.cases from authenticated;
revoke update (created_at) on public.cases from authenticated;
revoke update (org_id) on public.cases from authenticated;
grant update (title, description, status, closed_at, closed_by, updated_at) on public.cases to authenticated;

-- ---- evidence ----------------------------------------------------------------
-- Safe columns (from 20260910000000_audit_read_path_and_hardening.sql:352):
--   title, description, type, updated_at
revoke update on table public.evidence from authenticated;
revoke update (id) on public.evidence from authenticated;
revoke update (case_id) on public.evidence from authenticated;
revoke update (evidence_number) on public.evidence from authenticated;
revoke update (status) on public.evidence from authenticated;
revoke update (created_by) on public.evidence from authenticated;
revoke update (created_at) on public.evidence from authenticated;
grant update (title, description, type, updated_at) on public.evidence to authenticated;

-- ---- document_versions -------------------------------------------------------
-- Append-only; no RPC updates individual version rows.
revoke update on table public.document_versions from authenticated;
revoke update (id) on public.document_versions from authenticated;
revoke update (evidence_id) on public.document_versions from authenticated;
revoke update (version) on public.document_versions from authenticated;
revoke update (prev_version_id) on public.document_versions from authenticated;
revoke update (file_name) on public.document_versions from authenticated;
revoke update (mime_type) on public.document_versions from authenticated;
revoke update (file_size_bytes) on public.document_versions from authenticated;
revoke update (sha256) on public.document_versions from authenticated;
revoke update (storage_key) on public.document_versions from authenticated;
revoke update (uploaded_by) on public.document_versions from authenticated;
revoke update (uploaded_at) on public.document_versions from authenticated;
revoke update (notes) on public.document_versions from authenticated;
-- No re-grant: zero UPDATE on document_versions for authenticated.

-- ---- audit_logs --------------------------------------------------------------
-- Append-only; SECURITY DEFINER INSERT only. No column should be user-updatable.
revoke update on table public.audit_logs from authenticated;
revoke update (id) on public.audit_logs from authenticated;
revoke update (actor_id) on public.audit_logs from authenticated;
revoke update (action) on public.audit_logs from authenticated;
revoke update (entity_type) on public.audit_logs from authenticated;
revoke update (entity_id) on public.audit_logs from authenticated;
revoke update (before) on public.audit_logs from authenticated;
revoke update (after) on public.audit_logs from authenticated;
revoke update (ip_address) on public.audit_logs from authenticated;
revoke update (meta) on public.audit_logs from authenticated;
revoke update (org_id) on public.audit_logs from authenticated;
revoke update (created_at) on public.audit_logs from authenticated;
-- No re-grant: zero UPDATE on audit_logs for authenticated.

-- ---- organizations -----------------------------------------------------------
-- Safe columns (from 20260912000000_organization_foundation.sql:236):
--   name, slug, updated_at
revoke update on table public.organizations from authenticated;
revoke update (id) on public.organizations from authenticated;
revoke update (created_by) on public.organizations from authenticated;
revoke update (created_at) on public.organizations from authenticated;
grant update (name, slug, updated_at) on public.organizations to authenticated;

-- ---- case_members, organization_members, chain_of_custody --------------------
-- No table-level UPDATE grant exists (already revoked by earlier migrations).
-- No action needed: RLS + RPC-only write model is already enforced.

-- ---- blockchain_anchors ------------------------------------------------------
-- No direct UPDATE: anchors are written only by SECURITY DEFINER RPCs
-- (create_blockchain_anchor / reconcile_anchor_anchored). The status column
-- must never be user-flipped.
revoke update on table public.blockchain_anchors from authenticated;
revoke update (id) on public.blockchain_anchors from authenticated;
revoke update (evidence_id) on public.blockchain_anchors from authenticated;
revoke update (document_version_id) on public.blockchain_anchors from authenticated;
revoke update (network) on public.blockchain_anchors from authenticated;
revoke update (chain_id) on public.blockchain_anchors from authenticated;
revoke update (contract_address) on public.blockchain_anchors from authenticated;
revoke update (evidence_id_hash) on public.blockchain_anchors from authenticated;
revoke update (version_id_hash) on public.blockchain_anchors from authenticated;
revoke update (evidence_sha256) on public.blockchain_anchors from authenticated;
revoke update (status) on public.blockchain_anchors from authenticated;
revoke update (tx_hash) on public.blockchain_anchors from authenticated;
revoke update (block_number) on public.blockchain_anchors from authenticated;
revoke update (error_message) on public.blockchain_anchors from authenticated;
revoke update (anchored_at) on public.blockchain_anchors from authenticated;
revoke update (created_at) on public.blockchain_anchors from authenticated;
revoke update (updated_at) on public.blockchain_anchors from authenticated;
-- No re-grant: zero UPDATE on blockchain_anchors for authenticated.

-- =============================================================================
-- PART 3: Hardened update_case — add is_case_member check
--
-- Current authz: public.case_role(p_case_id) <> 'lead'
-- This checks the explicit case_members row but ignores org membership. A
-- stale case_members holder (org membership revoked) still passes.
--
-- Fix: require is_case_member(p_case_id) (org-aware) AND case_role = 'lead'.
-- The two checks together ensure the actor is (a) an org member AND
-- (b) an explicit lead — matching the RLS policy in 20260914.
-- =============================================================================

create or replace function public.update_case(
    p_case_id uuid,
    p_title text default null,
    p_description text default null,
    p_set_description_null boolean default false,
    p_status text default null
)
returns public.cases
language plpgsql
security definer
set search_path = ''
as $function$
declare
    v_actor  uuid := auth.uid();
    v_row    public.cases;
    v_before jsonb;
    v_changed boolean := false;
    v_old_status text;
    v_new_title text;
    v_new_description text;
    v_new_status text;
    v_new_closed_at timestamptz;
    v_new_closed_by uuid;
begin
    -- authenticate / authorize: must be an authenticated session with a profile.
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;
    if not exists (select 1 from public.profiles p where p.id = v_actor) then
        raise exception 'profile_not_found';
    end if;

    -- validate: the case must exist and the caller must be its lead.
    select c.* into v_row
    from public.cases c
    where c.id = p_case_id;
    if not found then
        raise exception 'case_not_found';
    end if;

    -- HARDENING: require org-aware case membership (defense in depth). A stale
    -- case_members row whose org membership was revoked is now blocked at the
    -- RPC level, matching the RLS policy boundary.
    if not public.is_case_member(p_case_id) then
        raise exception 'not_case_member';
    end if;

    -- 'is distinct from' (not '<>') is deliberate: case_role returns NULL for
    -- a profile with no explicit case_members row (e.g. an org admin), and
    -- NULL <> 'lead' is NULL — which would silently let non-leads through.
    if public.case_role(p_case_id) is distinct from 'lead' then
        raise exception 'not_lead';
    end if;

    -- validate: every supplied value must satisfy the existing constraints.
    if p_status is not null and p_status not in ('draft', 'active', 'closed', 'archived') then
        raise exception 'status_not_allowed';
    end if;
    if p_title is not null and btrim(p_title) = '' then
        raise exception 'title_required';
    end if;
    if p_title is not null and length(btrim(p_title)) > 500 then
        raise exception 'title_too_long';
    end if;
    if p_description is not null and length(p_description) > 5000 then
        raise exception 'description_too_long';
    end if;

    -- business operation: compute the candidate values, detect real changes.
    v_new_title := case when p_title is not null then btrim(p_title) else v_row.title end;
    v_new_description := case
        when p_set_description_null then null
        when p_description is not null then p_description
        else v_row.description
    end;
    v_new_status := case when p_status is not null then p_status else v_row.status end;

    v_changed := (v_new_title is distinct from v_row.title)
        or (v_new_description is distinct from v_row.description)
        or (v_new_status is distinct from v_row.status);

    if not v_changed then
        return v_row;
    end if;

    v_before := to_jsonb(v_row);
    v_old_status := v_row.status;

    v_new_closed_at := case
        when p_status is not null and p_status in ('closed', 'archived') then now()
        when p_status is not null then null
        else v_row.closed_at
    end;
    v_new_closed_by := case
        when p_status is not null and p_status in ('closed', 'archived') then v_actor
        when p_status is not null then null
        else v_row.closed_by
    end;

    update public.cases c0
    set title       = v_new_title,
        description = v_new_description,
        status      = v_new_status,
        closed_at   = v_new_closed_at,
        closed_by   = v_new_closed_by,
        updated_at  = now()
    where c0.id = p_case_id
    returning * into v_row;

    -- audit: record the update. audit_logs has no direct INSERT policy; only
    -- SECURITY DEFINER system paths may write it.
    insert into public.audit_logs (actor_id, action, entity_type, entity_id, before, after, meta)
    values (
        v_actor,
        'case.updated',
        'case',
        p_case_id,
        v_before,
        to_jsonb(v_row),
        jsonb_build_object(
            'case_number', v_row.case_number,
            'previous_status', v_old_status,
            'new_status', v_row.status,
            'status_changed', v_old_status is distinct from v_row.status
        )
    );

    -- audit: a dedicated status transition event, when the status actually
    -- changed (metadata-only edits must not emit one).
    if v_old_status is distinct from v_row.status then
        insert into public.audit_logs (actor_id, action, entity_type, entity_id, before, after, meta)
        values (
            v_actor,
            'case.status_changed',
            'case',
            p_case_id,
            jsonb_build_object('status', v_old_status),
            jsonb_build_object('status', v_row.status),
            jsonb_build_object(
                'case_number', v_row.case_number,
                'previous_status', v_old_status,
                'new_status', v_row.status
            )
        );
    end if;

    return v_row;
end;
$function$;

alter function public.update_case(uuid, text, text, boolean, text) owner to postgres;
revoke execute on function public.update_case(uuid, text, text, boolean, text) from public, anon;
grant execute on function public.update_case(uuid, text, text, boolean, text) to authenticated;

-- =============================================================================
-- PART 4: Hardened update_evidence_status — add is_case_member check
--
-- Current authz: explicit case_members WHERE role in ('lead', 'investigator').
-- A stale case_members row still passes.
--
-- Fix: add is_case_member(v_case.id) as a separate guard. The actor must be
-- an org member AND have the explicit role.
-- =============================================================================

create or replace function public.update_evidence_status(
    p_evidence_id uuid,
    p_status      text
)
returns public.evidence
language plpgsql
security definer
set search_path = ''
as $function$
declare
    v_actor          uuid := auth.uid();
    v_old            public.evidence;
    v_new            public.evidence;
    v_case           public.cases;
    v_anchor_version uuid;
begin
    -- authenticate / authorize.
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;
    if not exists (select 1 from public.profiles p where p.id = v_actor) then
        raise exception 'profile_not_found';
    end if;

    -- validate: the status must be part of the existing evidence.status CHECK
    -- vocabulary.
    if p_status is not null and p_status not in ('received', 'under_review', 'verified', 'rejected', 'archived') then
        raise exception 'status_not_allowed';
    end if;
    if p_status is null then
        raise exception 'status_not_allowed';
    end if;

    -- load evidence and its case.
    select e.* into v_old from public.evidence e where e.id = p_evidence_id;
    if not found then
        raise exception 'evidence_not_found';
    end if;

    select c.* into v_case from public.cases c where c.id = v_old.case_id;
    if not found then
        raise exception 'case_not_found';
    end if;

    -- HARDENING: require org-aware case membership. A stale case_members row
    -- whose organization membership was revoked is now blocked at the RPC level.
    if not public.is_case_member(v_case.id) then
        raise exception 'not_case_member';
    end if;

    -- authorize: only the case lead or an investigator may transition evidence
    -- status (the same authorization model as upload / anchoring). Viewers can
    -- read, never write.
    if not exists (
        select 1
        from public.case_members m
        where m.case_id = v_old.case_id
          and m.profile_id = v_actor
          and m.role_in_case in ('lead', 'investigator')
    ) then
        raise exception 'not_authorized_to_update';
    end if;

    -- no-op: unchanged status is not an audit-worthy event.
    if v_old.status = p_status then
        return v_old;
    end if;

    -- HARDENING: 'verified' must represent a real, on-chain verification
    -- operation, never a hand-flip. At least one document version of this
    -- evidence must have a blockchain_anchors row in state 'anchored' whose
    -- evidence_sha256 exactly equals the version's recorded sha256 — the
    -- invariant mark_anchor_anchored re-asserts at confirmation time. The
    -- matching version is captured for the custody entry below.
    if p_status = 'verified' then
        select ba.document_version_id into v_anchor_version
        from public.blockchain_anchors ba
        join public.document_versions dv on dv.id = ba.document_version_id
        where ba.evidence_id = v_old.id
          and ba.status = 'anchored'
          and ba.evidence_sha256 = dv.sha256
        limit 1;
        if v_anchor_version is null then
            raise exception 'verification_required';
        end if;
    end if;

    update public.evidence e0
    set status     = p_status,
        updated_at = now()
    where e0.id = v_old.id
    returning * into v_new;

    -- audit: record the transition. audit_logs has no direct INSERT policy;
    -- only SECURITY DEFINER system paths may write it.
    insert into public.audit_logs (actor_id, action, entity_type, entity_id, before, after, meta)
    values (
        v_actor,
        'evidence.status_changed',
        'evidence',
        v_new.id,
        jsonb_build_object('status', v_old.status),
        jsonb_build_object('status', v_new.status),
        jsonb_build_object(
            'case_id', v_case.id,
            'case_number', v_case.case_number,
            'evidence_id', v_new.id,
            'evidence_number', v_new.evidence_number,
            'title', v_new.title,
            'previous_status', v_old.status,
            'new_status', v_new.status
        )
    );

    -- custody: a possession event accompanies the status transition, in the
    -- SAME transaction (unchanged from 20260916000000 — the hardened rewrite
    -- must not lose the possession record). Idempotent — a duplicated
    -- transition never creates a second row.
    if p_status in ('verified', 'archived') then
        if not exists (
            select 1
            from public.chain_of_custody c
            where c.evidence_id = v_new.id
              and c.action = p_status
        ) then
            insert into public.chain_of_custody (
                evidence_id, document_version_id, action, actor_id,
                from_profile_id, to_profile_id, location, notes, occurred_at
            ) values (
                v_new.id,
                case when p_status = 'verified' then v_anchor_version else null end,
                p_status,
                v_actor,
                null,
                null,
                null,
                null,
                now()
            );
        end if;
    end if;

    return v_new;
end;
$function$;

alter function public.update_evidence_status(uuid, text) owner to postgres;
revoke execute on function public.update_evidence_status(uuid, text) from public, anon;
grant execute on function public.update_evidence_status(uuid, text) to authenticated;

-- =============================================================================
-- PART 5: Hardened create_evidence — add is_case_member check
--
-- Current visibility check: c.created_by = v_actor OR explicit case_members.
-- Current role check: explicit case_members WHERE role in ('lead', 'investigator').
-- Both are stale-member-ulnerable because they only check case_members.
--
-- Fix: replace visibility check with is_case_member(p_case_id) (org-aware),
-- and add is_case_member(p_case_id) to the role check.
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

    -- HARDENING: use org-aware case visibility. The old check
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

-- =============================================================================
-- PART 6: Hardened create_blockchain_anchor — add is_case_member check
--
-- Current authz: explicit case_members WHERE role in ('lead', 'investigator').
-- A stale case_members row still passes.
--
-- Fix: add is_case_member(v_evidence.case_id) guard before the role check.
-- =============================================================================

create or replace function public.create_blockchain_anchor(
    p_document_version_id uuid
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
    v_actor          uuid := auth.uid();
    v_version        public.document_versions;
    v_evidence       public.evidence;
    v_anchor         public.blockchain_anchors;
    v_previous       jsonb;
    v_evidence_hash  text;
    v_version_hash   text;
begin
    -- authenticate: derive the actor from the session, never from arguments.
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;

    -- authorize: the actor must have an application profile.
    if not exists (select 1 from public.profiles p where p.id = v_actor) then
        raise exception 'profile_not_found';
    end if;

    -- validate: the document version must exist.
    select dv.* into v_version
    from public.document_versions dv
    where dv.id = p_document_version_id;
    if not found then
        raise exception 'document_version_not_found';
    end if;

    -- derive the owning evidence (and its case) from the version.
    select e.* into v_evidence
    from public.evidence e
    where e.id = v_version.evidence_id;
    if not found then
        raise exception 'evidence_not_found';
    end if;

    -- HARDENING: require org-aware case membership. A stale case_members row
    -- whose organization membership was revoked is now blocked at the RPC level.
    if not public.is_case_member(v_evidence.case_id) then
        raise exception 'not_case_member';
    end if;

    -- authorize: only the case lead or an investigator may anchor evidence,
    -- using the same authorization model as upload (create_evidence).
    if not exists (
        select 1
        from public.case_members m
        where m.case_id = v_evidence.case_id
          and m.profile_id = v_actor
          and m.role_in_case in ('lead', 'investigator')
    ) then
        raise exception 'not_authorized_to_anchor';
    end if;

    -- reuse / reset / reject based on the existing anchor state, if any.
    select a.* into v_anchor
    from public.blockchain_anchors a
    where a.document_version_id = p_document_version_id
    for update;

    if v_anchor.id is not null then
        if v_anchor.status = 'anchored' then
            raise exception 'already_anchored';
        end if;
        if v_anchor.status = 'pending' then
            return jsonb_build_object('anchor', to_jsonb(v_anchor), 'reused', true);
        end if;
        -- status = 'failed': reset to pending and reuse the slot. The retry is
        -- itself an audit event so repeated failures stay on the record.
        v_previous := to_jsonb(v_anchor);
        update public.blockchain_anchors
        set status = 'pending',
            error_message = null,
            updated_at = now()
        where id = v_anchor.id
        returning * into v_anchor;
        insert into public.audit_logs (actor_id, action, entity_type, entity_id, before, after, meta)
        values (
            v_actor,
            'evidence.anchor_retry',
            'blockchain_anchor',
            v_anchor.id,
            v_previous,
            to_jsonb(v_anchor),
            jsonb_build_object(
                'evidence_id', v_anchor.evidence_id,
                'document_version_id', v_anchor.document_version_id,
                'network', v_anchor.network,
                'chain_id', v_anchor.chain_id,
                'contract_address', v_anchor.contract_address,
                'previous_status', v_previous->>'status',
                'new_status', v_anchor.status
            )
        );
        return jsonb_build_object('anchor', to_jsonb(v_anchor), 'reused', true);
    end if;

    -- compute the deterministic encodings and reuse the version's exact SHA-256.
    v_evidence_hash := public.uuid_to_bytes32(v_evidence.id);
    v_version_hash  := public.uuid_to_bytes32(v_version.id);

    -- create a fresh pending anchor. evidence_sha256 is taken directly from
    -- document_versions.sha256 (never client-supplied), enforcing equality.
    insert into public.blockchain_anchors (
        evidence_id,
        document_version_id,
        network,
        chain_id,
        contract_address,
        evidence_id_hash,
        version_id_hash,
        evidence_sha256,
        status
    ) values (
        v_evidence.id,
        v_version.id,
        'sepolia',
        11155111,
        '0x1D76cea78A844fed9aca674C82a900917e848b1a',
        v_evidence_hash,
        v_version_hash,
        v_version.sha256,
        'pending'
    )
    returning * into v_anchor;

    -- audit: record the intent in the same transaction. audit_logs has no
    -- direct INSERT policy; only SECURITY DEFINER system paths may write it.
    insert into public.audit_logs (actor_id, action, entity_type, entity_id, after, meta)
    values (
        v_actor,
        'evidence.anchor_requested',
        'blockchain_anchor',
        v_anchor.id,
        to_jsonb(v_anchor),
        jsonb_build_object(
            'document_version_id', v_version.id,
            'network', 'sepolia',
            'chain_id', 11155111,
            'contract_address', '0x1D76cea78A844fed9aca674C82a900917e848b1a',
            'evidence_sha256', v_version.sha256
        )
    );

    return jsonb_build_object('anchor', to_jsonb(v_anchor), 'reused', false);
end;
$function$;

alter function public.create_blockchain_anchor(uuid) owner to postgres;
revoke execute on function public.create_blockchain_anchor(uuid) from public, anon;
grant execute on function public.create_blockchain_anchor(uuid) to authenticated;

-- =============================================================================
-- PART 7: list_organization_members — SECURITY DEFINER read RPC
--
-- Returns the member roster for an organization. Authorization: the caller
-- must be a member of the target org (org-scoped visibility, consistent with
-- the organizations SELECT policy).
--
-- Return type mirrors the pattern of list_case_audit_events: explicit
-- returns table (...) with named columns, SECURITY DEFINER, owner postgres,
-- search_path = ''.
-- =============================================================================

create or replace function public.list_organization_members(
    p_org_id uuid
)
returns table (
    id              uuid,
    profile_id      uuid,
    full_name       text,
    badge_number    text,
    role_in_org     text,
    added_by_name   text,
    added_by        uuid,
    added_at        timestamptz
)
language plpgsql
security definer
set search_path = ''
as $function$
declare
    v_actor uuid := auth.uid();
begin
    -- authenticate / authorize: an authenticated session with a profile.
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;
    if not exists (select 1 from public.profiles p where p.id = v_actor) then
        raise exception 'profile_not_found';
    end if;

    -- authorize (visibility): the caller must be a member of the target org.
    -- An inaccessible org is reported identically to a nonexistent one.
    if not public.is_org_member(p_org_id) then
        raise exception 'org_not_found';
    end if;

    return query
    select
        m.id,
        m.profile_id,
        p.full_name,
        p.badge_number,
        m.role_in_org,
        ap.full_name as added_by_name,
        m.added_by,
        m.added_at
    from public.organization_members m
    join public.profiles p on p.id = m.profile_id
    left join public.profiles ap on ap.id = m.added_by
    where m.org_id = p_org_id
    order by m.added_at, m.id;
end;
$function$;

alter function public.list_organization_members(uuid) owner to postgres;
revoke execute on function public.list_organization_members(uuid) from public, anon;
grant execute on function public.list_organization_members(uuid) to authenticated;

-- =============================================================================
-- PART 8: list_organization_audit_events — SECURITY DEFINER read RPC
--
-- Returns the org-scoped audit trail. Authorization: the caller must be a
-- member of the target org.
--
-- All audit_logs rows with matching org_id are returned. The org_id invariant
-- (set at write time or backfilled by 20260913000000) ensures case/evidence/
-- anchor events resolve to their owning org. Organization and
-- organization_member events carry org_id directly.
--
-- storage_key is scrubbed from meta (defense in depth — same as
-- list_case_audit_events).
-- =============================================================================

create or replace function public.list_organization_audit_events(
    p_org_id uuid
)
returns table (
    id           uuid,
    action       text,
    entity_type  text,
    entity_id    uuid,
    actor_id     uuid,
    actor_name   text,
    entity_label text,
    created_at   timestamptz,
    meta         jsonb
)
language plpgsql
security definer
set search_path = ''
as $function$
declare
    v_actor uuid := auth.uid();
begin
    -- authenticate / authorize: an authenticated session with a profile.
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;
    if not exists (select 1 from public.profiles p where p.id = v_actor) then
        raise exception 'profile_not_found';
    end if;

    -- authorize (visibility): the caller must be a member of the target org.
    if not public.is_org_member(p_org_id) then
        raise exception 'org_not_found';
    end if;

    -- resolve the owning organization for every entity type. Writers populate
    -- audit_logs.org_id for organization / organization_member / custody
    -- events; case-scoped events store the org only in their JSON, so the
    -- owning org is resolved from the entity chain (the same mapping the
    -- 20260913000000 backfill uses). Returning every row whose resolved org is
    -- the target makes the org trail complete regardless of writer behavior.
    return query
    with resolved as (
        select
            r0.id,
            r0.action,
            r0.entity_type,
            r0.entity_id,
            r0.actor_id,
            r0.created_at,
            r0.meta_scrubbed as meta,
            r0.org_id
                as org_id,
            case r0.entity_type
                when 'case' then
                    (select c.org_id from public.cases c where c.id = r0.entity_id)
                when 'case_member' then (
                    select c.org_id
                    from public.cases c
                    where c.id = coalesce(
                        (r0.after ->> 'case_id')::uuid,
                        (r0.meta ->> 'case_id')::uuid,
                        (r0.before ->> 'case_id')::uuid
                    )
                )
                when 'evidence' then (
                    select c.org_id
                    from public.evidence e
                    join public.cases c on c.id = e.case_id
                    where e.id = r0.entity_id
                )
                when 'document_version' then (
                    select c.org_id
                    from public.document_versions dv
                    join public.evidence e on e.id = dv.evidence_id
                    join public.cases c on c.id = e.case_id
                    where dv.id = r0.entity_id
                )
                when 'blockchain_anchor' then (
                    select c.org_id
                    from public.blockchain_anchors ba
                    join public.evidence e on e.id = ba.evidence_id
                    join public.cases c on c.id = e.case_id
                    where ba.id = r0.entity_id
                )
                when 'organization' then r0.entity_id
                when 'organization_member' then (r0.meta ->> 'org_id')::uuid
                else null::uuid
            end as resolved_org,
            r0.profile_ref
        from (
            select
                a.*,
                (a.meta - 'storage_key')::jsonb as meta_scrubbed,
                coalesce(
                    (a.after ->> 'profile_id')::uuid,
                    (a.before ->> 'profile_id')::uuid,
                    (a.meta ->> 'to_profile_id')::uuid,
                    (a.meta ->> 'removed_profile_id')::uuid,
                    (a.meta ->> 'profile_id')::uuid
                ) as profile_ref
            from public.audit_logs a
        ) r0
    )
    select
        r.id,
        r.action,
        r.entity_type,
        r.entity_id,
        r.actor_id,
        ap.full_name as actor_name,
        case r.entity_type
            when 'case' then
                (select c.title from public.cases c where c.id = r.entity_id)
            when 'evidence' then
                (select e.title from public.evidence e where e.id = r.entity_id)
            when 'document_version' then
                (select dv.file_name from public.document_versions dv where dv.id = r.entity_id)
            when 'blockchain_anchor' then (
                select e.title
                from public.blockchain_anchors ba
                join public.evidence e on e.id = ba.evidence_id
                where ba.id = r.entity_id
            )
            when 'organization' then
                (select o.name from public.organizations o where o.id = r.entity_id)
            when 'case_member' then
                (select p.full_name from public.profiles p where p.id = r.profile_ref)
            when 'organization_member' then
                (select p.full_name from public.profiles p where p.id = r.profile_ref)
            else null::text
        end as entity_label,
        r.created_at,
        r.meta
    from resolved r
    left join public.profiles ap on ap.id = r.actor_id
    where r.org_id = p_org_id
       or r.resolved_org = p_org_id
    order by r.created_at desc, r.id desc;
end;
$function$;

alter function public.list_organization_audit_events(uuid) owner to postgres;
revoke execute on function public.list_organization_audit_events(uuid) from public, anon;
grant execute on function public.list_organization_audit_events(uuid) to authenticated;

-- =============================================================================
-- PART 9: lookup_profiles_for_organization — SECURITY DEFINER read RPC
--
-- Returns candidate profiles who are NOT yet members of the target org,
-- optionally filtered by full_name or badge_number (ILIKE, case-insensitive
-- substring). Used by the "add member" UI to search for people to add.
--
-- Authorization: the caller must be a member of the target org (org-scoped
-- visibility, consistent with the organizations SELECT policy). The
-- authorization boundary is never weakened: a caller can only search for
-- candidates relative to an org they belong to.
--
-- NOT EXISTS against organization_members excludes every profile already in
-- p_org_id, so the result IS the candidate set to add. Only id / full_name /
-- badge_number are exposed — no auth internals, no role data. Results are
-- capped at 10 candidates. The ILIKE filter is safe (parameterized, no
-- injection risk).
-- =============================================================================

create or replace function public.lookup_profiles_for_organization(
    p_org_id  uuid,
    p_query   text default null
)
returns table (
    id           uuid,
    full_name    text,
    badge_number text
)
language plpgsql
security definer
set search_path = ''
as $function$
declare
    v_actor uuid := auth.uid();
begin
    -- authenticate / authorize: an authenticated session with a profile.
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;
    if not exists (select 1 from public.profiles p where p.id = v_actor) then
        raise exception 'profile_not_found';
    end if;

    -- authorize (visibility): the caller must be a member of the target org.
    if not public.is_org_member(p_org_id) then
        raise exception 'org_not_found';
    end if;

    -- candidates = existing application profiles that are NOT already members
    -- of the target org. A profile belonging to a different organization is a
    -- valid candidate (organization_members allows a profile in many orgs).
    return query
    select
        p.id,
        p.full_name,
        p.badge_number
    from public.profiles p
    where not exists (
        select 1
        from public.organization_members existing
        where existing.org_id = p_org_id
          and existing.profile_id = p.id
    )
      and (
          p_query is null
          or p.full_name ilike '%' || p_query || '%'
          or p.badge_number ilike '%' || p_query || '%'
      )
    order by p.full_name, p.id
    limit 10;
end;
$function$;

alter function public.lookup_profiles_for_organization(uuid, text) owner to postgres;
revoke execute on function public.lookup_profiles_for_organization(uuid, text) from public, anon;
grant execute on function public.lookup_profiles_for_organization(uuid, text) to authenticated;

-- =============================================================================
-- End of migration 20260917000000_organization_member_management_hardening
-- =============================================================================
