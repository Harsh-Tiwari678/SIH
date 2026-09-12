-- =============================================================================
-- SIH26190 Secure Evidence — case close / archive immutability hardening
--
-- Fifth hardening pass. Implements the product's case lifecycle contract:
--
--   1. STATUS TRANSITION MATRIX (server-side): the cases.status CHECK allows
--      any of draft/active/closed/archived as a legal target, but only a
--      documented set of transitions is legitimate. update_case now enforces
--      the matrix below and raises 'transition_not_allowed' for anything else.
--
--        draft    -> active
--        active   -> draft | closed
--        closed   -> active | archived
--        archived -> closed
--
--      Reopening a closed case = closed -> active. Restoring an archived case
--      = archived -> closed (NOT active). Metadata-only edits (title /
--      description, no status change) are unaffected and remain allowed on
--      closed/archived cases, per the product decision — they stay audit
--      logged by the existing case.updated path. The closed_at/closed_by
--      invariant is preserved exactly: entering closed/archived sets both
--      from server-side now()/auth.uid(); leaving to draft/active clears the
--      pair; a metadata-only edit leaves them untouched.
--
--   2. CLOSED-CASE MUTATION GATES: once a case is closed or archived, these
--      user mutations are rejected at the database/RPC layer with the
--      distinct 'case_not_open' error:
--        * update_evidence_status     (evidence status transitions)
--        * record_custody_event       (chain-of-custody possession writes)
--        * create_blockchain_anchor   (NEW anchor intents only — see below)
--
--      The following server/orchestrator operations are deliberately NOT
--      gated — a pending blockchain anchor created before case closure must
--      still reconcile/confirm on-chain after closure:
--        * mark_anchor_anchored / mark_anchor_failed / reconcile_anchor_anchored
--        * record_verification_event
--      create_blockchain_anchor only raises case_not_open when it would MINT a
--      brand-new anchor slot; reusing an existing pending/failed slot (the
--      reconcile path) stays open so in-flight anchors complete.
--
--   3. DIRECT-UPDATE SURFACE: the authenticated column UPDATE grant on
--      public.cases is narrowed. status, closed_at and closed_by are removed
--      so a lead/client can never hand-write the lifecycle state; the trusted
--      update_case SECURITY DEFINER RPC remains the only status mutator.
--
-- Security decisions (unchanged): all rewritten RPCs stay SECURITY DEFINER
-- with search_path = '' and owner postgres; EXECUTE is revoked from
-- public/anon and granted to authenticated only; identity is always derived
-- from auth.uid(), never parameters; no RLS policy is weakened; no new tables,
-- columns, or status values are introduced; audit_logs writes remain inside
-- the same SECURITY DEFINER transactions (no parallel audit system); cases are
-- never hard-deleted (ON DELETE RESTRICT is unchanged).
-- =============================================================================

-- =============================================================================
-- PART 1: remove direct UPDATE permission for lifecycle columns
--
-- The 20260917 hardening grant on public.cases is:
--   grant update (title, description, status, closed_at, closed_by, updated_at)
--
-- title/description/updated_at stay directly writable by leads through the
-- cases_update_lead_only RLS policy (the primary path is update_case; the
-- grant only relaxes metadata). status/closed_at/closed_by are lifecycle state
-- owned by update_case exclusively and are revoked here. Verified application
-- paths never issue a direct UPDATE against these three columns — every
-- transition in the app flows through the update_case RPC.
-- =============================================================================

revoke update (status) on public.cases from authenticated;
revoke update (closed_at) on public.cases from authenticated;
revoke update (closed_by) on public.cases from authenticated;

-- =============================================================================
-- PART 2: update_case — enforce the server-side transition matrix
--
-- Recreated from the 20260917 hardened definition (is_case_member + lead check,
-- closed_at/closed_by invariant, case.updated + case.status_changed audit).
-- The ONLY behavioral addition is the transition matrix check, which runs when
-- the status actually changes. Metadata-only edits (p_status null or equal to
-- the current status) never enter the matrix and stay allowed regardless of the
-- case status.
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

    -- require org-aware case membership (defense in depth). A stale
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

    -- business rule: enforce the server-side status transition matrix when the
    -- status actually changes. The cases.status CHECK allows every target, so
    -- the matrix is the real lifecycle contract:
    --   draft   -> active
    --   active  -> draft | closed
    --   closed  -> active | archived     (reopen / archive)
    --   archived-> closed                (restore; NOT active)
    -- Metadata-only edits (p_status null/unchanged) are unaffected and remain
    -- available on closed/archived cases (product decision; audit logged).
    if v_new_status is distinct from v_row.status then
        if not (
            (v_row.status = 'draft' and v_new_status = 'active')
         or (v_row.status = 'active' and v_new_status in ('draft', 'closed'))
         or (v_row.status = 'closed' and v_new_status in ('active', 'archived'))
         or (v_row.status = 'archived' and v_new_status = 'closed')
        ) then
            raise exception 'transition_not_allowed';
        end if;
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
-- PART 3: update_evidence_status — block transitions on closed/archived cases
--
-- Recreated from the 20260917 hardened definition (org-aware is_case_member,
-- role check, verified-anchor-gate, same-transaction audit + custody mirror).
-- The ONLY behavioral addition: a closed/archived case rejects any evidence
-- status transition with 'case_not_open' (the UI already hides the controls;
-- this makes the DB authoritative).
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

    -- require org-aware case membership. A stale case_members row
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

    -- business rule: evidence status is immutable once the case is closed or
    -- archived. The server (not the UI) is authoritative. The case being a
    -- no-op (same status) is still rejected here for a closed case — the
    -- transition surface is simply not available.
    if v_case.status not in ('draft', 'active') then
        raise exception 'case_not_open';
    end if;

    -- no-op: unchanged status is not an audit-worthy event.
    if v_old.status = p_status then
        return v_old;
    end if;

    -- 'verified' must represent a real, on-chain verification operation, never
    -- a hand-flip. At least one document version of this evidence must have a
    -- blockchain_anchors row in state 'anchored' whose evidence_sha256 exactly
    -- equals the version's recorded sha256 — the invariant
    -- mark_anchor_anchored re-asserts at confirmation time. The matching
    -- version is captured for the custody entry below.
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
-- PART 4: record_custody_event — block possession writes on closed/archived
--
-- Recreated from 20260916000000 (the ONLY non-intake custody writer). The ONLY
-- behavioral addition: a closed/archived case rejects any new possession event
-- with 'case_not_open'. This does not affect reads — the custody trail of a
-- closed case stays fully readable. The anchor-gated 'verified' and the
-- intake-only 'received' rules are unchanged.
-- =============================================================================

create or replace function public.record_custody_event(
    p_evidence_id         uuid,
    p_action              text,
    p_document_version_id uuid default null,
    p_from_profile_id     uuid default null,
    p_to_profile_id       uuid default null,
    p_location            text default null,
    p_notes               text default null
)
returns public.chain_of_custody
language plpgsql
security definer
set search_path = ''
as $function$
declare
    v_actor     uuid := auth.uid();
    v_case      public.cases;
    v_evidence  public.evidence;
    v_custody   public.chain_of_custody;
    v_action    text  := lower(btrim(p_action));
begin
    -- 1. authenticate — the actor is ALWAYS the session user; the function
    --    never accepts an actor_id (or occurred_at) argument.
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;

    -- 2. the actor must have an application profile.
    if not exists (select 1 from public.profiles p where p.id = v_actor) then
        raise exception 'profile_not_found';
    end if;

    -- 3. load the evidence with a visibility constraint (mirrors
    --    create_evidence), so an evidence the caller cannot see — including
    --    one in another organization — is reported identically to a
    --    nonexistent one (no existence leak).
    select e.*
    into v_evidence
    from public.evidence e
    where e.id = p_evidence_id
      and (
          e.created_by = v_actor
          or exists (
              select 1
              from public.case_members m
              where m.case_id = e.case_id
                and m.profile_id = v_actor
          )
      );
    if not found then
        raise exception 'evidence_not_found';
    end if;

    select c.* into v_case from public.cases c where c.id = v_evidence.case_id;
    if not found then
        raise exception 'case_not_found';
    end if;

    -- 4. authorize: the caller must belong to the evidence case's
    --    ORGANIZATION (org-aware is_case_member) …
    if not public.is_case_member(v_case.id) then
        raise exception 'not_authorized_for_custody';
    end if;

    -- 5. … and hold an explicit lead / investigator role in the case
    --    (viewers read custody, they never record it).
    if not exists (
        select 1
        from public.case_members m
        where m.case_id = v_case.id
          and m.profile_id = v_actor
          and m.role_in_case in ('lead', 'investigator')
    ) then
        raise exception 'not_authorized_for_custody';
    end if;

    -- 5b. business rule: a closed/archived case is a frozen possession trail.
    --     No new custody event may be recorded once the case is not open.
    if v_case.status not in ('draft', 'active') then
        raise exception 'case_not_open';
    end if;

    -- 6. validate the action against the existing vocabulary.
    if v_action not in ('received', 'transferred', 'returned', 'verified', 'released', 'archived') then
        raise exception 'action_not_allowed';
    end if;

    -- 7. 'received' is written by create_evidence on intake and must not be
    --    freely reproducible through this workflow.
    if v_action = 'received' then
        raise exception 'received_created_on_intake';
    end if;

    -- 8. action shape rules: transfer/return require a recipient; release and
    --    archive terminate possession (a target is meaningless and rejected).
    if v_action in ('transferred', 'returned') and p_to_profile_id is null then
        raise exception 'to_profile_required';
    end if;
    if v_action in ('released', 'archived') and p_to_profile_id is not null then
        raise exception 'to_profile_not_allowed';
    end if;
    --    you cannot hand custody to yourself — a transfer needs a real
    --    receiving party (there is no acceptor handshake in this phase).
    if v_action in ('transferred', 'returned') and p_to_profile_id = v_actor then
        raise exception 'to_profile_is_actor';
    end if;

    -- 9. an optional document version must belong to THIS evidence.
    if p_document_version_id is not null and not exists (
        select 1
        from public.document_versions dv
        where dv.id = p_document_version_id
          and dv.evidence_id = v_evidence.id
    ) then
        raise exception 'document_version_not_found';
    end if;

    -- 10. from / to profiles (when provided) must be members of the SAME
    --     case. Cross-case or cross-organization custody is meaningless and
    --     rejected; the two-arg is_case_member mirrors the old INSERT policy.
    if p_from_profile_id is not null and not public.is_case_member(p_from_profile_id, v_case.id) then
        raise exception 'from_profile_not_in_case';
    end if;
    if p_to_profile_id is not null and not public.is_case_member(p_to_profile_id, v_case.id) then
        raise exception 'to_profile_not_in_case';
    end if;
    if p_from_profile_id is not null and p_to_profile_id is not null and p_from_profile_id = p_to_profile_id then
        raise exception 'from_to_same_profile';
    end if;

    -- 11. 'verified' must reflect a real on-chain verification — the same
    --     invariant update_evidence_status enforces (no hand-flip).
    if v_action = 'verified' then
        if not exists (
            select 1
            from public.blockchain_anchors ba
            join public.document_versions dv on dv.id = ba.document_version_id
            where ba.evidence_id = v_evidence.id
              and ba.status = 'anchored'
              and ba.evidence_sha256 = dv.sha256
        ) then
            raise exception 'verification_required';
        end if;
    end if;

    -- 12. metadata limits (defense in depth; the route already trims).
    if p_location is not null and char_length(p_location) > 500 then
        raise exception 'invalid_custody_detail';
    end if;
    if p_notes is not null and char_length(p_notes) > 2000 then
        raise exception 'invalid_custody_detail';
    end if;

    -- 13. write the custody event. occurred_at is server-set to now(); a
    --     caller can never backdate (or predate) a possession record.
    insert into public.chain_of_custody (
        evidence_id, document_version_id, action, actor_id,
        from_profile_id, to_profile_id, location, notes, occurred_at
    ) values (
        v_evidence.id,
        p_document_version_id,
        v_action,
        v_actor,
        p_from_profile_id,
        p_to_profile_id,
        p_location,
        p_notes,
        now()
    )
    returning * into v_custody;

    -- 14. audit mirror in the SAME transaction. entity_type is 'evidence' (the
    --     portfolio-level audit vocabulary); org_id is set explicitly because
    --     case-level RPCs predate the org_id column and list_*_audit_events
    --     joins the case row — the explicit org_id keeps the reference resolvable.
    insert into public.audit_logs (actor_id, action, entity_type, entity_id, org_id, meta)
    values (
        v_actor,
        'custody.' || v_action,
        'evidence',
        v_evidence.id,
        v_case.org_id,
        jsonb_build_object(
            'case_id', v_case.id,
            'case_number', v_case.case_number,
            'evidence_id', v_evidence.id,
            'evidence_number', v_evidence.evidence_number,
            'title', v_evidence.title,
            'document_version_id', v_custody.document_version_id,
            'custody_event_id', v_custody.id,
            'action', v_action,
            'from_profile_id', v_custody.from_profile_id,
            'from_profile_name', (select p.full_name from public.profiles p where p.id = v_custody.from_profile_id),
            'to_profile_id', v_custody.to_profile_id,
            'to_profile_name', (select p.full_name from public.profiles p where p.id = v_custody.to_profile_id),
            'location', v_custody.location,
            'notes', v_custody.notes
        )
    );

    return v_custody;
end;
$function$;

alter function public.record_custody_event(uuid, text, uuid, uuid, uuid, text, text) owner to postgres;
revoke execute on function public.record_custody_event(uuid, text, uuid, uuid, uuid, text, text) from public, anon;
grant execute on function public.record_custody_event(uuid, text, uuid, uuid, uuid, text, text) to authenticated;

-- =============================================================================
-- PART 5: create_blockchain_anchor — block NEW anchor intents on closed cases
--
-- Recreated from the 20260917 hardened definition (org-aware is_case_member,
-- lead/investigator role, idempotent pending reuse / failed reset, fresh-pending
-- mint, same-transaction audit).
--
-- The ONLY behavioral addition: a brand-new anchor slot may only be minted
-- while the case is draft/active ('case_not_open' otherwise). An EXISTING
-- pending or failed slot is still reusable without any case-status check, so a
-- pending anchor created before closure continues to reconcile/confirm after
-- closure (requirement: the orchestrator must never be blocked mid-flight).
-- mark_anchor_anchored / mark_anchor_failed / reconcile_anchor_anchored are
-- intentionally left ungated.
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
    v_case_status    text;
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

    -- require org-aware case membership. A stale case_members row
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

    -- business rule: only a FRESH anchor intent requires an open case. There
    -- is no existing slot for this version, so minting one on a closed or
    -- archived case is rejected. (An existing pending slot is handled above
    -- and can still reconcile after closure.)
    select c.status into v_case_status
    from public.cases c
    where c.id = v_evidence.case_id;
    if not found then
        raise exception 'case_not_found';
    end if;
    if v_case_status not in ('draft', 'active') then
        raise exception 'case_not_open';
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
-- End of migration 20260918000000_case_close_immutability
-- =============================================================================