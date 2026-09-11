-- =============================================================================
-- SIH26190 Secure Evidence — operational chain-of-custody workflow
--
-- Phase 2 (minimal). Prior state: chain_of_custody rows were written ONLY by
-- create_evidence() ('received'), while a direct INSERT RLS policy
-- (chain_of_custody_insert_lead_or_investigator) let any lead/investigator
-- fabricate custody rows straight through the table — no audit mirror, no
-- server-set timestamps, and an attacker-controlled actor_id/occurred_at.
--
-- This migration:
--
--   1. record_custody_event() — the ONLY non-intake writer of custody rows.
--      SECURITY DEFINER, actor derived from auth.uid() (never from arguments),
--      occurred_at set server-side to now() (client backdating/imposture is
--      impossible), action vocabulary + shape rules enforced, from/to must be
--      members of the SAME case, the audit mirror is written in the SAME
--      transaction (with org_id set, unlike the case-level RPCs which predate
--      the org_id column), and every fallible path fails closed.
--
--   2. Direct-INSERT gap closed: the authenticated INSERT grant and the
--      direct INSERT policy on chain_of_custody are removed. The SELECT grant
--      / org-aware SELECT policy are untouched (read access is unchanged).
--
--   3. update_evidence_status() extended so a status transition to 'verified'
--      (which is already anchor-gated) or to 'archived' ALSO records the
--      corresponding possession event in the SAME transaction, idempotently —
--      a retried transition never duplicates a custody row, and the existing
--      audit behavior is preserved exactly.
--
-- Explicit, documented limitation (do not extend beyond this silently):
--   this phase records *validated events*; it does NOT implement a strict
--   "current holder" state machine or an acceptor handshake. A 'transferred'
--   event does not lock the evidence to its new holder, and there is no
--   cryptographic handshake between actor and recipient. The server-forced
--   actor_id / occurred_at guarantees that every event is attributable to the
--   authenticated session that issued it; proving "the evidence is currently
--   at X" is out of scope for the minimal phase.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- 1) record_custody_event — validated, audited custody writes
-- ---------------------------------------------------------------------------

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

-- ---------------------------------------------------------------------------
-- 2) Close the direct-INSERT gap on chain_of_custody
--
-- The INSERT policy is dropped and the authenticated INSERT grant revoked.
-- From now on create_evidence() (intake) and record_custody_event() (all
-- later events) are the ONLY writers — both SECURITY DEFINER, both audit every
-- write, both derive the actor from auth.uid(). SELECT (org-aware) is kept.
-- service_role is untouched.
-- ---------------------------------------------------------------------------

drop policy if exists "chain_of_custody_insert_lead_or_investigator" on public.chain_of_custody;
revoke insert on table public.chain_of_custody from authenticated;
-- Supabase's schema-default ACL grants UPDATE/DELETE/TRUNCATE to
-- authenticated for every table created in public. Those surfaced here too:
-- RLS already made possession rows immutable (no UPDATE/DELETE policy exists,
-- so every row is filtered out), but the privilege layer should not pretend
-- otherwise. Revoke them so a mutation is rejected at the granularity of the
-- exact code someone reads in \dp, not merely filtered by RLS.
revoke update, delete, truncate on table public.chain_of_custody from authenticated;

-- ---------------------------------------------------------------------------
-- 3) update_evidence_status — record possession when status reaches
--    'verified' (anchor-gated) or 'archived'.
--
-- Minimal extension of the hardened status transition: the anchor gate is
-- unchanged, the audit behavior is unchanged, and the corresponding custody
-- entry is created in the SAME transaction. The existence check makes the
-- custody write idempotent across a duplicated transition (the existing
-- unchanged-status early return already handles most retries).
-- ---------------------------------------------------------------------------

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
    v_actor           uuid := auth.uid();
    v_old             public.evidence;
    v_new             public.evidence;
    v_case            public.cases;
    v_anchor_version  uuid;
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
    -- SAME transaction. Idempotent — a duplicated transition (or an existing
    -- record_custody_event('verified')) never creates a second row. The
    -- possession record is intentionally the ONLY addition here; the status
    -- transition's own audit row above is unchanged.
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

-- ---------------------------------------------------------------------------
-- 4) Relax the possession CHECK so possession-NEUTRAL events can be recorded
--
-- The intake migration constrained every custody row with
--
--     check (from_profile_id is distinct from to_profile_id)
--
-- which is exactly right for a HANDOFF (received/transferred/returned) but
-- wrong for the three events the workflow treats as possession-neutral:
--
--   * verified — possession does not move; the row only documents that a
--                lead anchored the chain to a verified document version.
--   * released — possession is not claimed by anyone else; the row only
--                documents that possession terminated.
--   * archived — same shape as released, via the status path.
--
-- For those, both arms are NULL, and `NULL IS DISTINCT FROM NULL` is FALSE,
-- so the intake check rejected the row before it could be written. Because
-- all credentialed writers (record_custody_event, create_evidence, and the
-- update_evidence_status extension) deliberately leave both arms NULL for
-- these three events, the constraint must tolerate the (null, null) shape.
--
-- The ban on self-handoff is retained verbatim: neither arm NULL, from = to.
-- One arm NULL remains legal (received/released), and both arms populated
-- must name different profiles (transferred/returned).
-- ---------------------------------------------------------------------------
alter table public.chain_of_custody
    drop constraint if exists chain_of_custody_check;

alter table public.chain_of_custody
    add constraint chain_of_custody_check
    check (
        from_profile_id is null
        or to_profile_id is null
        or from_profile_id <> to_profile_id
    );

alter table public.chain_of_custody owner to postgres;
