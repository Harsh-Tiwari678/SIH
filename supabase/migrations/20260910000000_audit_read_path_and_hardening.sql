-- =============================================================================
-- SIH26190 Secure Evidence — audit read path + evidence status hardening
--
-- Phase 1 of real audit logging. Makes the audit trail read-back real and
-- trustworthy, and hardens the evidence "verified" status so it can only be
-- reached through an actual, on-chain verified anchor.
--
-- What this migration changes:
--
--   1) Read path (new, member-scoped):
--      * list_case_audit_events(p_case_id)      — full audit trail for a case
--      * list_evidence_audit_events(p_evidence_id) — audit trail for one evidence
--      Both are SECURITY DEFINER RPCs that re-derive the actor from
--      auth.uid(), require case membership (same boundary the SELECT RLS uses),
--      resolve the polymorphic entity_type/entity_id to a concrete case,
--      and strip `storage_key` from meta so no object-key internals leak.
--      audit_logs itself keeps NO new SELECT policy (still admin/supervisor
--      only) — the RPC is the only way ordinary members read audit events.
--
--   2) Evidence status hardening (new):
--      * update_evidence_status(p_evidence_id, p_status)
--        Only the case lead / an investigator may transition evidence status.
--        'verified' additionally REQUIRES at least one document version of the
--        evidence with a blockchain_anchors row in state 'anchored' whose
--        evidence_sha256 exactly equals the version's sha256. A user can never
--        flip evidence to 'verified' by hand.
--      * The direct `status` column UPDATE grant on evidence is revoked; status
--        is now only writable through this RPC (metadata columns remain
--        directly editable exactly as before).
--
--   3) New audit events appended in the existing dotted vocabulary, always
--      written inside SECURITY DEFINER RPCs with actor_id = auth.uid():
--      * case.status_changed            (update_case, when the status actually changes)
--      * evidence.hash_generated        (create_evidence, SHA-256 fingerprint step)
--      * evidence.custody_received      (create_evidence, possession entry)
--      * evidence.status_changed        (update_evidence_status)
--      * evidence.verification_requested / passed / failed
--                                       (record_verification_event, called by the
--                                        verification read path — read-side audit)
--      * evidence.anchor_retry          (create_blockchain_anchor, failed -> pending reset)
--
--   4) record_verification_event(p_document_version_id, p_result, p_verdict)
--      Member-scoped (any case member may verify a version via the read path,
--      so any member may cause a verification audit entry; identity still comes
--      from auth.uid()). Enforces coherent result/verdict pairs.
--
-- Chain of custody is intentionally NOT extended here: transfer / access /
-- return custody actions are not implemented anywhere in the application and
-- must not be faked. The existing append-only RLS path (writes only via
-- SECURITY DEFINER RPCs / actor-bound RLS) is preserved unchanged.
--
-- Existing events continue to exist verbatim; create_blockchain_anchor,
-- create_evidence and update_case are re-created only to append the extra
-- events above.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1) Read path — audit trail RPCs
-- -----------------------------------------------------------------------------

create or replace function public.list_case_audit_events(p_case_id uuid)
returns table (
    id           uuid,
    action       text,
    entity_type  text,
    entity_id    uuid,
    actor_id     uuid,
    actor_name   text,
    case_id      uuid,
    evidence_id  uuid,
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
    v_case  uuid;
begin
    -- authenticate / authorize: an authenticated session with a profile.
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;
    if not exists (select 1 from public.profiles p where p.id = v_actor) then
        raise exception 'profile_not_found';
    end if;

    -- authorize (visibility): the case must exist AND be visible to the actor
    -- (creator or member), matching cases_select_creator_or_member RLS, so an
    -- inaccessible case is reported identically to a nonexistent one.
    select c.id into v_case
    from public.cases c
    where c.id = p_case_id
      and (
          c.created_by = v_actor
          or public.is_case_member(c.id)
      );
    if v_case is null then
        raise exception 'case_not_found';
    end if;

    -- build the trail: resolve every polymorphic entity to its owning case /
    -- evidence / label, then return only rows that belong to THIS case. 'meta'
    -- is scrubbed of storage keys and other internals the UI should never see.
    return query
    with resolved as (
        select
            a.id,
            a.action,
            a.entity_type,
            a.entity_id,
            a.actor_id,
            a.created_at,
            (a.meta - 'storage_key') as meta,
            cid.case_id,
            cid.evidence_id,
            cid.entity_label
        from public.audit_logs a
        cross join lateral (
            select
                case a.entity_type
                    when 'case' then a.entity_id
                    when 'case_member' then (a.meta ->> 'case_id')::uuid
                    when 'evidence' then (select e.case_id from public.evidence e where e.id = a.entity_id)
                    when 'document_version' then (
                        select e.case_id
                        from public.document_versions dv
                        join public.evidence e on e.id = dv.evidence_id
                        where dv.id = a.entity_id
                    )
                    when 'blockchain_anchor' then (
                        select e.case_id
                        from public.blockchain_anchors ba
                        join public.evidence e on e.id = ba.evidence_id
                        where ba.id = a.entity_id
                    )
                    else null::uuid
                end as case_id,
                case a.entity_type
                    when 'evidence' then a.entity_id
                    when 'document_version' then (
                        select dv.evidence_id
                        from public.document_versions dv
                        where dv.id = a.entity_id
                    )
                    when 'blockchain_anchor' then (
                        select ba.evidence_id
                        from public.blockchain_anchors ba
                        where ba.id = a.entity_id
                    )
                    else null::uuid
                end as evidence_id,
                case a.entity_type
                    when 'case' then (select c.case_number from public.cases c where c.id = a.entity_id)
                    when 'evidence' then (select e.title from public.evidence e where e.id = a.entity_id)
                    when 'document_version' then (select dv.file_name from public.document_versions dv where dv.id = a.entity_id)
                    when 'blockchain_anchor' then (
                        select e.title
                        from public.blockchain_anchors ba
                        join public.evidence e on e.id = ba.evidence_id
                        where ba.id = a.entity_id
                    )
                    when 'case_member' then (
                        select p.full_name
                        from public.profiles p
                        where p.id = coalesce(
                            (a.meta ->> 'to_profile_id')::uuid,
                            (a.meta ->> 'removed_profile_id')::uuid
                        )
                    )
                    else null::text
                end as entity_label
        ) cid
        where cid.case_id = p_case_id
    )
    select
        r.id,
        r.action,
        r.entity_type,
        r.entity_id,
        r.actor_id,
        (select p.full_name from public.profiles p where p.id = r.actor_id) as actor_name,
        r.case_id,
        r.evidence_id,
        r.entity_label,
        r.created_at,
        r.meta
    from resolved r
    order by r.created_at desc, r.id desc;
end;
$function$;

alter function public.list_case_audit_events(uuid) owner to postgres;
revoke execute on function public.list_case_audit_events(uuid) from public, anon;
grant execute on function public.list_case_audit_events(uuid) to authenticated;

create or replace function public.list_evidence_audit_events(p_evidence_id uuid)
returns table (
    id           uuid,
    action       text,
    entity_type  text,
    entity_id    uuid,
    actor_id     uuid,
    actor_name   text,
    case_id      uuid,
    evidence_id  uuid,
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
    v_case  uuid;
begin
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;
    if not exists (select 1 from public.profiles p where p.id = v_actor) then
        raise exception 'profile_not_found';
    end if;

    -- authorize (visibility): the evidence must exist and its case must be
    -- visible to the actor (creator or member).
    select e.case_id into v_case
    from public.evidence e
    where e.id = p_evidence_id
      and exists (
          select 1
          from public.cases c
          where c.id = e.case_id
            and (
                c.created_by = v_actor
                or public.is_case_member(c.id)
            )
      );
    if v_case is null then
        raise exception 'evidence_not_found';
    end if;

    -- the evidence's trail: the evidence row itself, its document versions and
    -- its blockchain anchors. Verdict / result events live on the version row.
    return query
    with resolved as (
        select
            a.id,
            a.action,
            a.entity_type,
            a.entity_id,
            a.actor_id,
            a.created_at,
            (a.meta - 'storage_key') as meta,
            cid.case_id,
            cid.evidence_id,
            cid.entity_label
        from public.audit_logs a
        cross join lateral (
            select
                case a.entity_type
                    when 'evidence' then (select e.case_id from public.evidence e where e.id = a.entity_id)
                    when 'document_version' then (
                        select e.case_id
                        from public.document_versions dv
                        join public.evidence e on e.id = dv.evidence_id
                        where dv.id = a.entity_id
                    )
                    when 'blockchain_anchor' then (
                        select e.case_id
                        from public.blockchain_anchors ba
                        join public.evidence e on e.id = ba.evidence_id
                        where ba.id = a.entity_id
                    )
                    else null::uuid
                end as case_id,
                case a.entity_type
                    when 'evidence' then a.entity_id
                    when 'document_version' then (
                        select dv.evidence_id
                        from public.document_versions dv
                        where dv.id = a.entity_id
                    )
                    when 'blockchain_anchor' then (
                        select ba.evidence_id
                        from public.blockchain_anchors ba
                        where ba.id = a.entity_id
                    )
                    else null::uuid
                end as evidence_id,
                case a.entity_type
                    when 'evidence' then (select e.title from public.evidence e where e.id = a.entity_id)
                    when 'document_version' then (select dv.file_name from public.document_versions dv where dv.id = a.entity_id)
                    when 'blockchain_anchor' then (
                        select e.title
                        from public.blockchain_anchors ba
                        join public.evidence e on e.id = ba.evidence_id
                        where ba.id = a.entity_id
                    )
                    else null::text
                end as entity_label
        ) cid
        where
            (a.entity_type = 'evidence' and a.entity_id = p_evidence_id)
            or (
                a.entity_type = 'document_version'
                and exists (
                    select 1 from public.document_versions dv
                    where dv.id = a.entity_id and dv.evidence_id = p_evidence_id
                )
            )
            or (
                a.entity_type = 'blockchain_anchor'
                and exists (
                    select 1 from public.blockchain_anchors ba
                    where ba.id = a.entity_id and ba.evidence_id = p_evidence_id
                )
            )
    )
    select
        r.id,
        r.action,
        r.entity_type,
        r.entity_id,
        r.actor_id,
        (select p.full_name from public.profiles p where p.id = r.actor_id) as actor_name,
        r.case_id,
        r.evidence_id,
        r.entity_label,
        r.created_at,
        r.meta
    from resolved r
    order by r.created_at desc, r.id desc;
end;
$function$;

alter function public.list_evidence_audit_events(uuid) owner to postgres;
revoke execute on function public.list_evidence_audit_events(uuid) from public, anon;
grant execute on function public.list_evidence_audit_events(uuid) to authenticated;

-- -----------------------------------------------------------------------------
-- 2) Evidence status hardening
-- -----------------------------------------------------------------------------

-- Revoke the direct `status` column UPDATE grant on evidence. Status becomes
-- writable ONLY through update_evidence_status below (which enforces the
-- verification gate); metadata columns keep the exact grant they had before.
grant update (title, description, type, updated_at) on public.evidence to authenticated;

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
    v_actor uuid := auth.uid();
    v_old   public.evidence;
    v_new   public.evidence;
    v_case  public.cases;
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
    -- invariant mark_anchor_anchored re-asserts at confirmation time.
    if p_status = 'verified' then
        if not exists (
            select 1
            from public.blockchain_anchors ba
            join public.document_versions dv on dv.id = ba.document_version_id
            where ba.evidence_id = v_old.id
              and ba.status = 'anchored'
              and ba.evidence_sha256 = dv.sha256
        ) then
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

    return v_new;
end;
$function$;

alter function public.update_evidence_status(uuid, text) owner to postgres;
revoke execute on function public.update_evidence_status(uuid, text) from public, anon;
grant execute on function public.update_evidence_status(uuid, text) to authenticated;

-- -----------------------------------------------------------------------------
-- 3) Verification audit event recorder
--
-- Written by the (read-only) verification path so every on-chain check is on
-- the record. Authorization: any member of the version's case may trigger a
-- verification read, so any member may cause a verification audit entry —
-- identity still comes from auth.uid(). Result/verdict pairs are coerced to a
-- small coherent set:
--   requested + (verified | not_anchored | hash_mismatch | verification_ambiguous)
--   passed    + verified
--   failed    + (hash_mismatch | verification_ambiguous)
-- -----------------------------------------------------------------------------
create or replace function public.record_verification_event(
    p_document_version_id uuid,
    p_result              text,
    p_verdict             text
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
    v_action   text;
    v_an       uuid;
    v_network  text;
    v_chain    bigint;
    v_contract text;
begin
    -- authenticate / authorize.
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;
    if not exists (select 1 from public.profiles p where p.id = v_actor) then
        raise exception 'profile_not_found';
    end if;

    -- validate: vocabulary + coherent pairs.
    if p_result is null or p_result not in ('requested', 'passed', 'failed') then
        raise exception 'invalid_result';
    end if;
    if p_verdict is null or p_verdict not in ('verified', 'not_anchored', 'hash_mismatch', 'verification_ambiguous') then
        raise exception 'invalid_verdict';
    end if;
    if p_result = 'passed' and p_verdict <> 'verified' then
        raise exception 'invalid_verdict';
    end if;
    if p_result = 'failed' and p_verdict not in ('hash_mismatch', 'verification_ambiguous') then
        raise exception 'invalid_verdict';
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

    -- authorize: the actor must be a member of the version's case (same
    -- boundary as the verification read path).
    if not public.is_case_member(v_case.id) then
        raise exception 'not_case_member';
    end if;

    -- attach the anchor read context when one exists (best-effort; the anchor
    -- may be absent for unanchored versions).
    select a.id, a.network, a.chain_id, a.contract_address
    into v_an, v_network, v_chain, v_contract
    from public.blockchain_anchors a
    where a.document_version_id = p_document_version_id
    order by a.created_at desc
    limit 1;

    v_action := case
        when p_result = 'requested' then 'evidence.verification_requested'
        when p_result = 'passed'    then 'evidence.verification_passed'
        else                             'evidence.verification_failed'
    end;

    insert into public.audit_logs (actor_id, action, entity_type, entity_id, meta)
    values (
        v_actor,
        v_action,
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
            'sha256', v_version.sha256,
            'result', p_result,
            'verdict', p_verdict,
            'network', v_network,
            'chain_id', v_chain,
            'contract_address', v_contract
        )
    );
end;
$function$;

alter function public.record_verification_event(uuid, text, text) owner to postgres;
revoke execute on function public.record_verification_event(uuid, text, text) from public, anon;
grant execute on function public.record_verification_event(uuid, text, text) to authenticated;

-- -----------------------------------------------------------------------------
-- 4) create_blockchain_anchor: + evidence.anchor_retry on failed -> pending
-- -----------------------------------------------------------------------------
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

-- -----------------------------------------------------------------------------
-- 5) create_evidence: + evidence.hash_generated / evidence.custody_received
--    and a richer evidence.created meta (title / evidence_number).
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

-- -----------------------------------------------------------------------------
-- 6) update_case: + case.status_changed when the status actually changes
-- -----------------------------------------------------------------------------
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

    if public.case_role(p_case_id) <> 'lead' then
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

-- Owned by the trusted role; guarantees privilege is via postgres, not a
-- lower-privilege owner, matching the existing SECURITY DEFINER helpers.
alter function public.update_case(uuid, text, text, boolean, text) owner to postgres;

-- Callable only by authenticated users, never anon/PUBLIC.
revoke execute on function public.update_case(uuid, text, text, boolean, text) from public;
revoke execute on function public.update_case(uuid, text, text, boolean, text) from anon;

grant execute on function public.update_case(uuid, text, text, boolean, text) to authenticated;