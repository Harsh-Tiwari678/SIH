-- =============================================================================
-- SIH26190 Secure Evidence — block fabricated blockchain anchor state (audit C1)
--
-- BACKGROUND
--   mark_anchor_anchored / mark_anchor_failed / reconcile_anchor_anchored were
--   granted EXECUTE to `authenticated`, so ANY signed-in user could invoke them
--   through PostgREST with CALLER-SUPPLIED transaction metadata and put a
--   blockchain_anchors row into 'anchored' with no real Ethereum transaction at
--   all. update_evidence_status('verified') then accepted that row because its
--   gate only required status='anchored' AND a matching stored SHA-256.
--
-- THE FIX
--   1. REVOKE `authenticated` EXECUTE from the three state-mutating RPCs. They
--      become owner-only (postgres) and are no longer reachable from any
--      browser session or PostgREST client.
--   2. Add a single gateway function, public.anchor_state_apply(...), granted
--      to `authenticated` — the ONLY role a PostgREST session ever runs as —
--      that additionally requires a server confirmation digest. The digest is
--      the SHA-256 of ANCHOR_CONFIRMATION_SECRET (a 256-bit value held only by
--      the server, in .env.local). The RAW SECRET NEVER appears in the
--      database or on the wire, only its digest; a 256-bit preimage search is
--      infeasible, so possession of the digest is a real server capability.
--   3. The gateway REDISPATCHES to the (now revoked) functions, which still
--      enforce everything they always did: auth.uid()-based lead/investigator
--      authorization, pending-only terminal transitions, stored-hash invariant
--      re-checks, terminal-state guards, and audit writes. auth.uid() is
--      therefore necessary but never sufficient — a user needs BOTH the case
--      role AND a server-produced confirmation.
--   4. HARDEN the 'verified' transition so it additionally requires a
--      persisted, non-NULL tx_hash. Reconciled rows (which by design carry
--      tx_hash = NULL, since an on-chain read cannot recover a hash) can no
--      longer satisfy the gate, so mere status='anchored' + matching hash is no
--      longer enough to produce a verified evidence row.
--
-- The independent on-chain verification endpoint (a real EvidenceAnchor read)
-- is unchanged and remains the definitive check that a row is genuinely backed
-- by the chain.
--
-- ROTATION
--   Rotate ANCHOR_CONFIRMATION_SECRET by (a) generating a fresh 256-bit value,
--   (b) putting it into .env.local, (c) embedding its SHA-256 digest as
--   v_expected_confirmation in a NEW migration — never editing this one
--   retroactively.
--
--   NOTE: the development secret that produced the digest above was exposed in
--   audit/development output. Treat it as compromised: rotate it (steps a–c)
--   BEFORE any staging or production use. The digest in this migration is left
--   untouched until that rotation lands in a new migration.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- PART 1: remove the browser-reachable write surface on anchor state.
-- ---------------------------------------------------------------------------

revoke execute on function public.mark_anchor_anchored(uuid, text, bigint, timestamptz) from public, anon, authenticated;
revoke execute on function public.mark_anchor_failed(uuid, text) from public, anon, authenticated;
revoke execute on function public.reconcile_anchor_anchored(uuid, bigint, timestamptz) from public, anon, authenticated;

-- ---------------------------------------------------------------------------
-- PART 2: single server-gated gateway for anchor state transitions.
-- ---------------------------------------------------------------------------

create or replace function public.anchor_state_apply(
    p_action             text,
    p_anchor_id          uuid,
    p_tx_hash            text,
    p_block_number       bigint,
    p_anchored_at        timestamptz,
    p_error_message      text,
    p_confirmation_token text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
    -- SHA-256 digest of ANCHOR_CONFIRMATION_SECRET. The secret itself is never
    -- stored in the database; comparing digests keeps the secret server-only.
    -- Any rotation MUST land here as a new migration with the new digest.
    v_expected_confirmation constant text := 'f74f6dcf7db30762071cd334efb9e92859c4d1b88ba81114765a386136418a23';
begin
    if p_anchor_id is null or p_confirmation_token is null then
        raise exception 'invalid_anchor_params';
    end if;

    -- Capability gate: only server code able to read ANCHOR_CONFIRMATION_SECRET
    -- can produce this digest. This is the boundary that turns PostgREST-exposed
    -- RPCs into server-only transitions regardless of the caller's role.
    if p_confirmation_token <> v_expected_confirmation then
        raise exception 'invalid_confirmation';
    end if;

    -- Dispatch to the (now owner-only) transition RPCs. These still derive the
    -- actor from auth.uid() and enforce lead/investigator authorization, the
    -- pending-only transition rule, the stored-hash invariant, and the audit
    -- writes — the gateway adds the capability requirement, it does not replace
    -- any of the original checks.
    if p_action = 'anchored' then
        return public.mark_anchor_anchored(p_anchor_id, p_tx_hash, p_block_number, p_anchored_at);
    end if;

    if p_action = 'failed' then
        return public.mark_anchor_failed(p_anchor_id, p_error_message);
    end if;

    if p_action = 'reconcile' then
        return public.reconcile_anchor_anchored(p_anchor_id, p_block_number, p_anchored_at);
    end if;

    raise exception 'invalid_action';
end;
$function$;

alter function public.anchor_state_apply(text, uuid, text, bigint, timestamptz, text, text) owner to postgres;
revoke execute on function public.anchor_state_apply(text, uuid, text, bigint, timestamptz, text, text) from public, anon;
grant execute on function public.anchor_state_apply(text, uuid, text, bigint, timestamptz, text, text) to authenticated;

-- ---------------------------------------------------------------------------
-- PART 3: harden the 'verified' transition to require a persisted tx_hash.
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
    -- mark_anchor_anchored re-asserts at confirmation time — AND that row must
    -- carry a PERSISTED, non-NULL transaction hash. A reconciled row
    -- (tx_hash = NULL by design, because an on-chain read cannot recover one)
    -- proves the chain holds our hash but not a confirmed broadcast, so it can
    -- never satisfy the verified gate. Since direct anchor writes are now
    -- revoked and the gateway requires the server confirmation, the only way a
    -- row reaches 'anchored' WITH a non-null tx_hash is the server-side
    -- confirmation path. The matching version is captured for the custody entry
    -- below.
    if p_status = 'verified' then
        select ba.document_version_id into v_anchor_version
        from public.blockchain_anchors ba
        join public.document_versions dv on dv.id = ba.document_version_id
        where ba.evidence_id = v_old.id
          and ba.status = 'anchored'
          and ba.evidence_sha256 = dv.sha256
          and ba.tx_hash is not null
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