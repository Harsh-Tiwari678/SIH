-- =============================================================================
-- SIH26190 Secure Evidence — blockchain_anchors reconciliation
--
-- Recovers the distributed-failure window of the anchor lifecycle:
--
--   ETH tx confirmed on-chain  ->  mark_anchor_anchored DB write fails
--                               ->  row stays 'pending'
--                               ->  a naive retry would REBROADCAST, hit the
--                                   contract's AlreadyAnchored guard, and the
--                                   orchestrator could then only mark the row
--                                   'failed' — the DB could never converge to
--                                   'anchored' even though the chain is right.
--
-- This migration adds `reconcile_anchor_anchored`, the DB-side primitive that
-- lets the server converge a 'pending' row to 'anchored' from a READ-ONLY
-- on-chain observation, WITHOUT sending a second Ethereum transaction and
-- WITHOUT fabricating a transaction hash.
--
-- TRUST / SEQUENCE (important):
--   * The server first proves on-chain truth with a read: EvidenceAnchor
--     getAnchor(evidence_id_hash, version_id_hash) + verify() against the
--     expected SHA-256. The hashes used are exactly the deterministic bytes32
--     encodings the anchor row already stores (uuid_to_bytes32 / sha256), so
--     the read is keyed to THIS version's slot and can only match our own data.
--   * Only on a match does the server call this RPC with the block metadata
--     observed on-chain (block_number, anchored_at). This RPC NEVER contacts
--     Ethereum and NEVER accepts caller-supplied evidence content — it re-loads
--     the anchor by id, re-checks the actor/profile/case authorization exactly
--     like mark_anchor_anchored, re-asserts the stored-hash invariant, and
--     transitions pending -> anchored.
--   * tx_hash is deliberately NOT a parameter and is never written here: the
--     on-chain read cannot return a transaction hash, and inventing one is
--     forbidden. Reconciled rows therefore carry tx_hash = NULL (the column
--     CHECK already permits this). Integrity still holds via evidence_sha256 +
--     block_number + anchored_at + the audit trail. A future block-scan
--     backfill could recover the hash without changing this contract.
--   * State machine is preserved exactly: only pending -> anchored, guarded by
--     `where status = 'pending'`. A terminal (anchored/failed) row is never
--     mutated, so a mismatched reconcile attempt can never overwrite valid
--     state.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- reconcile_anchor_anchored(p_anchor_id, p_block_number, p_anchored_at)
--
-- Attr: called ONLY by the server after it has already proven via a read-only
--       contract call that this anchor's slot holds its expected evidence hash.
--       Mirrors mark_anchor_anchored (auth, profile, case lead/investigator,
--       stored-hash invariant, pending-only transition, audit) with the single
--       deliberate difference: NO p_tx_hash parameter — it stays NULL.
-- -----------------------------------------------------------------------------
create or replace function public.reconcile_anchor_anchored(
    p_anchor_id     uuid,
    p_block_number  bigint,
    p_anchored_at   timestamptz
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
    v_actor   uuid := auth.uid();
    v_anchor  public.blockchain_anchors;
    v_updated boolean := false;
begin
    -- authenticate: derive the actor from the session, never from arguments.
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;

    -- authorize: the actor must have an application profile.
    if not exists (select 1 from public.profiles p where p.id = v_actor) then
        raise exception 'profile_not_found';
    end if;

    -- validate: block metadata sanity — the same bounds mark_anchor_anchored
    -- enforces (minus the tx_hash regex, which intentionally does not apply).
    if p_block_number is null or p_block_number < 1 then
        raise exception 'invalid_tx_metadata';
    end if;
    if p_anchored_at is null then
        raise exception 'invalid_tx_metadata';
    end if;

    -- authorize + load: the anchor must exist and the actor must be a
    -- lead/investigator on the evidence's case.
    select a.* into v_anchor
    from public.blockchain_anchors a
    where a.id = p_anchor_id
    for update;
    if not found then
        raise exception 'anchor_not_found';
    end if;

    if not exists (
        select 1
        from public.case_members m
        where m.case_id = (select e.case_id from public.evidence e where e.id = v_anchor.evidence_id)
          and m.profile_id = v_actor
          and m.role_in_case in ('lead', 'investigator')
    ) then
        raise exception 'not_authorized_to_anchor';
    end if;

    -- enforce that the stored hash equals the version's hash (the same
    -- invariant mark_anchor_anchored re-asserts before recording success).
    if v_anchor.evidence_sha256 is distinct from (
        select dv.sha256 from public.document_versions dv
        where dv.id = v_anchor.document_version_id
    ) then
        raise exception 'hash_mismatch';
    end if;

    -- only transition pending -> anchored; NEVER mutate a terminal row and
    -- NEVER write tx_hash (it is unrecoverable by a chain read and must not be
    -- invented). The column CHECK guarantees an anchored/reconciled row may
    -- carry a NULL tx_hash.
    update public.blockchain_anchors
    set status        = 'anchored',
        block_number  = p_block_number,
        anchored_at   = p_anchored_at,
        error_message = null,
        updated_at    = now()
    where id = p_anchor_id
      and status = 'pending'
    returning * into v_anchor;

    v_updated := found;
    if not v_updated then
        -- already anchored (or otherwise terminal); return unchanged.
        select a.* into v_anchor
        from public.blockchain_anchors a
        where a.id = p_anchor_id;
        return jsonb_build_object('anchor', to_jsonb(v_anchor), 'transitioned', false);
    end if;

    insert into public.audit_logs (actor_id, action, entity_type, entity_id, after, meta)
    values (
        v_actor,
        'evidence.anchor_reconciled',
        'blockchain_anchor',
        v_anchor.id,
        to_jsonb(v_anchor),
        jsonb_build_object(
            'evidence_id', v_anchor.evidence_id,
            'document_version_id', v_anchor.document_version_id,
            'network', v_anchor.network,
            'chain_id', v_anchor.chain_id,
            'contract_address', v_anchor.contract_address,
            'block_number', p_block_number,
            'anchored_at', p_anchored_at,
            'evidence_sha256', v_anchor.evidence_sha256
        )
    );

    return jsonb_build_object('anchor', to_jsonb(v_anchor), 'transitioned', true);
end;
$function$;

alter function public.reconcile_anchor_anchored(uuid, bigint, timestamptz) owner to postgres;
revoke execute on function public.reconcile_anchor_anchored(uuid, bigint, timestamptz) from public, anon;
grant execute on function public.reconcile_anchor_anchored(uuid, bigint, timestamptz) to authenticated;