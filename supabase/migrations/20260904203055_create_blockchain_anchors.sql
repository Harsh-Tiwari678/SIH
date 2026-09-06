-- =============================================================================
-- SIH26190 Secure Evidence — blockchain_anchors
--
-- Tracks the link between a document_version and its immutable on-chain
-- integrity anchor (EvidenceAnchor on Ethereum Sepolia).
--
-- CRITICAL FAILURE-BOUNDARY RULE:
--   A PostgreSQL transaction CANNOT roll back an Ethereum transaction, and
--   vice versa. These are two independent systems. The design therefore never
--   assumes cross-system atomicity:
--     * The DB owns the *intent* ("we want this SHA-256 anchored") as a
--       'pending' row, and the authoritative record of *where* it landed
--       ('anchored' row with tx_hash / block_number / anchored_at).
--     * The chain owns the actual append-only receipt of the hash + timestamp.
--   The RPCs here only mutate DB state; Ethereum is never contacted from SQL.
--   Confirmation / failure are recorded via dedicated SECURITY DEFINER RPCs
--   (mark_anchor_anchored / mark_anchor_failed), driven by the server after it
--   observes the on-chain result. Retries are idempotent across both systems:
--     - DB side:   UNIQUE(document_version_id)  +  pending->anchored|failed
--                  conditional transitions (never mutate a terminal row).
--     - Chain side: EvidenceAnchor.anchor() reverts AlreadyAnchored if the
--                  (evidence_id_hash, version_id_hash) pair is already set.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Helper: deterministic UUID -> bytes32 encoding, exactly as EvidenceAnchor.
-- The contract left-pads the 16-byte UUID with 16 zero bytes, so the UUID
-- occupies the right-most 16 bytes of the bytes32 value. This mirrors the
-- JS helper `hex.padStart(64, "0")` used by the test suite and deploy layer.
-- -----------------------------------------------------------------------------
create or replace function public.uuid_to_bytes32(p_uuid uuid)
returns text
language sql
stable
security definer
set search_path = ''
as $function$
    select '0x' || lpad(replace(p_uuid::text, '-', ''), 64, '0');
$function$;

alter function public.uuid_to_bytes32(uuid) owner to postgres;
revoke execute on function public.uuid_to_bytes32(uuid) from public, anon;
grant execute on function public.uuid_to_bytes32(uuid) to authenticated;

-- -----------------------------------------------------------------------------
-- 0) Table
-- -----------------------------------------------------------------------------
create table public.blockchain_anchors (
    id                  uuid primary key default gen_random_uuid(),

    -- Relationship: one document_version -> at most one anchor (UNIQUE below).
    -- Evidence/versions are never hard-deleted (ON DELETE RESTRICT), so an
    -- anchor row can never outlive or silently outpoint a deleted row.
    evidence_id         uuid not null references public.evidence (id) on delete restrict,
    document_version_id uuid not null references public.document_versions (id) on delete restrict,

    -- Explicit network identity so historical records stay understandable even
    -- if the contract is later replaced.
    network             text not null check (network ~ '^[a-z0-9]+$'),
    chain_id            bigint not null check (chain_id > 0),
    contract_address    text not null check (contract_address ~ '^0x[0-9a-fA-F]{40}$'),

    -- Deterministic bytes32 encodings used for on-chain lookup/verify, exactly
    -- as produced by EvidenceAnchor's UUID -> bytes32 convention.
    evidence_id_hash    text not null check (evidence_id_hash ~ '^0x[0-9a-fA-F]{64}$'),
    version_id_hash     text not null check (version_id_hash ~ '^0x[0-9a-fA-F]{64}$'),

    -- The exact SHA-256 digest stored on the document_version row. Not PII.
    evidence_sha256     text not null check (evidence_sha256 ~ '^[0-9a-f]{64}$'),

    -- Transaction lifecycle: nullable until confirmed.
    tx_hash             text check (tx_hash is null or tx_hash ~ '^0x[0-9a-fA-F]{64}$'),
    block_number        bigint check (block_number is null or block_number > 0),
    anchored_at         timestamptz,

    -- State machine: pending -> anchored | failed (terminal).
    status              text not null default 'pending'
                        check (status in ('pending', 'anchored', 'failed')),
    error_message       text check (error_message is null or char_length(error_message) <= 2000),

    created_at          timestamptz not null default now(),
    updated_at          timestamptz not null default now(),

    -- One anchor record per document_version.
    constraint blockchain_anchors_document_version_unique unique (document_version_id)
);

-- Indexes for lookup / verification / reconciliation paths.
create index blockchain_anchors_key_hash_idx
    on public.blockchain_anchors (evidence_id_hash, version_id_hash);
create index blockchain_anchors_status_created_idx
    on public.blockchain_anchors (status, created_at);

-- -----------------------------------------------------------------------------
-- 1) RLS
--    * SELECT: authenticated case members can read anchors for evidence in a
--      case they belong to (resolved via evidence -> case membership, the same
--      boundary used for evidence / document_versions reads).
--    * INSERT / UPDATE / DELETE: NO policies -> denied by default. Anchors are
--      written ONLY by the SECURITY DEFINER RPCs below (running as postgres),
--      so no direct client path can mint or mutate an anchor.
-- -----------------------------------------------------------------------------
alter table public.blockchain_anchors enable row level security;

drop policy if exists "blockchain_anchors_select_case_members" on public.blockchain_anchors;
create policy "blockchain_anchors_select_case_members"
on public.blockchain_anchors
for select
to authenticated
using (
    exists (
        select 1
        from public.evidence e
        where e.id = evidence_id
          and public.is_case_member(e.case_id)
    )
);

revoke all on public.blockchain_anchors from anon;
grant select on public.blockchain_anchors to authenticated;

-- -----------------------------------------------------------------------------
-- 2) create_blockchain_anchor(document_version_id)
--
-- Initiates anchoring: creates (or reuses) a 'pending' anchor row for the
-- specified document_version. It NEVER contacts Ethereum and NEVER accepts a
-- SHA-256 from the client: evidence_sha256 is read directly from
-- document_versions and enforced to be equal inside this RPC. The current
-- blockchain network/contract configuration is enforced here (update this
-- migration if the contract is ever replaced).
--
-- Idempotency / duplicate prevention:
--   * A row already 'anchored'      -> raise already_anchored (terminal, never
--                                      re-created).
--   * A row already 'pending'       -> return it unchanged (in-flight).
--   * A row already 'failed'        -> reset to 'pending' and return, so a
--                                      retry reuses the slot (no second row).
--   * No row                        -> insert a fresh 'pending' row.
--   The UNIQUE(document_version_id) constraint and the on-chain
--   AlreadyAnchored guard jointly prevent double-anchoring.
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
        -- status = 'failed': reset to pending and reuse the slot.
        update public.blockchain_anchors
        set status = 'pending',
            error_message = null,
            updated_at = now()
        where id = v_anchor.id
        returning * into v_anchor;
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
-- 3) mark_anchor_anchored(p_anchor_id, p_tx_hash, p_block_number, p_anchored_at)
--
-- Records a confirmed on-chain anchor. The server calls this AFTER it observes
-- a successful Ethereum transaction for the anchor's (evidence_id_hash,
-- version_id_hash). Only transitions pending -> anchored. It validates the
-- supplied transaction metadata and that the stored hash equals the version's
-- hash, then stores the authoritative blockchain timestamp (anchored_at) and
-- writes an 'evidence.anchored' audit log. An already-anchored row is never
-- mutated.
-- -----------------------------------------------------------------------------
create or replace function public.mark_anchor_anchored(
    p_anchor_id     uuid,
    p_tx_hash       text,
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
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;
    if not exists (select 1 from public.profiles p where p.id = v_actor) then
        raise exception 'profile_not_found';
    end if;

    -- validate: transaction metadata sanity.
    if p_tx_hash is null or p_tx_hash !~ '^0x[0-9a-fA-F]{64}$' then
        raise exception 'invalid_tx_metadata';
    end if;
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

    -- enforce that the stored hash equals the version's hash (should always
    -- hold because create_blockchain_anchor derived it from the version; this
    -- re-asserts the invariant at confirmation time).
    if v_anchor.evidence_sha256 is distinct from (
        select dv.sha256 from public.document_versions dv
        where dv.id = v_anchor.document_version_id
    ) then
        raise exception 'hash_mismatch';
    end if;

    -- only transition pending -> anchored; never mutate a terminal row.
    update public.blockchain_anchors
    set status        = 'anchored',
        tx_hash       = p_tx_hash,
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
        'evidence.anchored',
        'blockchain_anchor',
        v_anchor.id,
        to_jsonb(v_anchor),
        jsonb_build_object(
            'evidence_id', v_anchor.evidence_id,
            'document_version_id', v_anchor.document_version_id,
            'network', v_anchor.network,
            'chain_id', v_anchor.chain_id,
            'contract_address', v_anchor.contract_address,
            'tx_hash', p_tx_hash,
            'block_number', p_block_number,
            'anchored_at', p_anchored_at,
            'evidence_sha256', v_anchor.evidence_sha256
        )
    );

    return jsonb_build_object('anchor', to_jsonb(v_anchor), 'transitioned', true);
end;
$function$;

alter function public.mark_anchor_anchored(uuid, text, bigint, timestamptz) owner to postgres;
revoke execute on function public.mark_anchor_anchored(uuid, text, bigint, timestamptz) from public, anon;
grant execute on function public.mark_anchor_anchored(uuid, text, bigint, timestamptz) to authenticated;

-- -----------------------------------------------------------------------------
-- 4) mark_anchor_failed(p_anchor_id, p_error_message)
--
-- Records a definitive on-chain failure for a pending anchor. Only transitions
-- pending -> failed. Stores a BOUNDED, SANITIZED error message — the server is
-- responsible for scrubbing provider/reason text (never secrets, keys, or
-- request payloads) before calling this RPC; the length CHECK backstops it.
-- Writes an 'evidence.anchor_failed' audit log. Never exposes secrets; never
-- mutates an anchored row.
-- -----------------------------------------------------------------------------
create or replace function public.mark_anchor_failed(
    p_anchor_id     uuid,
    p_error_message text
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
    v_clean   text;
begin
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;
    if not exists (select 1 from public.profiles p where p.id = v_actor) then
        raise exception 'profile_not_found';
    end if;

    -- bound + sanitize the message (strip any line breaks that could corrupt
    -- logs/UI; length is additionally backstopped by the column CHECK).
    v_clean := null;
    if p_error_message is not null then
        v_clean := left(regexp_replace(p_error_message, '[\r\n]+', ' ', 'g'), 2000);
    end if;

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

    -- only transition pending -> failed; never mutate a terminal row.
    update public.blockchain_anchors
    set status        = 'failed',
        error_message = v_clean,
        updated_at    = now()
    where id = p_anchor_id
      and status = 'pending'
    returning * into v_anchor;

    v_updated := found;
    if not v_updated then
        select a.* into v_anchor
        from public.blockchain_anchors a
        where a.id = p_anchor_id;
        return jsonb_build_object('anchor', to_jsonb(v_anchor), 'transitioned', false);
    end if;

    insert into public.audit_logs (actor_id, action, entity_type, entity_id, after, meta)
    values (
        v_actor,
        'evidence.anchor_failed',
        'blockchain_anchor',
        v_anchor.id,
        to_jsonb(v_anchor),
        jsonb_build_object(
            'evidence_id', v_anchor.evidence_id,
            'document_version_id', v_anchor.document_version_id,
            'network', v_anchor.network,
            'chain_id', v_anchor.chain_id,
            'contract_address', v_anchor.contract_address,
            'error_message', v_clean
        )
    );

    return jsonb_build_object('anchor', to_jsonb(v_anchor), 'transitioned', true);
end;
$function$;

alter function public.mark_anchor_failed(uuid, text) owner to postgres;
revoke execute on function public.mark_anchor_failed(uuid, text) from public, anon;
grant execute on function public.mark_anchor_failed(uuid, text) to authenticated;
