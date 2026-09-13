-- =============================================================================
-- SIH26190 Secure Evidence — anchor-state forgery regression tests
--
-- Verifies the audit C1 fix landed by
-- 20260919000000_block_anchor_state_forgery.sql. The fix:
--
--   (A) mark_anchor_anchored / mark_anchor_failed / reconcile_anchor_anchored
--       are REVOKED from `authenticated` — the browser/PostgREST write surface
--       for anchor state no longer exists. At most postgres (the owner) can
--       still execute them.
--   (C) public.anchor_state_apply is the single gateway; it is granted to
--       `authenticated` (the ONLY role a PostgREST session ever runs as) but
--       requires a server confirmation digest the raw secret never produces:
--       the gateway compares the supplied digest against the SHA-256 of
--       ANCHOR_CONFIRMATION_SECRET. The raw secret is never stored in the DB.
--       The inner RPCs STILL enforce auth.uid()-based lead/investigator
--       authorization, so capability is necessary but never sufficient.
--   (E) update_evidence_status('verified') now requires a PERSISTED, non-NULL
--       tx_hash: a fabricated 'anchored' row without a real broadcast (and
--       every reconciled row, which carries tx_hash = NULL by design) can no
--       longer produce a verified evidence row.
--
-- Independent ship: the read/on-chain verification surface is untouched (the
-- verification endpoint still reads the EvidenceAnchor contract directly, and
-- RLS reads of blockchain_anchors are unchanged).
--
-- Test inventory (target letter -> test):
--   T1 (A) lead + investigator cannot directly execute mark_anchor_anchored
--   T2 (B) mark_anchor_failed is revoked and unexecutable
--   T3 (C) reconcile_anchor_anchored is revoked and unexecutable
--   T4 (D) anon cannot execute the gateway either
--   T5 (E) verified gate: pending row and NULL-tx_hash (reconciled) row both
--          rejected; only a persisted-tx_hash anchored row verifies
--   T6 (F) gateway anchored path works for the server (correct token, lead)
--          and writes the evidence.anchored audit row
--   T7 (G) reconciliation still works through the gateway (tx_hash stays NULL)
--   T8 (G) the failed path still works through the gateway
--   T9 (G) gateway token/vocabulary gates: wrong token, viewer role, non-case
--          member (even with the CORRECT token), invalid action all rejected
--   T11(F) the raw secret is never stored in the DB — only its digest is
--   T12(A) RLS reads of blockchain_anchors are NOT weakened by the revocations
--
-- HOW TO RUN (single transaction required — the script relies on `set local`):
--   supabase start          # needs Docker
--   supabase db reset       # apply all migrations on a fresh DB
--   psql "$SUPABASE_DB_URL" -1 -v ON_ERROR_STOP=1 \
--       -f supabase/tests/anchor_state_forgery.sql
-- (or paste the whole file into the Supabase SQL editor, which runs in one
--  transaction, replacing $SUPABASE_DB_URL at the top.)
--
-- Every test either passes silently or aborts with a `FAIL T<n>` exception.
-- The script mutates only rows it creates itself; run against a throwaway DB.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Server confirmation DIGEST (SHA-256 of the server-only
-- ANCHOR_CONFIRMATION_SECRET). The gateway only stores/compares this 64-hex
-- digest; the RAW secret (32 random bytes) appears nowhere in this repo — it
-- lives only in the git-ignored server environment (.env.local). The secret
-- value used during development was shown in audit output, so it MUST be
-- rotated before staging/production use (see the ROTATION note in the migration).
--   digest : f74f6dcf7db30762071cd334efb9e92859c4d1b88ba81114765a386136418a23
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- Test users / fixture ids (deterministic, never collide with real data)
-- ---------------------------------------------------------------------------
-- u20  71100000-0000-0000-0000-000000000020  org-alpha ADMIN, lead of C20
-- u21  71100000-0000-0000-0000-000000000021  org-alpha investigator, investigator of C20
-- u22  71100000-0000-0000-0000-000000000022  org-alpha member, NO case_members row
-- u23  71100000-0000-0000-0000-000000000023  org-alpha member, viewer of C20
-- org_alpha 72100000-0000-0000-0000-0000000000A0
-- C20       73100000-0000-0000-0000-0000000000A0  (org-alpha, active)
-- EV20/A0   74100000-...A0  V20 sha repeat('d')  BA20 pending
-- EV21/A1   74100000-...A1  V21 sha repeat('a')  BA21 anchored, tx_hash NULL (reconciled-style)
-- EV22/A2   74100000-...A2  V22 sha repeat('b')  BA22 pending
-- EV23/A3   74100000-...A3  V23 sha repeat('c')  BA23 pending

-- ---------------------------------------------------------------------------
-- Fixtures (run as postgres / owner; RLS is bypassed for the fixture writer)
-- ---------------------------------------------------------------------------

insert into auth.users (id, email, encrypted_password, email_confirmed_at, raw_app_meta_data, created_at, updated_at)
values
  ('71100000-0000-0000-0000-000000000020', 'an.u20@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('71100000-0000-0000-0000-000000000021', 'an.u21@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('71100000-0000-0000-0000-000000000022', 'an.u22@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('71100000-0000-0000-0000-000000000023', 'an.u23@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now());

insert into public.profiles (id, full_name, role)
values
  ('71100000-0000-0000-0000-000000000020', 'Anchor Forgery Lead Alpha',      'officer'),
  ('71100000-0000-0000-0000-000000000021', 'Anchor Forgery Investigator',    'officer'),
  ('71100000-0000-0000-0000-000000000022', 'Anchor Forgery Org Member',      'officer'),
  ('71100000-0000-0000-0000-000000000023', 'Anchor Forgery Viewer Alpha',    'officer')
on conflict (id) do nothing;

insert into public.organizations (id, name, slug, created_by)
values ('72100000-0000-0000-0000-0000000000A0', 'Anchor Forgery Org', 'anchor-forgery-org', '71100000-0000-0000-0000-000000000020');

insert into public.organization_members (org_id, profile_id, role_in_org, added_by)
values
  ('72100000-0000-0000-0000-0000000000A0', '71100000-0000-0000-0000-000000000020', 'admin',        '71100000-0000-0000-0000-000000000020'),
  ('72100000-0000-0000-0000-0000000000A0', '71100000-0000-0000-0000-000000000021', 'investigator', '71100000-0000-0000-0000-000000000020'),
  ('72100000-0000-0000-0000-0000000000A0', '71100000-0000-0000-0000-000000000022', 'member',       '71100000-0000-0000-0000-000000000020'),
  ('72100000-0000-0000-0000-0000000000A0', '71100000-0000-0000-0000-000000000023', 'member',       '71100000-0000-0000-0000-000000000020');

insert into public.cases (id, org_id, case_number, title, description, status, created_by)
values ('73100000-0000-0000-0000-0000000000A0', '72100000-0000-0000-0000-0000000000A0', 'FORGERY-CASE', 'Anchor forgery case', null, 'active', '71100000-0000-0000-0000-000000000020');

insert into public.case_members (case_id, profile_id, role_in_case, added_by)
values
  ('73100000-0000-0000-0000-0000000000A0', '71100000-0000-0000-0000-000000000020', 'lead',         '71100000-0000-0000-0000-000000000020'),
  ('73100000-0000-0000-0000-0000000000A0', '71100000-0000-0000-0000-000000000021', 'investigator', '71100000-0000-0000-0000-000000000020'),
  ('73100000-0000-0000-0000-0000000000A0', '71100000-0000-0000-0000-000000000023', 'viewer',       '71100000-0000-0000-0000-000000000020');

-- Evidence + document versions
insert into public.evidence (id, case_id, evidence_number, title, description, type, status, created_by)
values
  ('74100000-0000-0000-0000-0000000000A0', '73100000-0000-0000-0000-0000000000A0', 'FORG-EV-0', 'Pending anchor evidence', null, 'document', 'received', '71100000-0000-0000-0000-000000000020'),
  ('74100000-0000-0000-0000-0000000000A1', '73100000-0000-0000-0000-0000000000A0', 'FORG-EV-1', 'Reconciled-only evidence', null, 'document', 'received', '71100000-0000-0000-0000-000000000020'),
  ('74100000-0000-0000-0000-0000000000A2', '73100000-0000-0000-0000-0000000000A0', 'FORG-EV-2', 'Reconcile-path evidence',  null, 'document', 'received', '71100000-0000-0000-0000-000000000020'),
  ('74100000-0000-0000-0000-0000000000A3', '73100000-0000-0000-0000-0000000000A0', 'FORG-EV-3', 'Failed-path evidence',     null, 'document', 'received', '71100000-0000-0000-0000-000000000020');

insert into public.document_versions (id, evidence_id, version, prev_version_id, file_name, mime_type, file_size_bytes, sha256, storage_key, uploaded_by, notes)
values
  ('75100000-0000-0000-0000-0000000000A0', '74100000-0000-0000-0000-0000000000A0', 1, null, 'forg-0.pdf', 'application/pdf', 1, repeat('d', 64), '73100000-0000-0000-0000-0000000000A0/74100000-0000-0000-0000-0000000000A0/75100000-0000-0000-0000-0000000000A0', '71100000-0000-0000-0000-000000000020', null),
  ('75100000-0000-0000-0000-0000000000A1', '74100000-0000-0000-0000-0000000000A1', 1, null, 'forg-1.pdf', 'application/pdf', 2, repeat('a', 64), '73100000-0000-0000-0000-0000000000A0/74100000-0000-0000-0000-0000000000A1/75100000-0000-0000-0000-0000000000A1', '71100000-0000-0000-0000-000000000020', null),
  ('75100000-0000-0000-0000-0000000000A2', '74100000-0000-0000-0000-0000000000A2', 1, null, 'forg-2.pdf', 'application/pdf', 3, repeat('b', 64), '73100000-0000-0000-0000-0000000000A0/74100000-0000-0000-0000-0000000000A2/75100000-0000-0000-0000-0000000000A2', '71100000-0000-0000-0000-000000000020', null),
  ('75100000-0000-0000-0000-0000000000A3', '74100000-0000-0000-0000-0000000000A3', 1, null, 'forg-3.pdf', 'application/pdf', 4, repeat('c', 64), '73100000-0000-0000-0000-0000000000A0/74100000-0000-0000-0000-0000000000A3/75100000-0000-0000-0000-0000000000A3', '71100000-0000-0000-0000-000000000020', null);

-- Blockchain anchors.
-- BA20: pending (must NOT verify until a persisted tx_hash exists).
-- BA21: 'anchored' with tx_hash = NULL — a reconciled-style row; the forged
--       state the fix hardens against.
-- BA22/BA23: pending slots used to prove the gateway paths (reconcile/failed).
insert into public.blockchain_anchors (id, evidence_id, document_version_id, network, chain_id, contract_address, evidence_id_hash, version_id_hash, evidence_sha256, status, tx_hash, block_number, anchored_at)
values
  ('77100000-0000-0000-0000-0000000000A0', '74100000-0000-0000-0000-0000000000A0', '75100000-0000-0000-0000-0000000000A0', 'sepolia', 11155111, '0x' || repeat('0', 40), '0x' || repeat('d', 64), '0x' || repeat('d', 64), repeat('d', 64), 'pending',  null, null, null),
  ('77100000-0000-0000-0000-0000000000A1', '74100000-0000-0000-0000-0000000000A1', '75100000-0000-0000-0000-0000000000A1', 'sepolia', 11155111, '0x' || repeat('0', 40), '0x' || repeat('a', 64), '0x' || repeat('a', 64), repeat('a', 64), 'anchored', null, 5, now()),
  ('77100000-0000-0000-0000-0000000000A2', '74100000-0000-0000-0000-0000000000A2', '75100000-0000-0000-0000-0000000000A2', 'sepolia', 11155111, '0x' || repeat('0', 40), '0x' || repeat('b', 64), '0x' || repeat('b', 64), repeat('b', 64), 'pending',  null, null, null),
  ('77100000-0000-0000-0000-0000000000A3', '74100000-0000-0000-0000-0000000000A3', '75100000-0000-0000-0000-0000000000A3', 'sepolia', 11155111, '0x' || repeat('0', 40), '0x' || repeat('c', 64), '0x' || repeat('c', 64), repeat('c', 64), 'pending',  null, null, null);

-- =============================================================================
-- T1 (A) — revoked: neither the lead nor the investigator can directly execute
-- mark_anchor_anchored.
-- =============================================================================
set local role authenticated;
set local request.jwt.claims = '{"sub":"71100000-0000-0000-0000-000000000020"}';

do $$
begin
    if has_function_privilege('authenticated', 'public.mark_anchor_anchored(uuid, text, bigint, timestamptz)', 'EXECUTE') then
        raise exception 'FAIL T1: authenticated still holds EXECUTE on mark_anchor_anchored';
    end if;
end $$;

do $$
declare
    v_executed   boolean := false;
    v_unexpected text    := null;
begin
    begin
        perform public.mark_anchor_anchored('77100000-0000-0000-0000-0000000000A0', '0x' || repeat('e', 64), 10, now());
        v_executed := true;
    exception
        when insufficient_privilege or undefined_function then
            null; -- expected: EXECUTE was revoked, the call must never run
        when others then
            v_unexpected := sqlerrm;
    end;

    -- assertions live OUTSIDE the catching block, so a FAIL can never be
    -- swallowed by it. Three outcomes remain distinguishable:
    --   v_executed=true           the forbidden call RAN -> FAIL
    --   v_unexpected <> null      it raised the wrong error     -> FAIL
    --   both false                it was blocked as expected    -> pass
    if v_executed then
        raise exception 'FAIL T1: lead directly transitioned an anchor to anchored';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL T1: unexpected error instead of the expected revocation: %', v_unexpected;
    end if;
end $$;

-- investigator attempt must fail identically.
set local request.jwt.claims = '{"sub":"71100000-0000-0000-0000-000000000021"}';

do $$
declare
    v_executed   boolean := false;
    v_unexpected text    := null;
begin
    begin
        perform public.mark_anchor_anchored('77100000-0000-0000-0000-0000000000A0', '0x' || repeat('e', 64), 10, now());
        v_executed := true;
    exception
        when insufficient_privilege or undefined_function then
            null; -- expected: EXECUTE was revoked
        when others then
            v_unexpected := sqlerrm;
    end;

    if v_executed then
        raise exception 'FAIL T1: investigator directly transitioned an anchor to anchored';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL T1: unexpected error instead of the expected revocation: %', v_unexpected;
    end if;
end $$;

-- =============================================================================
-- T2 (B) — revoked: mark_anchor_failed is unexecutable.
-- =============================================================================
do $$
begin
    if has_function_privilege('authenticated', 'public.mark_anchor_failed(uuid, text)', 'EXECUTE') then
        raise exception 'FAIL T2: authenticated still holds EXECUTE on mark_anchor_failed';
    end if;
end $$;

do $$
declare
    v_executed   boolean := false;
    v_unexpected text    := null;
begin
    begin
        perform public.mark_anchor_failed('77100000-0000-0000-0000-0000000000A3', 'simulated revert');
        v_executed := true;
    exception
        when insufficient_privilege or undefined_function then
            null; -- expected: EXECUTE was revoked
        when others then
            v_unexpected := sqlerrm;
    end;

    if v_executed then
        raise exception 'FAIL T2: investigator directly marked an anchor failed';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL T2: unexpected error instead of the expected revocation: %', v_unexpected;
    end if;
end $$;

-- =============================================================================
-- T3 (C) — revoked: reconcile_anchor_anchored is unexecutable.
-- =============================================================================
do $$
begin
    if has_function_privilege('authenticated', 'public.reconcile_anchor_anchored(uuid, bigint, timestamptz)', 'EXECUTE') then
        raise exception 'FAIL T3: authenticated still holds EXECUTE on reconcile_anchor_anchored';
    end if;
end $$;

do $$
declare
    v_executed   boolean := false;
    v_unexpected text    := null;
begin
    begin
        perform public.reconcile_anchor_anchored('77100000-0000-0000-0000-0000000000A2', 11, now());
        v_executed := true;
    exception
        when insufficient_privilege or undefined_function then
            null; -- expected: EXECUTE was revoked
        when others then
            v_unexpected := sqlerrm;
    end;

    if v_executed then
        raise exception 'FAIL T3: investigator directly reconciled an anchor';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL T3: unexpected error instead of the expected revocation: %', v_unexpected;
    end if;
end $$;

-- =============================================================================
-- T4 (D) — the gateway is authenticated-only: `anon` has no EXECUTE either.
-- =============================================================================
do $$
begin
    if has_function_privilege('anon', 'public.anchor_state_apply(text, uuid, text, bigint, timestamptz, text, text)', 'EXECUTE') then
        raise exception 'FAIL T4: anon holds EXECUTE on anchor_state_apply';
    end if;
    if not has_function_privilege('authenticated', 'public.anchor_state_apply(text, uuid, text, bigint, timestamptz, text, text)', 'EXECUTE') then
        raise exception 'FAIL T4: anchor_state_apply must stay executable by authenticated';
    end if;
end $$;

set local role anon;
set local request.jwt.claims = '{"sub":null}';

do $$
declare
    v_executed   boolean := false;
    v_unexpected text    := null;
begin
    begin
        perform public.anchor_state_apply('anchored', '77100000-0000-0000-0000-0000000000A0', '0x' || repeat('e', 64), 10, now(), null, 'f74f6dcf7db30762071cd334efb9e92859c4d1b88ba81114765a386136418a23');
        v_executed := true;
    exception
        when insufficient_privilege or undefined_function then
            null; -- expected: anon holds no EXECUTE on the gateway
        when others then
            v_unexpected := sqlerrm;
    end;

    if v_executed then
        raise exception 'FAIL T4: anon executed the anchor gateway';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL T4: unexpected error instead of the expected permission denial: %', v_unexpected;
    end if;
end $$;

set local role authenticated;

-- =============================================================================
-- T5 (E) — the verified gate needs a PERSISTED tx_hash, so a pending row and a
-- reconciled-only ('anchored', tx_hash NULL) row BOTH fail to verify.
-- =============================================================================
set local request.jwt.claims = '{"sub":"71100000-0000-0000-0000-000000000020"}';

do $$
declare
    v_executed   boolean := false;
    v_unexpected text    := null;
begin
    begin
        perform public.update_evidence_status('74100000-0000-0000-0000-0000000000A0', 'verified');
        v_executed := true;
    exception
        when others then
            v_unexpected := sqlerrm;
    end;

    if v_executed then
        raise exception 'FAIL T5: verified succeeded while the only anchor is pending';
    end if;
    if v_unexpected is null or position('verification_required' in v_unexpected) = 0 then
        raise exception 'FAIL T5: unexpected error instead of verification_required: %', v_unexpected;
    end if;
end $$;

do $$
declare
    v_executed   boolean := false;
    v_unexpected text    := null;
begin
    begin
        perform public.update_evidence_status('74100000-0000-0000-0000-0000000000A1', 'verified');
        v_executed := true;
    exception
        when others then
            v_unexpected := sqlerrm;
    end;

    if v_executed then
        raise exception 'FAIL T5: verified succeeded with only a NULL-tx_hash (reconciled-style) anchored row';
    end if;
    if v_unexpected is null or position('verification_required' in v_unexpected) = 0 then
        raise exception 'FAIL T5: unexpected error instead of verification_required: %', v_unexpected;
    end if;
end $$;

-- =============================================================================
-- T6 (F) — the server gateway path: correct confirmation digest + lead role
-- transitions a pending row to anchored and writes the evidence.anchored audit.
-- =============================================================================
do $$
declare
    v_res    jsonb;
    v_status text;
    v_tx     text;
    v_audit  bigint;
begin
    v_res := public.anchor_state_apply(
        'anchored',
        '77100000-0000-0000-0000-0000000000A0',
        '0x' || repeat('e', 64),
        10,
        now(),
        null,
        'f74f6dcf7db30762071cd334efb9e92859c4d1b88ba81114765a386136418a23'
    );
    if not coalesce((v_res->>'transitioned')::boolean, false) then
        raise exception 'FAIL T6: gateway anchored did not report transitioned';
    end if;

    select a.status, a.tx_hash into v_status, v_tx
    from public.blockchain_anchors a
    where a.id = '77100000-0000-0000-0000-0000000000A0';
    if v_status <> 'anchored' then
        raise exception 'FAIL T6: row did not land in anchored state';
    end if;
    if v_tx <> '0x' || repeat('e', 64) then
        raise exception 'FAIL T6: persisted tx_hash does not match the confirmed receipt';
    end if;

    select count(*) into v_audit
    from public.list_case_audit_events('73100000-0000-0000-0000-0000000000A0')
    where action = 'evidence.anchored'
      and entity_id = '77100000-0000-0000-0000-0000000000A0';
    if v_audit < 1 then
        raise exception 'FAIL T6: evidence.anchored audit row missing';
    end if;
end $$;

-- =============================================================================
-- T7 (E) — with a REAL persisted-tx_hash anchored row the same transition now
-- succeeds, writes its audit event, and creates the verified custody entry.
-- =============================================================================
do $$
declare
    v_status text;
    v_coc    bigint;
    v_audit  bigint;
begin
    perform public.update_evidence_status('74100000-0000-0000-0000-0000000000A0', 'verified');

    select e.status into v_status from public.evidence e where e.id = '74100000-0000-0000-0000-0000000000A0';
    if v_status <> 'verified' then
        raise exception 'FAIL T7: verified transition did not persist';
    end if;

    select count(*) into v_coc
    from public.chain_of_custody
    where evidence_id = '74100000-0000-0000-0000-0000000000A0'
      and action = 'verified';
    if v_coc <> 1 then
        raise exception 'FAIL T7: verified custody entry missing';
    end if;

    select count(*) into v_audit
    from public.list_case_audit_events('73100000-0000-0000-0000-0000000000A0')
    where action = 'evidence.status_changed'
      and entity_id = '74100000-0000-0000-0000-0000000000A0'
      and meta->>'new_status' = 'verified';
    if v_audit < 1 then
        raise exception 'FAIL T7: evidence.status_changed audit row missing';
    end if;
end $$;

-- =============================================================================
-- T8 (G) — reconciliation (pending -> anchored WITHOUT a broadcast) still works
-- through the gateway and still writes NO tx_hash — it can never forge one.
-- =============================================================================
do $$
declare
    v_res    jsonb;
    v_status text;
    v_tx     text;
begin
    v_res := public.anchor_state_apply(
        'reconcile',
        '77100000-0000-0000-0000-0000000000A2',
        null,
        11,
        now(),
        null,
        'f74f6dcf7db30762071cd334efb9e92859c4d1b88ba81114765a386136418a23'
    );
    if not coalesce((v_res->>'transitioned')::boolean, false) then
        raise exception 'FAIL T8: gateway reconcile did not report transitioned';
    end if;

    select a.status, a.tx_hash into v_status, v_tx
    from public.blockchain_anchors a
    where a.id = '77100000-0000-0000-0000-0000000000A2';
    if v_status <> 'anchored' then
        raise exception 'FAIL T8: reconciled row did not land in anchored state';
    end if;
    if v_tx is not null then
        raise exception 'FAIL T8: reconciliation fabricated a transaction hash';
    end if;
end $$;

-- =============================================================================
-- T9 (G) — the failed path still works through the gateway; the failed row is
-- then terminal even for a lead with the correct token.
-- =============================================================================
do $$
declare
    v_res    jsonb;
    v_status text;
    v_audit  bigint;
begin
    v_res := public.anchor_state_apply(
        'failed',
        '77100000-0000-0000-0000-0000000000A3',
        null,
        null,
        null,
        'simulated provider revert',
        'f74f6dcf7db30762071cd334efb9e92859c4d1b88ba81114765a386136418a23'
    );
    if not coalesce((v_res->>'transitioned')::boolean, false) then
        raise exception 'FAIL T9: gateway failed did not report transitioned';
    end if;

    select a.status into v_status
    from public.blockchain_anchors a
    where a.id = '77100000-0000-0000-0000-0000000000A3';
    if v_status <> 'failed' then
        raise exception 'FAIL T9: failed row did not land in failed state';
    end if;

    -- terminal: a correct-token retry cannot flip a failed row to anchored.
    v_res := public.anchor_state_apply(
        'anchored',
        '77100000-0000-0000-0000-0000000000A3',
        '0x' || repeat('f', 64),
        12,
        now(),
        null,
        'f74f6dcf7db30762071cd334efb9e92859c4d1b88ba81114765a386136418a23'
    );
    if (v_res->>'transitioned')::boolean then
        raise exception 'FAIL T9: a failed row was transitioned by a retry';
    end if;

    select count(*) into v_audit
    from public.list_case_audit_events('73100000-0000-0000-0000-0000000000A0')
    where action = 'evidence.anchor_failed'
      and entity_id = '77100000-0000-0000-0000-0000000000A3';
    if v_audit < 1 then
        raise exception 'FAIL T9: evidence.anchor_failed audit row missing';
    end if;
end $$;

-- =============================================================================
-- T10 (G) — token + vocabulary gates on the gateway.
--  * wrong confirmation digest -> invalid_confirmation (even for the lead)
--  * viewer with the CORRECT digest -> not_authorized_to_anchor (inner RPC)
--  * org member with NO case membership + CORRECT digest -> not_authorized
--  * unknown action with the correct digest -> invalid_action
-- =============================================================================
do $$
declare
    v_executed   boolean := false;
    v_unexpected text    := null;
begin
    begin
        perform public.anchor_state_apply(
            'anchored',
            '77100000-0000-0000-0000-0000000000A2',
            '0x' || repeat('e', 64),
            10,
            now(),
            null,
            repeat('0', 64)
        );
        v_executed := true;
    exception
        when others then
            v_unexpected := sqlerrm;
    end;

    if v_executed then
        raise exception 'FAIL T10: wrong confirmation digest was accepted';
    end if;
    if v_unexpected is null or position('invalid_confirmation' in v_unexpected) = 0 then
        raise exception 'FAIL T10: unexpected error (expected invalid_confirmation): %', v_unexpected;
    end if;
end $$;

-- viewer (case member, not lead/investigator) with the CORRECT digest.
set local request.jwt.claims = '{"sub":"71100000-0000-0000-0000-000000000023"}';

do $$
declare
    v_executed   boolean := false;
    v_unexpected text    := null;
begin
    begin
        perform public.anchor_state_apply(
            'anchored',
            '77100000-0000-0000-0000-0000000000A2',
            '0x' || repeat('e', 64),
            10,
            now(),
            null,
            'f74f6dcf7db30762071cd334efb9e92859c4d1b88ba81114765a386136418a23'
        );
        v_executed := true;
    exception
        when others then
            v_unexpected := sqlerrm;
    end;

    if v_executed then
        raise exception 'FAIL T10: viewer with the server digest anchored a row';
    end if;
    if v_unexpected is null or position('not_authorized_to_anchor' in v_unexpected) = 0 then
        raise exception 'FAIL T10: unexpected error (expected not_authorized_to_anchor): %', v_unexpected;
    end if;
end $$;

-- org member WITHOUT an explicit case role, with the CORRECT digest.
set local request.jwt.claims = '{"sub":"71100000-0000-0000-0000-000000000022"}';

do $$
declare
    v_executed   boolean := false;
    v_unexpected text    := null;
begin
    begin
        perform public.anchor_state_apply(
            'anchored',
            '77100000-0000-0000-0000-0000000000A2',
            '0x' || repeat('e', 64),
            10,
            now(),
            null,
            'f74f6dcf7db30762071cd334efb9e92859c4d1b88ba81114765a386136418a23'
        );
        v_executed := true;
    exception
        when others then
            v_unexpected := sqlerrm;
    end;

    if v_executed then
        raise exception 'FAIL T10: org member without case role anchored a row';
    end if;
    if v_unexpected is null or position('not_authorized_to_anchor' in v_unexpected) = 0 then
        raise exception 'FAIL T10: unexpected error (expected not_authorized_to_anchor): %', v_unexpected;
    end if;
end $$;

set local request.jwt.claims = '{"sub":"71100000-0000-0000-0000-000000000020"}';

do $$
declare
    v_executed   boolean := false;
    v_unexpected text    := null;
begin
    begin
        perform public.anchor_state_apply(
            'mark_failed_verification',
            '77100000-0000-0000-0000-0000000000A2',
            null,
            null,
            null,
            null,
            'f74f6dcf7db30762071cd334efb9e92859c4d1b88ba81114765a386136418a23'
        );
        v_executed := true;
    exception
        when others then
            v_unexpected := sqlerrm;
    end;

    if v_executed then
        raise exception 'FAIL T10: unknown action was executed';
    end if;
    if v_unexpected is null or position('invalid_action' in v_unexpected) = 0 then
        raise exception 'FAIL T10: unexpected error (expected invalid_action): %', v_unexpected;
    end if;
end $$;

-- =============================================================================
-- T11 (F) — the raw secret is NEVER stored in the database; only its SHA-256
-- digest is wired into the gateway source.
-- =============================================================================
do $$
declare
    v_src text;
    v_bad bigint;
begin
    select prosrc into v_src
    from pg_proc
    where oid = 'public.anchor_state_apply(text, uuid, text, bigint, timestamptz, text, text)'::regprocedure;

    -- Every 64-hex token in the gateway source must be exactly the confirmation
    -- DIGEST. If the RAW secret (a different 256-bit value) were ever wired into
    -- the gateway it would surface as a divergent 64-hex token and trip this
    -- check — so the test file never needs to contain the secret itself.
    select count(*) into v_bad
    from (
        select t[1] as token
        from regexp_matches(v_src, '[0-9a-f]{64}', 'g') as t
    ) m
    where m.token <> 'f74f6dcf7db30762071cd334efb9e92859c4d1b88ba81114765a386136418a23';

    if v_bad > 0 then
        raise exception 'FAIL T11: the gateway source contains a 64-hex token that is not the confirmation digest';
    end if;
    if position('f74f6dcf7db30762071cd334efb9e92859c4d1b88ba81114765a386136418a23' in v_src) = 0 then
        raise exception 'FAIL T11: the confirmation digest is not wired into the gateway';
    end if;
end $$;

-- =============================================================================
-- T12 (A/H) — the revocations do NOT weaken RLS reads: a case lead still reads
-- anchored rows through the policy, and an unrelated org member still cannot.
-- =============================================================================
do $$
declare
    v_count bigint;
begin
    if not exists (
        select 1 from public.blockchain_anchors
        where id = '77100000-0000-0000-0000-0000000000A0'
    ) then
        raise exception 'FAIL T12: lead cannot read the anchored row';
    end if;
end $$;

set local request.jwt.claims = '{"sub":"71100000-0000-0000-0000-000000000022"}';

do $$
begin
    if exists (
        select 1 from public.blockchain_anchors
        where id = '77100000-0000-0000-0000-0000000000A0'
    ) then
        raise exception 'FAIL T12: org member without case role read an anchor row';
    end if;
end $$;

-- =============================================================================
-- Final: reset the session role so the transaction stays owner-owned.
-- =============================================================================
reset role;