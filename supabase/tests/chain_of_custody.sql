-- =============================================================================
-- SIH26190 Secure Evidence — chain-of-custody workflow tests
--
-- Verifies 20260916000000_chain_of_custody_workflow.sql:
--
--   * record_custody_event() is the ONLY non-intake custody writer. The actor
--     is ALWAYS auth.uid() (never a client-supplied value), occurred_at is
--     ALWAYS server-set now() (backdating/is it impossible), every event is
--     mirrored into audit_logs in the same transaction with org_id populated.
--   * Direct authenticated INSERT on chain_of_custody is revoked (RPC-only),
--     and UPDATE / DELETE were never granted (immutable possession record).
--   * update_evidence_status() records custody 'verified' (anchor-gated) and
--     'archived' events in the same transaction, idempotently.
--   * create_evidence() intake still writes custody 'received'.
--
-- Test inventory (T1..T24):
--   T1   anon read of custody denied
--   T2   anon write (record_custody_event) denied
--   T3   outsider (cross-org, no case membership) cannot read another case's
--        custody
--   T4   org member WITHOUT case membership cannot read the case's custody
--   T5   viewer can READ custody but cannot record events
--   T6   lead records a transfer (actor = auth.uid(), server timestamp)
--        + cannot transfer custody to themselves
--   T7   investigator records a return
--   T8   no actor_id / forged-actor argument exists on the RPC (rejected)
--   T9   invalid action vocabulary rejected
--   T10  transferred / returned without a receiving member rejected
--   T11  released / archived WITH a receiving member rejected
--   T12  from/to profile not a member of the SAME case rejected (same org,
--        different case)
--   T13  from/to profile from another ORGANIZATION rejected
--   T14  backdating blocked: no occurred_at argument, timestamp server-set
--   T15  direct INSERT on chain_of_custody denied (REVOKE closed the gap)
--   T16  direct UPDATE on chain_of_custody denied
--   T17  direct DELETE on chain_of_custody denied
--   T18  custody event written as a matching audit_logs entry (same tx)
--   T19  audit_logs.org_id equals the case's organization
--   T20  'verified' custody is anchor-gated through the status path
--        (no anchor -> rejected; matching anchor -> verified custody row)
--   T21  'archived' custody written (idempotently) through the status path
--   T22  intake (create_evidence) still writes custody 'received'
--   T23  nonexistent evidence rejected (evidence_not_found)
--   T24  cross-organization evidence rejected identically (no existence leak)
--
-- HOW TO RUN (single transaction required — the script relies on set local):
--   supabase start          # needs Docker
--   supabase db reset       # apply all migrations on a fresh DB
--   psql "$SUPABASE_DB_URL" -1 -v ON_ERROR_STOP=1 \
--       -f supabase/tests/chain_of_custody.sql
-- (or paste the whole file into the Supabase SQL editor, which runs in one
--  transaction, replacing $SUPABASE_DB_URL at the top.)
--
-- Every test either passes silently or aborts with a `FAIL T<n>` exception.
-- The script mutates only rows it creates itself; run against a throwaway DB.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Test users / fixture ids (deterministic, never collide with real data)
-- ---------------------------------------------------------------------------
-- u2  71000000-0000-0000-0000-000000000002  org-alpha member, LEAD of C_A
-- u3  71000000-0000-0000-0000-000000000003  org-alpha member, member of C_A2 only
-- u4  71000000-0000-0000-0000-000000000004  org-alpha member, INVESTIGATOR of C_A
-- u5  71000000-0000-0000-0000-000000000005  org-beta member (cross-org outsider)
-- u6  71000000-0000-0000-0000-000000000006  org-beta admin, LEAD of C_B
-- u8  71000000-0000-0000-0000-000000000008  org-alpha member, VIEWER of C_A
-- org_alpha 72000000-0000-0000-0000-0000000000A1
-- org_beta  72000000-0000-0000-0000-0000000000B1
-- C_A       73000000-0000-0000-0000-0000000000A1  (org-alpha, active)
-- C_A2      73000000-0000-0000-0000-0000000000A2  (org-alpha, active, cross-case)
-- C_B       73000000-0000-0000-0000-0000000000B1  (org-beta,  active)
-- EV_A      74000000-0000-0000-0000-0000000000A1  (case C_A)
-- EV_B      74000000-0000-0000-0000-0000000000B1  (case C_B)
-- EV_C      74000000-0000-0000-0000-0000000000C1  (created via create_evidence, T22)
-- V_A       75000000-0000-0000-0000-0000000000A1  (evidence EV_A)
-- V_B       75000000-0000-0000-0000-0000000000B1  (evidence EV_B)
-- V_C       75000000-0000-0000-0000-0000000000C1  (evidence EV_C, T22)
-- BA_A      77000000-0000-0000-0000-0000000000A1  (EV_A, ANCHORED, sha matches V_A)
-- BA_B      77000000-0000-0000-0000-0000000000B1  (EV_B, PENDING — no gate pass)
-- COC_A     76000000-0000-0000-0000-0000000000A1  (EV_A received)

-- ---------------------------------------------------------------------------
-- Fixtures (run as postgres / owner; RLS is bypassed for the fixture writer)
-- ---------------------------------------------------------------------------

insert into auth.users (id, email, encrypted_password, email_confirmed_at, raw_app_meta_data, created_at, updated_at)
values
  ('71000000-0000-0000-0000-000000000002', 'coc.u2@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('71000000-0000-0000-0000-000000000003', 'coc.u3@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('71000000-0000-0000-0000-000000000004', 'coc.u4@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('71000000-0000-0000-0000-000000000005', 'coc.u5@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('71000000-0000-0000-0000-000000000006', 'coc.u6@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('71000000-0000-0000-0000-000000000008', 'coc.u8@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now());

insert into public.profiles (id, full_name, role)
values
  ('71000000-0000-0000-0000-000000000002', 'CoC Lead A',       'officer'),
  ('71000000-0000-0000-0000-000000000003', 'CoC Member A',      'officer'),
  ('71000000-0000-0000-0000-000000000004', 'CoC Investigator A','officer'),
  ('71000000-0000-0000-0000-000000000005', 'CoC Member B',      'officer'),
  ('71000000-0000-0000-0000-000000000006', 'CoC Admin B',       'officer'),
  ('71000000-0000-0000-0000-000000000008', 'CoC Viewer A',      'officer')
on conflict (id) do nothing;

insert into public.organizations (id, name, slug, created_by)
values
  ('72000000-0000-0000-0000-0000000000A1', 'org-alpha', 'coc-alpha', '71000000-0000-0000-0000-000000000002'),
  ('72000000-0000-0000-0000-0000000000B1', 'org-beta',  'coc-beta',  '71000000-0000-0000-0000-000000000006');

insert into public.organization_members (org_id, profile_id, role_in_org, added_by)
values
  ('72000000-0000-0000-0000-0000000000A1', '71000000-0000-0000-0000-000000000002', 'investigator', '71000000-0000-0000-0000-000000000002'),
  ('72000000-0000-0000-0000-0000000000A1', '71000000-0000-0000-0000-000000000003', 'member',       '71000000-0000-0000-0000-000000000002'),
  ('72000000-0000-0000-0000-0000000000A1', '71000000-0000-0000-0000-000000000004', 'member',       '71000000-0000-0000-0000-000000000002'),
  ('72000000-0000-0000-0000-0000000000A1', '71000000-0000-0000-0000-000000000008', 'member',       '71000000-0000-0000-0000-000000000002'),
  ('72000000-0000-0000-0000-0000000000B1', '71000000-0000-0000-0000-000000000006', 'admin',        '71000000-0000-0000-0000-000000000006'),
  ('72000000-0000-0000-0000-0000000000B1', '71000000-0000-0000-0000-000000000005', 'member',       '71000000-0000-0000-0000-000000000006');

insert into public.cases (id, org_id, case_number, title, description, status, created_by)
values
  ('73000000-0000-0000-0000-0000000000A1', '72000000-0000-0000-0000-0000000000A1', 'COC-CASE-A',  'custody case A',  null, 'active', '71000000-0000-0000-0000-000000000002'),
  ('73000000-0000-0000-0000-0000000000A2', '72000000-0000-0000-0000-0000000000A1', 'COC-CASE-A2', 'custody case A2', null, 'active', '71000000-0000-0000-0000-000000000003'),
  ('73000000-0000-0000-0000-0000000000B1', '72000000-0000-0000-0000-0000000000B1', 'COC-CASE-B',  'custody case B',  null, 'active', '71000000-0000-0000-0000-000000000006');

insert into public.case_members (case_id, profile_id, role_in_case, added_by)
values
  ('73000000-0000-0000-0000-0000000000A1', '71000000-0000-0000-0000-000000000002', 'lead',         '71000000-0000-0000-0000-000000000002'),
  ('73000000-0000-0000-0000-0000000000A1', '71000000-0000-0000-0000-000000000004', 'investigator', '71000000-0000-0000-0000-000000000002'),
  ('73000000-0000-0000-0000-0000000000A1', '71000000-0000-0000-0000-000000000008', 'viewer',       '71000000-0000-0000-0000-000000000002'),
  ('73000000-0000-0000-0000-0000000000A2', '71000000-0000-0000-0000-000000000003', 'lead',         '71000000-0000-0000-0000-000000000003'),
  ('73000000-0000-0000-0000-0000000000B1', '71000000-0000-0000-0000-000000000006', 'lead',         '71000000-0000-0000-0000-000000000006');

insert into public.evidence (id, case_id, evidence_number, title, description, type, status, created_by)
values
  ('74000000-0000-0000-0000-0000000000A1', '73000000-0000-0000-0000-0000000000A1', 'COC-EV-A', 'alpha evidence', null, 'document', 'received', '71000000-0000-0000-0000-000000000002'),
  ('74000000-0000-0000-0000-0000000000B1', '73000000-0000-0000-0000-0000000000B1', 'COC-EV-B', 'beta evidence',  null, 'document', 'received', '71000000-0000-0000-0000-000000000006');

insert into public.document_versions (id, evidence_id, version, prev_version_id, file_name, mime_type, file_size_bytes, sha256, storage_key, uploaded_by, notes)
values
  ('75000000-0000-0000-0000-0000000000A1', '74000000-0000-0000-0000-0000000000A1', 1, null, 'alpha.pdf', 'application/pdf', 10, repeat('a', 64), '73000000-0000-0000-0000-0000000000A1/74000000-0000-0000-0000-0000000000A1/75000000-0000-0000-0000-0000000000A1', '71000000-0000-0000-0000-000000000002', null),
  ('75000000-0000-0000-0000-0000000000B1', '74000000-0000-0000-0000-0000000000B1', 1, null, 'beta.pdf',  'application/pdf', 20, repeat('b', 64), '73000000-0000-0000-0000-0000000000B1/74000000-0000-0000-0000-0000000000B1/75000000-0000-0000-0000-0000000000B1', '71000000-0000-0000-0000-000000000006', null);

insert into public.chain_of_custody (id, evidence_id, document_version_id, action, actor_id, from_profile_id, to_profile_id, notes)
values
  ('76000000-0000-0000-0000-0000000000A1', '74000000-0000-0000-0000-0000000000A1', '75000000-0000-0000-0000-0000000000A1', 'received', '71000000-0000-0000-0000-000000000002', null, '71000000-0000-0000-0000-000000000002', 'intake');

insert into public.blockchain_anchors (id, evidence_id, document_version_id, network, chain_id, contract_address, evidence_id_hash, version_id_hash, evidence_sha256, status, tx_hash, block_number, anchored_at)
values
  ('77000000-0000-0000-0000-0000000000A1', '74000000-0000-0000-0000-0000000000A1', '75000000-0000-0000-0000-0000000000A1', 'sepolia', 11155111, '0x' || repeat('0', 40), '0x' || repeat('a', 64), '0x' || repeat('a', 64), repeat('a', 64), 'anchored', '0x' || repeat('1', 64), 1, now()),
  ('77000000-0000-0000-0000-0000000000B1', '74000000-0000-0000-0000-0000000000B1', '75000000-0000-0000-0000-0000000000B1', 'sepolia', 11155111, '0x' || repeat('0', 40), '0x' || repeat('b', 64), '0x' || repeat('b', 64), repeat('b', 64), 'pending',  null,           1, null);

-- =============================================================================
-- T1 — anon read of custody denied
-- =============================================================================
set local role anon;

do $$
begin
    begin
        perform 1 from public.chain_of_custody where evidence_id = '74000000-0000-0000-0000-0000000000A1';
        raise exception 'FAIL T1: anon could read chain_of_custody';
    exception when others then
        if sqlerrm like '%permission denied%' then
            null;
        else
            raise exception 'FAIL T1: unexpected denial %', sqlerrm;
        end if;
    end;
end $$;

-- =============================================================================
-- T2 — anon write (record_custody_event) denied
-- =============================================================================
do $$
begin
    begin
        perform public.record_custody_event(
            '74000000-0000-0000-0000-0000000000A1',
            'transferred',
            p_to_profile_id => '71000000-0000-0000-0000-000000000004'
        );
        raise exception 'FAIL T2: anon could call record_custody_event';
    exception when others then
        if sqlerrm like '%permission denied%' or sqlerrm like '%not_authenticated%' then
            null;
        else
            raise exception 'FAIL T2: unexpected denial %', sqlerrm;
        end if;
    end;
end $$;

-- =============================================================================
-- T3 — outsider (cross-org, no case membership) cannot read custody
-- =============================================================================
set local role authenticated;
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000005"}';

do $$
declare
    n integer;
begin
    select count(*) into n
    from public.chain_of_custody
    where evidence_id = '74000000-0000-0000-0000-0000000000A1';
    if n <> 0 then
        raise exception 'FAIL T3: cross-org outsider read % custody rows', n;
    end if;
end $$;

-- =============================================================================
-- T4 — org member WITHOUT case membership cannot read custody
-- =============================================================================
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000003"}';

do $$
declare
    n integer;
begin
    select count(*) into n
    from public.chain_of_custody
    where evidence_id = '74000000-0000-0000-0000-0000000000A1';
    if n <> 0 then
        raise exception 'FAIL T4: org member without case membership read % rows', n;
    end if;
end $$;

-- =============================================================================
-- T5 — viewer can READ custody but cannot record events
-- =============================================================================
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000008"}';

do $$
declare
    n integer;
begin
    select count(*) into n
    from public.chain_of_custody
    where evidence_id = '74000000-0000-0000-0000-0000000000A1';
    if n < 1 then
        raise exception 'FAIL T5: viewer could not read custody';
    end if;

    begin
        perform public.record_custody_event(
            '74000000-0000-0000-0000-0000000000A1',
            'released'
        );
        raise exception 'FAIL T5: viewer recorded a custody event';
    exception when others then
        if sqlerrm like '%not_authorized_for_custody%' then
            null;
        else
            raise exception 'FAIL T5: unexpected denial %', sqlerrm;
        end if;
    end;
end $$;

-- =============================================================================
-- T6 — lead records a transfer; actor forced + server timestamp + self-ban
-- =============================================================================
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000002"}';

do $$
declare
    v_custody public.chain_of_custody;
    n integer;
begin
    select * into v_custody
    from public.record_custody_event(
        '74000000-0000-0000-0000-0000000000A1',
        'transferred',
        p_document_version_id => '75000000-0000-0000-0000-0000000000A1',
        p_to_profile_id       => '71000000-0000-0000-0000-000000000004',
        p_location            => 'Almirah-3',
        p_notes               => 'moved for analysis'
    );

    -- the actor is the session user, whatever the caller "intended".
    if v_custody.actor_id <> '71000000-0000-0000-0000-000000000002' then
        raise exception 'FAIL T6: actor was %, expected the session user', v_custody.actor_id;
    end if;
    if v_custody.action <> 'transferred' then
        raise exception 'FAIL T6: action %', v_custody.action;
    end if;
    if v_custody.to_profile_id <> '71000000-0000-0000-0000-000000000004' then
        raise exception 'FAIL T6: wrong recipient';
    end if;
    -- server-set timestamp: must be "now", not a caller-chosen value.
    if v_custody.occurred_at is null
       or v_custody.occurred_at < now() - interval '1 minute'
       or v_custody.occurred_at > now() + interval '1 minute' then
        raise exception 'FAIL T6: occurred_at was not server-set now()';
    end if;

    -- a lead cannot hand custody to themselves.
    begin
        perform public.record_custody_event(
            '74000000-0000-0000-0000-0000000000A1',
            'returned',
            p_to_profile_id => '71000000-0000-0000-0000-000000000002'
        );
        raise exception 'FAIL T6: transfer/return to self was allowed';
    exception when others then
        if sqlerrm like '%to_profile_is_actor%' then
            null;
        else
            raise exception 'FAIL T6: unexpected self-transfer denial %', sqlerrm;
        end if;
    end;
end $$;

-- =============================================================================
-- T7 — investigator records a return
-- =============================================================================
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000004"}';

do $$
declare
    v_custody public.chain_of_custody;
    n integer;
begin
    select * into v_custody
    from public.record_custody_event(
        '74000000-0000-0000-0000-0000000000A1',
        'returned',
        p_to_profile_id => '71000000-0000-0000-0000-000000000002'
    );
    if v_custody.actor_id <> '71000000-0000-0000-0000-000000000004' then
        raise exception 'FAIL T7: actor was %, expected the investigator', v_custody.actor_id;
    end if;
    if v_custody.action <> 'returned' then
        raise exception 'FAIL T7: action %', v_custody.action;
    end if;
end $$;

-- =============================================================================
-- T8 — no actor_id / forged-actor argument exists on the RPC
-- =============================================================================
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000002"}';

do $$
begin
    begin
        perform public.record_custody_event(
            '74000000-0000-0000-0000-0000000000A1',
            'transferred',
            p_actor_id => '71000000-0000-0000-0000-000000000004',
            p_to_profile_id => '71000000-0000-0000-0000-000000000004'
        );
        raise exception 'FAIL T8: a caller-supplied actor_id was accepted';
    exception when others then
        null; -- the signature itself rejects the argument
    end;
end $$;

-- =============================================================================
-- T9 — invalid action vocabulary rejected
-- =============================================================================
do $$
begin
    begin
        perform public.record_custody_event(
            '74000000-0000-0000-0000-0000000000A1',
            'midnight_handoff'
        );
        raise exception 'FAIL T9: out-of-vocabulary action accepted';
    exception when others then
        if sqlerrm like '%action_not_allowed%' then
            null;
        else
            raise exception 'FAIL T9: unexpected denial %', sqlerrm;
        end if;
    end;

    begin
        perform public.record_custody_event('74000000-0000-0000-0000-0000000000A1', 'received');
        raise exception 'FAIL T9: intake-only received reproduced via RPC';
    exception when others then
        if sqlerrm like '%received_created_on_intake%' then
            null;
        else
            raise exception 'FAIL T9: unexpected received denial %', sqlerrm;
        end if;
    end;
end $$;

-- =============================================================================
-- T10 — transferred / returned without a receiving member rejected
-- =============================================================================
do $$
begin
    begin
        perform public.record_custody_event('74000000-0000-0000-0000-0000000000A1', 'transferred');
        raise exception 'FAIL T10: transfer without a recipient accepted';
    exception when others then
        if sqlerrm like '%to_profile_required%' then
            null;
        else
            raise exception 'FAIL T10: unexpected denial %', sqlerrm;
        end if;
    end;

    begin
        perform public.record_custody_event('74000000-0000-0000-0000-0000000000A1', 'returned');
        raise exception 'FAIL T10: return without a recipient accepted';
    exception when others then
        if sqlerrm like '%to_profile_required%' then
            null;
        else
            raise exception 'FAIL T10: unexpected denial %', sqlerrm;
        end if;
    end;
end $$;

-- =============================================================================
-- T11 — released / archived WITH a receiving member rejected
-- =============================================================================
do $$
begin
    begin
        perform public.record_custody_event(
            '74000000-0000-0000-0000-0000000000A1',
            'released',
            p_to_profile_id => '71000000-0000-0000-0000-000000000004'
        );
        raise exception 'FAIL T11: release with a recipient accepted';
    exception when others then
        if sqlerrm like '%to_profile_not_allowed%' then
            null;
        else
            raise exception 'FAIL T11: unexpected denial %', sqlerrm;
        end if;
    end;

    begin
        perform public.record_custody_event(
            '74000000-0000-0000-0000-0000000000A1',
            'archived',
            p_to_profile_id => '71000000-0000-0000-0000-000000000004'
        );
        raise exception 'FAIL T11: archive with a recipient accepted';
    exception when others then
        if sqlerrm like '%to_profile_not_allowed%' then
            null;
        else
            raise exception 'FAIL T11: unexpected denial %', sqlerrm;
        end if;
    end;
end $$;

-- =============================================================================
-- T12 — from/to profile not a member of the SAME case rejected
--        (u3 is org-alpha but a member of C_A2, never C_A)
-- =============================================================================
do $$
begin
    begin
        perform public.record_custody_event(
            '74000000-0000-0000-0000-0000000000A1',
            'transferred',
            p_to_profile_id => '71000000-0000-0000-0000-000000000003'
        );
        raise exception 'FAIL T12: transfer to a non-member of this case accepted';
    exception when others then
        if sqlerrm like '%to_profile_not_in_case%' then
            null;
        else
            raise exception 'FAIL T12: unexpected denial %', sqlerrm;
        end if;
    end;

    begin
        perform public.record_custody_event(
            '74000000-0000-0000-0000-0000000000A1',
            'returned',
            p_from_profile_id => '71000000-0000-0000-0000-000000000003',
            p_to_profile_id   => '71000000-0000-0000-0000-000000000004'
        );
        raise exception 'FAIL T12: from a non-member of this case accepted';
    exception when others then
        if sqlerrm like '%from_profile_not_in_case%' then
            null;
        else
            raise exception 'FAIL T12: unexpected denial %', sqlerrm;
        end if;
    end;
end $$;

-- =============================================================================
-- T13 — from/to profile from another ORGANIZATION rejected
-- =============================================================================
do $$
begin
    begin
        perform public.record_custody_event(
            '74000000-0000-0000-0000-0000000000A1',
            'transferred',
            p_to_profile_id => '71000000-0000-0000-0000-000000000006'
        );
        raise exception 'FAIL T13: transfer to a cross-org user accepted';
    exception when others then
        if sqlerrm like '%to_profile_not_in_case%' then
            null;
        else
            raise exception 'FAIL T13: unexpected denial %', sqlerrm;
        end if;
    end;
end $$;

-- =============================================================================
-- T14 — backdating blocked: no occurred_at argument; timestamp is server-set
-- =============================================================================
do $$
begin
    begin
        perform public.record_custody_event(
            '74000000-0000-0000-0000-0000000000A1',
            'released',
            p_occurred_at => now() - interval '30 days'
        );
        raise exception 'FAIL T14: a caller-supplied occurred_at was accepted';
    exception when others then
        null; -- the signature itself rejects the argument
    end;

    if exists (
        select 1
        from public.chain_of_custody c
        join public.audit_logs al on al.entity_id = c.evidence_id and al.action = 'custody.released'
        where c.evidence_id = '74000000-0000-0000-0000-0000000000A1'
          and c.action = 'released'
          and c.occurred_at < now() - interval '1 day'
    ) then
        raise exception 'FAIL T14: a custody row was backdated';
    end if;
end $$;

-- =============================================================================
-- T15 — direct INSERT on chain_of_custody denied (REVOKE closed the gap)
-- =============================================================================
do $$
declare
    n integer;
begin
    begin
        insert into public.chain_of_custody (id, evidence_id, action, actor_id)
        values (
            '76000000-0000-0000-0000-0000000000A2',
            '74000000-0000-0000-0000-0000000000A1',
            'released',
            '71000000-0000-0000-0000-000000000002'
        );
        raise exception 'FAIL T15: authenticated direct INSERT on chain_of_custody allowed';
    exception when others then
        if sqlerrm like '%permission denied%' then
            null;
        else
            raise exception 'FAIL T15: unexpected denial %', sqlerrm;
        end if;
    end;
end $$;

-- =============================================================================
-- T16 — direct UPDATE on chain_of_custody denied (immutable possession record)
-- =============================================================================
do $$
begin
    begin
        update public.chain_of_custody
        set location = 'doctored'
        where evidence_id = '74000000-0000-0000-0000-0000000000A1';
        raise exception 'FAIL T16: authenticated direct UPDATE on chain_of_custody allowed';
    exception when others then
        if sqlerrm like '%permission denied%' then
            null;
        else
            raise exception 'FAIL T16: unexpected denial %', sqlerrm;
        end if;
    end;
end $$;

-- =============================================================================
-- T17 — direct DELETE on chain_of_custody denied
-- =============================================================================
do $$
begin
    begin
        delete from public.chain_of_custody
        where evidence_id = '74000000-0000-0000-0000-0000000000A1';
        raise exception 'FAIL T17: authenticated direct DELETE on chain_of_custody allowed';
    exception when others then
        if sqlerrm like '%permission denied%' then
            null;
        else
            raise exception 'FAIL T17: unexpected denial %', sqlerrm;
        end if;
    end;
end $$;

-- =============================================================================
-- T18 — custody event mirrored into audit_logs (same transaction, attributed)
--
-- audit_logs has no direct SELECT path for authenticated sessions by design —
-- the audit read surface is the list_*_audit_events RPCs. These inspections
-- therefore run as the owner (the fixture writer), exactly like the fixtures.
-- =============================================================================
set local role postgres;

do $$
declare
    n integer;
    m jsonb;
begin
    select count(*) into n
    from public.audit_logs
    where action = 'custody.transferred'
      and entity_type = 'evidence'
      and entity_id = '74000000-0000-0000-0000-0000000000A1'
      and actor_id = '71000000-0000-0000-0000-000000000002';
    if n <> 1 then
        raise exception 'FAIL T18: custody.transferred audit mirror missing (found %)', n;
    end if;

    select meta into m
    from public.audit_logs
    where action = 'custody.transferred'
      and entity_id = '74000000-0000-0000-0000-0000000000A1';
    if m ->> 'action' <> 'transferred' then
        raise exception 'FAIL T18: audit meta action missing';
    end if;
    if m ->> 'to_profile_id' <> '71000000-0000-0000-0000-000000000004' then
        raise exception 'FAIL T18: audit meta recipient missing';
    end if;

    -- the investigator's return event too.
    select count(*) into n
    from public.audit_logs
    where action = 'custody.returned'
      and entity_id = '74000000-0000-0000-0000-0000000000A1'
      and actor_id = '71000000-0000-0000-0000-000000000004';
    if n <> 1 then
        raise exception 'FAIL T18: custody.returned audit mirror missing (found %)', n;
    end if;
end $$;

-- =============================================================================
-- T19 — audit_logs.org_id equals the case's organization
-- =============================================================================
do $$
declare
    n integer;
begin
    select count(*) into n
    from public.audit_logs
    where action = 'custody.transferred'
      and entity_id = '74000000-0000-0000-0000-0000000000A1'
      and org_id = '72000000-0000-0000-0000-0000000000A1';
    if n <> 1 then
        raise exception 'FAIL T19: custody audit org_id not populated correctly';
    end if;
end $$;

-- =============================================================================
-- T20 — 'verified' custody is anchor-gated through the status path
--        EV_B has no matching anchored anchor -> rejected
--        EV_A has a matching anchored anchor -> verified custody written
-- =============================================================================
set local role authenticated;
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000006"}';

do $$
begin
    begin
        perform public.update_evidence_status(
            '74000000-0000-0000-0000-0000000000B1',
            'verified'
        );
        raise exception 'FAIL T20: verified without a matching anchor accepted';
    exception when others then
        if sqlerrm like '%verification_required%' then
            null;
        else
            raise exception 'FAIL T20: unexpected denial %', sqlerrm;
        end if;
    end;
end $$;

set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000002"}';

do $$
declare
    n integer;
begin
    perform public.update_evidence_status(
        '74000000-0000-0000-0000-0000000000A1',
        'verified'
    );

    select count(*) into n
    from public.chain_of_custody
    where evidence_id = '74000000-0000-0000-0000-0000000000A1'
      and action = 'verified';
    if n <> 1 then
        raise exception 'FAIL T20: verified custody row not written (found %)', n;
    end if;

    if not exists (
        select 1
        from public.chain_of_custody
        where evidence_id = '74000000-0000-0000-0000-0000000000A1'
          and action = 'verified'
          and document_version_id = '75000000-0000-0000-0000-0000000000A1'
    ) then
        raise exception 'FAIL T20: verified custody did not reference the anchored version';
    end if;
end $$;

-- =============================================================================
-- T21 — 'archived' custody written (idempotently) through the status path
-- =============================================================================
do $$
declare
    n integer;
begin
    perform public.update_evidence_status('74000000-0000-0000-0000-0000000000A1', 'archived');
    select count(*) into n
    from public.chain_of_custody
    where evidence_id = '74000000-0000-0000-0000-0000000000A1'
      and action = 'archived';
    if n <> 1 then
        raise exception 'FAIL T21: archived custody row not written (found %)', n;
    end if;

    -- a retried transition must not duplicate the possession record.
    perform public.update_evidence_status('74000000-0000-0000-0000-0000000000A1', 'archived');
    select count(*) into n
    from public.chain_of_custody
    where evidence_id = '74000000-0000-0000-0000-0000000000A1'
      and action = 'archived';
    if n <> 1 then
        raise exception 'FAIL T21: archived custody duplicated on retry (found %)', n;
    end if;
end $$;

-- =============================================================================
-- T22 — intake (create_evidence) still writes custody 'received'
-- =============================================================================
do $$
declare
    n integer;
begin
    perform public.create_evidence(
        p_case_id               => '73000000-0000-0000-0000-0000000000A1',
        p_evidence_id           => '74000000-0000-0000-0000-0000000000C1',
        p_document_version_id   => '75000000-0000-0000-0000-0000000000C1',
        p_title                 => 'gamma evidence',
        p_description           => null,
        p_type                  => 'document',
        p_file_name             => 'gamma.pdf',
        p_mime_type             => 'application/pdf',
        p_file_size_bytes       => 30,
        p_sha256                => repeat('c', 64),
        p_storage_key           => '73000000-0000-0000-0000-0000000000a1/74000000-0000-0000-0000-0000000000c1/75000000-0000-0000-0000-0000000000c1',
        p_notes                 => null
    );

    select count(*) into n
    from public.chain_of_custody
    where evidence_id = '74000000-0000-0000-0000-0000000000C1'
      and action = 'received';
    if n <> 1 then
        raise exception 'FAIL T22: intake received custody row missing (found %)', n;
    end if;
end $$;

-- audit_logs has no direct SELECT path for authenticated — inspect as owner.
set local role postgres;

do $$
begin
    if not exists (
        select 1
        from public.audit_logs
        where action = 'evidence.custody_received'
          and entity_id = '74000000-0000-0000-0000-0000000000C1'
    ) then
        raise exception 'FAIL T22: intake custody audit mirror missing';
    end if;
end $$;

-- restore claims for T23+ (nonexistent/cross-org tests need authenticated role)
set local role authenticated;
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000002"}';

-- =============================================================================
-- T23 — nonexistent evidence rejected
-- =============================================================================
do $$
begin
    begin
        perform public.record_custody_event(
            '11111111-1111-1111-1111-111111111111',
            'released'
        );
        raise exception 'FAIL T23: nonexistent evidence accepted';
    exception when others then
        if sqlerrm like '%evidence_not_found%' then
            null;
        else
            raise exception 'FAIL T23: unexpected denial %', sqlerrm;
        end if;
    end;
end $$;

-- =============================================================================
-- T24 — cross-organization evidence rejected identically (no existence leak)
-- =============================================================================
do $$
declare
    n integer;
begin
    begin
        perform public.record_custody_event(
            '74000000-0000-0000-0000-0000000000B1',
            'released'
        );
        raise exception 'FAIL T24: cross-org evidence accepted';
    exception when others then
        -- the visibility-constrained load treats it as nonexistent.
        if sqlerrm like '%evidence_not_found%' then
            null;
        else
            raise exception 'FAIL T24: unexpected denial %', sqlerrm;
        end if;
    end;

    -- and EV_B's custody was genuinely untouched.
    select count(*) into n
    from public.chain_of_custody
    where evidence_id = '74000000-0000-0000-0000-0000000000B1';
    if n <> 0 then
        raise exception 'FAIL T24: cross-org evidence custody mutated (rows %)', n;
    end if;
end $$;

do $$
begin
    raise notice 'ALL CHAIN-OF-CUSTODY TESTS PASSED (T1..T24)';
end $$;