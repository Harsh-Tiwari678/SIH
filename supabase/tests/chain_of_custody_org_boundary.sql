-- =============================================================================
-- SIH26190 Secure Evidence — L1: chain-of-custody organization boundary
--
-- Validates 20260922000000_chain_of_custody_org_boundary.sql. Every profile
-- referenced by from_profile_id / to_profile_id must be a CURRENT member of
-- the case's organization (via organization_members) in addition to the
-- pre-existing explicit case_members requirement. Cross-organization and
-- stale ex-organization profiles are rejected even when an old case_members
-- row survives; possession-neutral (null, null) events and the legitimate
-- same-org handoff keep working.
--
-- Fixtures (organization model: organizations → organization_members →
-- cases → case_members):
--   u1  61000000-0000-0000-0000-000000000001  org_a member, LEAD of C_A  (actor)
--   u2  61000000-0000-0000-0000-000000000002  org_a member, INVESTIGATOR of C_A
--   X   61000000-0000-0000-0000-000000000003  org_b member BUT has a stale case_members
--                                             row on C_A (cross-org for this case)
--   S   61000000-0000-0000-0000-000000000004  org_a member REMOVED but keeps a stale
--                                             case_members row (lead) on C_A
--   uB  61000000-0000-0000-0000-000000000005  org_b admin, LEAD of C_B (org_b needs
--                                             a real member for X to be a valid
--                                             cross-org profile)
--   org_a 62000000-0000-0000-0000-0000000000A1   org_b 62000000-0000-0000-0000-0000000000B1
--   C_A   63000000-0000-0000-0000-0000000000A1 (org_a, active)   C_B 63000000-0000-0000-0000-0000000000B1 (org_b, active)
--   E_A   64000000-0000-0000-0000-0000000000A1 (in C_A)   V_A 65000000-0000-0000-0000-0000000000A1 (version 1)
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Fixtures (test role: postgres, direct inserts)
-- -----------------------------------------------------------------------------
insert into auth.users (id, email, encrypted_password, email_confirmed_at, raw_app_meta_data, created_at, updated_at)
values
  ('61000000-0000-0000-0000-000000000001', 'l1.u1@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('61000000-0000-0000-0000-000000000002', 'l1.u2@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('61000000-0000-0000-0000-000000000003', 'l1.x@example.com',  '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('61000000-0000-0000-0000-000000000004', 'l1.s@example.com',  '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('61000000-0000-0000-0000-000000000005', 'l1.ub@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now());

insert into public.profiles (id, full_name, badge_number, role)
values
  ('61000000-0000-0000-0000-000000000001', 'OrgBoundary Lead A',   'L1A-001', 'officer'),
  ('61000000-0000-0000-0000-000000000002', 'OrgBoundary Inv A',   'L1A-002', 'officer'),
  ('61000000-0000-0000-0000-000000000003', 'OrgBoundary Cross X', 'L1A-003', 'officer'),
  ('61000000-0000-0000-0000-000000000004', 'OrgBoundary Stale S', 'L1A-004', 'officer'),
  ('61000000-0000-0000-0000-000000000005', 'OrgBoundary Lead B',  'L1B-005', 'officer')
on conflict (id) do nothing;

insert into public.organizations (id, name, slug, created_by)
values
  ('62000000-0000-0000-0000-0000000000A1', 'org-l1-alpha', 'l1-alpha', '61000000-0000-0000-0000-000000000001'),
  ('62000000-0000-0000-0000-0000000000B1', 'org-l1-beta',  'l1-beta',  '61000000-0000-0000-0000-000000000005');

insert into public.organization_members (org_id, profile_id, role_in_org, added_by)
values
  ('62000000-0000-0000-0000-0000000000A1', '61000000-0000-0000-0000-000000000001', 'investigator', '61000000-0000-0000-0000-000000000001'),
  ('62000000-0000-0000-0000-0000000000A1', '61000000-0000-0000-0000-000000000002', 'member',       '61000000-0000-0000-0000-000000000001'),
  ('62000000-0000-0000-0000-0000000000A1', '61000000-0000-0000-0000-000000000004', 'member',       '61000000-0000-0000-0000-000000000001'),
  ('62000000-0000-0000-0000-0000000000B1', '61000000-0000-0000-0000-000000000005', 'admin',        '61000000-0000-0000-0000-000000000005'),
  ('62000000-0000-0000-0000-0000000000B1', '61000000-0000-0000-0000-000000000003', 'member',       '61000000-0000-0000-0000-000000000005');

insert into public.cases (id, org_id, case_number, title, description, status, created_by)
values
  ('63000000-0000-0000-0000-0000000000A1', '62000000-0000-0000-0000-0000000000A1', 'L1-CASE-A',  'boundary case A', null, 'active', '61000000-0000-0000-0000-000000000001'),
  ('63000000-0000-0000-0000-0000000000B1', '62000000-0000-0000-0000-0000000000B1', 'L1-CASE-B',  'boundary case B', null, 'active', '61000000-0000-0000-0000-000000000005');

insert into public.case_members (case_id, profile_id, role_in_case, added_by)
values
  ('63000000-0000-0000-0000-0000000000A1', '61000000-0000-0000-0000-000000000001', 'lead',         '61000000-0000-0000-0000-000000000001'),
  ('63000000-0000-0000-0000-0000000000A1', '61000000-0000-0000-0000-000000000002', 'investigator', '61000000-0000-0000-0000-000000000001'),
  -- X: a case_members row for a profile that is NOT a member of org_a (cross-org).
  ('63000000-0000-0000-0000-0000000000A1', '61000000-0000-0000-0000-000000000003', 'member',       '61000000-0000-0000-0000-000000000001'),
  -- S: a case_members row that survives the org_a membership removal below (stale).
  ('63000000-0000-0000-0000-0000000000A1', '61000000-0000-0000-0000-000000000004', 'lead',         '61000000-0000-0000-0000-000000000001'),
  ('63000000-0000-0000-0000-0000000000B1', '61000000-0000-0000-0000-000000000005', 'lead',         '61000000-0000-0000-0000-000000000005');

-- S is removed from org_a but its C_A case_members row stays: the exact
-- "stale ex-organization profile, old case_members row remains" audit case.
delete from public.organization_members
where org_id = '62000000-0000-0000-0000-0000000000A1'
  and profile_id = '61000000-0000-0000-0000-000000000004';

insert into public.evidence (id, case_id, evidence_number, title, description, type, status, created_by)
values
  ('64000000-0000-0000-0000-0000000000A1', '63000000-0000-0000-0000-0000000000A1', 'L1-EV-A', 'boundary evidence A', null, 'document', 'received', '61000000-0000-0000-0000-000000000001'),
  ('64000000-0000-0000-0000-0000000000B1', '63000000-0000-0000-0000-0000000000B1', 'L1-EV-B', 'boundary evidence B', null, 'document', 'received', '61000000-0000-0000-0000-000000000005');

insert into public.document_versions (id, evidence_id, version, prev_version_id, file_name, mime_type, file_size_bytes, sha256, storage_key, uploaded_by, notes)
values
  ('65000000-0000-0000-0000-0000000000A1', '64000000-0000-0000-0000-0000000000A1', 1, null, 'boundary-a.pdf', 'application/pdf', 11, repeat('a', 64), '63000000-0000-0000-0000-0000000000a1/64000000-0000-0000-0000-0000000000a1/65000000-0000-0000-0000-0000000000a1', '61000000-0000-0000-0000-000000000001', null),
  ('65000000-0000-0000-0000-0000000000B1', '64000000-0000-0000-0000-0000000000B1', 1, null, 'boundary-b.pdf', 'application/pdf', 12, repeat('b', 64), '63000000-0000-0000-0000-0000000000b1/64000000-0000-0000-0000-0000000000b1/65000000-0000-0000-0000-0000000000b1', '61000000-0000-0000-0000-000000000005', null);

insert into public.chain_of_custody (id, evidence_id, document_version_id, action, actor_id, from_profile_id, to_profile_id, notes)
values
  ('66000000-0000-0000-0000-0000000000A1', '64000000-0000-0000-0000-0000000000A1', '65000000-0000-0000-0000-0000000000A1', 'received', '61000000-0000-0000-0000-000000000001', null, '61000000-0000-0000-0000-000000000001', 'intake');

-- -----------------------------------------------------------------------------
-- Fixture sanity — the tests must actually be exercising the finding.
-- Under the PRE-L1 code both X and S passed the case-member check because a
-- non-empty case_members row survived; these assertions prove that the rows
-- exist (so the negative tests were genuinely reachable before hardening).
-- -----------------------------------------------------------------------------
set local role postgres;

do $$
begin
    if not exists (
        select 1 from public.case_members
        where case_id = '63000000-0000-0000-0000-0000000000A1'
          and profile_id = '61000000-0000-0000-0000-000000000003'
    ) then
        raise exception 'FAIL L1-fixture: cross-org case_members row for X missing';
    end if;
    if exists (
        select 1 from public.organization_members
        where org_id = '62000000-0000-0000-0000-0000000000A1'
          and profile_id = '61000000-0000-0000-0000-000000000003'
    ) then
        raise exception 'FAIL L1-fixture: X unexpectedly an org_a member';
    end if;
    if not exists (
        select 1 from public.case_members
        where case_id = '63000000-0000-0000-0000-0000000000A1'
          and profile_id = '61000000-0000-0000-0000-000000000004'
    ) then
        raise exception 'FAIL L1-fixture: stale case_members row for S missing';
    end if;
    if exists (
        select 1 from public.organization_members
        where org_id = '62000000-0000-0000-0000-0000000000A1'
          and profile_id = '61000000-0000-0000-0000-000000000004'
    ) then
        raise exception 'FAIL L1-fixture: S still an org_a member (stale simulation broken)';
    end if;
    if not exists (
        select 1 from public.organization_members
        where org_id = '62000000-0000-0000-0000-0000000000A1'
          and profile_id = '61000000-0000-0000-0000-000000000002'
    ) then
        raise exception 'FAIL L1-fixture: u2 (legit same-org profile) missing';
    end if;
end $$;

-- =============================================================================
-- L1-T1 — current same-org profile accepted (u1 → u2, both org_a + C_A members)
-- =============================================================================
set local role authenticated;
set local request.jwt.claims = '{"sub":"61000000-0000-0000-0000-000000000001"}';

do $$
declare
    v_custody public.chain_of_custody;
    n integer;
begin
    select * from public.record_custody_event(
        '64000000-0000-0000-0000-0000000000A1',
        'transferred',
        p_to_profile_id => '61000000-0000-0000-0000-000000000002'
    ) into v_custody;
    if v_custody.to_profile_id <> '61000000-0000-0000-0000-000000000002' then
        raise exception 'FAIL L1-T1: same-org transfer did not persist recipient';
    end if;

    set local role postgres;
    select count(*) into n
    from public.chain_of_custody
    where evidence_id = '64000000-0000-0000-0000-0000000000A1'
      and action = 'transferred';
    if n <> 1 then
        raise exception 'FAIL L1-T1: transferred custody row missing (found %)', n;
    end if;
    if not exists (
        select 1 from public.audit_logs
        where action = 'custody.transferred'
          and entity_id = '64000000-0000-0000-0000-0000000000A1'
          and org_id = '62000000-0000-0000-0000-0000000000A1'
    ) then
        raise exception 'FAIL L1-T1: transfer audit mirror missing';
    end if;
    set local role authenticated;
    set local request.jwt.claims = '{"sub":"61000000-0000-0000-0000-000000000001"}';
end $$;

-- =============================================================================
-- L1-T2 — cross-org from_profile rejected (X holds a C_A case_members row but
--         belongs to org_b; before L1 the old case-membership path accepted it)
-- =============================================================================
do $$
declare
    v_allowed boolean := false;
begin
    begin
        perform public.record_custody_event(
            '64000000-0000-0000-0000-0000000000A1',
            'released',
            p_from_profile_id => '61000000-0000-0000-0000-000000000003'
        );
        v_allowed := true;
    exception when others then
        if sqlerrm not like '%from_profile_not_in_case%' then
            raise exception 'FAIL L1-T2: unexpected denial %', sqlerrm;
        end if;
    end;
    if v_allowed then
        raise exception 'FAIL L1-T2: cross-org from_profile accepted';
    end if;
end $$;

-- =============================================================================
-- L1-T3 — cross-org to_profile rejected
-- =============================================================================
do $$
declare
    v_allowed boolean := false;
begin
    begin
        perform public.record_custody_event(
            '64000000-0000-0000-0000-0000000000A1',
            'transferred',
            p_to_profile_id => '61000000-0000-0000-0000-000000000003'
        );
        v_allowed := true;
    exception when others then
        if sqlerrm not like '%to_profile_not_in_case%' then
            raise exception 'FAIL L1-T3: unexpected denial %', sqlerrm;
        end if;
    end;
    if v_allowed then
        raise exception 'FAIL L1-T3: cross-org to_profile accepted';
    end if;
end $$;

-- =============================================================================
-- L1-T4 — stale ex-org from_profile rejected (S was removed from org_a but its
--         C_A case_members row survives)
-- =============================================================================
do $$
declare
    v_allowed boolean := false;
begin
    begin
        perform public.record_custody_event(
            '64000000-0000-0000-0000-0000000000A1',
            'released',
            p_from_profile_id => '61000000-0000-0000-0000-000000000004'
        );
        v_allowed := true;
    exception when others then
        if sqlerrm not like '%from_profile_not_in_case%' then
            raise exception 'FAIL L1-T4: unexpected denial %', sqlerrm;
        end if;
    end;
    if v_allowed then
        raise exception 'FAIL L1-T4: stale ex-org from_profile accepted';
    end if;
end $$;

-- =============================================================================
-- L1-T5 — stale ex-org to_profile rejected
-- =============================================================================
do $$
declare
    v_allowed boolean := false;
begin
    begin
        perform public.record_custody_event(
            '64000000-0000-0000-0000-0000000000A1',
            'transferred',
            p_to_profile_id => '61000000-0000-0000-0000-000000000004'
        );
        v_allowed := true;
    exception when others then
        if sqlerrm not like '%to_profile_not_in_case%' then
            raise exception 'FAIL L1-T5: unexpected denial %', sqlerrm;
        end if;
    end;
    if v_allowed then
        raise exception 'FAIL L1-T5: stale ex-org to_profile accepted';
    end if;
end $$;

-- =============================================================================
-- L1-T6 — possession-neutral (null, null) event still accepted (released)
-- =============================================================================
do $$
declare
    v_custody public.chain_of_custody;
    n integer;
begin
    select * from public.record_custody_event(
        '64000000-0000-0000-0000-0000000000A1',
        'released'
    ) into v_custody;
    if v_custody.from_profile_id is not null or v_custody.to_profile_id is not null then
        raise exception 'FAIL L1-T6: released event has unexpected profilerarms';
    end if;

    set local role postgres;
    select count(*) into n
    from public.chain_of_custody
    where evidence_id = '64000000-0000-0000-0000-0000000000A1'
      and action = 'released';
    if n <> 1 then
        raise exception 'FAIL L1-T6: released custody row missing (found %)', n;
    end if;
    set local role authenticated;
    set local request.jwt.claims = '{"sub":"61000000-0000-0000-0000-000000000001"}';
end $$;

-- =============================================================================
-- L1-T7 — legitimate custody workflow still passes end-to-end (transfer with
--         document version + notes, then a same-org intake-style handoff)
-- =============================================================================
do $$
declare
    v_custody public.chain_of_custody;
    v_later   public.chain_of_custody;
    n integer;
begin
    select * from public.record_custody_event(
        '64000000-0000-0000-0000-0000000000A1',
        'transferred',
        p_document_version_id => '65000000-0000-0000-0000-0000000000A1',
        p_to_profile_id       => '61000000-0000-0000-0000-000000000002',
        p_location            => 'Evidence room 1',
        p_notes               => 'L1 legitimate handoff'
    ) into v_custody;
    if v_custody.to_profile_id <> '61000000-0000-0000-0000-000000000002'
       or v_custody.document_version_id <> '65000000-0000-0000-0000-0000000000A1'
       or v_custody.location <> 'Evidence room 1'
       or v_custody.notes <> 'L1 legitimate handoff'
    then
        raise exception 'FAIL L1-T7: legitimate transfer fields not persisted';
    end if;

    -- a second same-org handoff in the opposite direction (u2 has explicit
    -- investigator role but not lead — the workflow requires to != actor, so
    -- u2 hands back to u1).
    set local request.jwt.claims = '{"sub":"61000000-0000-0000-0000-000000000002"}';
    select * from public.record_custody_event(
        '64000000-0000-0000-0000-0000000000A1',
        'returned',
        p_to_profile_id => '61000000-0000-0000-0000-000000000001'
    ) into v_later;
    if v_later.action <> 'returned' or v_later.to_profile_id <> '61000000-0000-0000-0000-000000000001' then
        raise exception 'FAIL L1-T7: return handoff fields not persisted';
    end if;

    set local role postgres;
    select count(*) into n
    from public.chain_of_custody
    where evidence_id = '64000000-0000-0000-0000-0000000000A1';
    -- received (fixture) + transferred (T1) + released (T6) + transferred (T7) + returned (T7)
    if n <> 5 then
        raise exception 'FAIL L1-T7: unexpected custody trail length (found %)', n;
    end if;
end $$;

-- =============================================================================
-- Final sweeps — no rejected attempt left a row behind, and the audit trail
-- only contains the five legitimate events.
-- =============================================================================
set local role postgres;

do $$
declare
    n integer;
begin
    select count(*) into n
    from public.chain_of_custody
    where evidence_id = '64000000-0000-0000-0000-0000000000A1';
    if n <> 5 then
        raise exception 'FAIL L1-final: custody trail length %, expected 5', n;
    end if;
    if exists (
        select 1 from public.audit_logs
        where entity_type = 'evidence'
          and entity_id = '64000000-0000-0000-0000-0000000000A1'
          and action like 'custody.%'
          and action not in ('custody.received', 'custody.transferred', 'custody.released', 'custody.returned')
    ) then
        raise exception 'FAIL L1-final: unexpected custody audit action present';
    end if;
end $$;

-- restore the session to a fully-privileged role for the remainder of the file
reset role;

do $$ begin raise notice 'chain_of_custody_org_boundary: all tests passed (L1-T1..L1-T7)'; end $$;