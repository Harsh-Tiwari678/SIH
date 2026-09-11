-- =============================================================================
-- SIH26190 Secure Evidence — organization-aware case security tests
--
-- Verifies the org boundary added by
-- 20260914000000_organization_case_security.sql. The security model under
-- test is:
--
--   CASE READ ACCESS:
--     A user can read a case iff they are a member of the case's organization
--     AND (they are an org ADMIN for it OR they have an explicit case_members
--     row). Foreign-org membership grants nothing.
--
--   CASE WRITE ACCESS: explicit case role only (lead / investigator).
--     Org admins get org-wide READ/AUDIT, not lead-equivalent write.
--
--   CREATION: create_case requires a validated org_id; membership is
--     required; the creator is always auto-added as 'lead'.
--
--   MEMBER MANAGEMENT: RPC-only (direct case_members DML revoked), lead-only,
--     and the target must belong to the case's organization.
--
-- Test inventory (T1..T20):
--   T1   org admin reads a case in their org without explicit membership
--   T2   org investigator with explicit lead membership reads the case
--   T3   org member WITHOUT explicit case membership cannot read the case
--   T4   org member WITH explicit case membership can read the case
--   T5   cross-org user cannot read the other org's case
--   T6   create_case: org member creates a valid case; becomes lead (org_id set)
--   T7   create_case: rejected for an org the caller does not belong to
--   T8   create_case: nonexistent / missing org rejected; anon cannot create
--   T9   evidence read: org admin sees it; cross-org user does not
--   T10  document_versions read: same boundary
--   T11  chain_of_custody read: same boundary
--   T12  blockchain_anchors read: same boundary
--   T13  list_case_audit_events: org admin yes; non-member org user no;
--        cross-org user no (no existence leak)
--   T14  list_evidence_audit_events: same boundary
--   T15  promoting an org member to admin grants org-wide case access
--   T16  demoting back to member removes org-wide access (explicit membership
--        still required)
--   T17  removing an org membership revokes case access even with stale
--        case_members rows (and a never-org-member with a stale row is
--        equally blocked)
--   T18  add_case_member: target from another organization is rejected
--   T19  add_case_member: non-lead and org admin (without explicit lead)
--        are rejected
--   T20  member management via RPC works (change/remove), lead invariants
--        hold, and direct cases/case_members DML is revoked (RPC-only)
--
-- HOW TO RUN (single transaction required — the script relies on `set local`):
--   supabase start          # needs Docker
--   supabase db reset       # apply all migrations on a fresh DB
--   psql "$SUPABASE_DB_URL" -1 -v ON_ERROR_STOP=1 \
--       -f supabase/tests/organization_case_security.sql
-- (or paste the whole file into the Supabase SQL editor, which runs in one
--  transaction, replacing $SUPABASE_DB_URL at the top.)
--
-- Every test either passes silently or aborts with a `FAIL T<n>` exception.
-- The script mutates only rows it creates itself; run against a throwaway DB.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Test users / fixture ids (deterministic, never collide with real data)
-- ---------------------------------------------------------------------------
-- u1  71000000-0000-0000-0000-000000000001  org-alpha admin
-- u2  71000000-0000-0000-0000-000000000002  org-alpha investigator, lead of C_A
-- u3  71000000-0000-0000-0000-000000000003  org-alpha member (promote/demote/remove)
-- u4  71000000-0000-0000-0000-000000000004  org-alpha member, case member (investigator) of C_A
-- u5  71000000-0000-0000-0000-000000000005  org-beta member (cross-org actor)
-- u6  71000000-0000-0000-0000-000000000006  org-beta admin, lead of C_B
-- u7  71000000-0000-0000-0000-000000000007  no org membership (stale case_members row)
-- org_alpha 72000000-0000-0000-0000-0000000000A1
-- org_beta  72000000-0000-0000-0000-0000000000B1
-- C_A       73000000-0000-0000-0000-0000000000A1  (org-alpha)
-- C_B       73000000-0000-0000-0000-0000000000B1  (org-beta)
-- EV_A      74000000-0000-0000-0000-0000000000A1  (case C_A)
-- EV_B      74000000-0000-0000-0000-0000000000B1  (case C_B)
-- V_A       75000000-0000-0000-0000-0000000000A1  (evidence EV_A)
-- V_B       75000000-0000-0000-0000-0000000000B1  (evidence EV_B)
-- COC_A     76000000-0000-0000-0000-0000000000A1  (evidence EV_A)
-- COC_B     76000000-0000-0000-0000-0000000000B1  (evidence EV_B)
-- BA_A      77000000-0000-0000-0000-0000000000A1  (evidence EV_A)
-- BA_B      77000000-0000-0000-0000-0000000000B1  (evidence EV_B)

-- ---------------------------------------------------------------------------
-- Fixtures (run as postgres / owner; RLS is bypassed for the fixture writer)
-- ---------------------------------------------------------------------------

insert into auth.users (id, email, encrypted_password, email_confirmed_at, raw_app_meta_data, created_at, updated_at)
values
  ('71000000-0000-0000-0000-000000000001', 'c.u1@example.com',      '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('71000000-0000-0000-0000-000000000002', 'c.u2@example.com',      '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('71000000-0000-0000-0000-000000000003', 'c.u3@example.com',      '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('71000000-0000-0000-0000-000000000004', 'c.u4@example.com',      '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('71000000-0000-0000-0000-000000000005', 'c.u5@example.com',      '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('71000000-0000-0000-0000-000000000006', 'c.u6@example.com',      '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('71000000-0000-0000-0000-000000000007', 'c.u7@example.com',      '', now(), '{"role":"authenticated","provider":"email"}', now(), now());

insert into public.profiles (id, full_name, role)
values
  ('71000000-0000-0000-0000-000000000001', 'Case Sec Admin Alpha',     'officer'),
  ('71000000-0000-0000-0000-000000000002', 'Case Sec Lead Alpha',      'officer'),
  ('71000000-0000-0000-0000-000000000003', 'Case Sec Member Alpha',    'officer'),
  ('71000000-0000-0000-0000-000000000004', 'Case Sec Member Alpha 2',  'officer'),
  ('71000000-0000-0000-0000-000000000005', 'Case Sec Member Beta',     'officer'),
  ('71000000-0000-0000-0000-000000000006', 'Case Sec Admin Beta',      'officer'),
  ('71000000-0000-0000-0000-000000000007', 'Case Sec Outsider',        'officer')
on conflict (id) do nothing;

-- Organizations
insert into public.organizations (id, name, slug, created_by)
values
  ('72000000-0000-0000-0000-0000000000A1', 'Org Alpha', 'org-alpha', '71000000-0000-0000-0000-000000000001'),
  ('72000000-0000-0000-0000-0000000000B1', 'Org Beta',  'org-beta',  '71000000-0000-0000-0000-000000000006');

-- Organization members
insert into public.organization_members (org_id, profile_id, role_in_org, added_by)
values
  ('72000000-0000-0000-0000-0000000000A1', '71000000-0000-0000-0000-000000000001', 'admin',        '71000000-0000-0000-0000-000000000001'),
  ('72000000-0000-0000-0000-0000000000A1', '71000000-0000-0000-0000-000000000002', 'investigator', '71000000-0000-0000-0000-000000000001'),
  ('72000000-0000-0000-0000-0000000000A1', '71000000-0000-0000-0000-000000000003', 'member',       '71000000-0000-0000-0000-000000000001'),
  ('72000000-0000-0000-0000-0000000000A1', '71000000-0000-0000-0000-000000000004', 'member',       '71000000-0000-0000-0000-000000000001'),
  ('72000000-0000-0000-0000-0000000000B1', '71000000-0000-0000-0000-000000000006', 'admin',        '71000000-0000-0000-0000-000000000006'),
  ('72000000-0000-0000-0000-0000000000B1', '71000000-0000-0000-0000-000000000005', 'member',       '71000000-0000-0000-0000-000000000006');

-- Cases (org_id is NOT NULL; explicit here). C_A has NO membership for its org
-- admin u1 on purpose: org-wide read must come from the org role, not a row.
insert into public.cases (id, org_id, case_number, title, description, status, created_by)
values
  ('73000000-0000-0000-0000-0000000000A1', '72000000-0000-0000-0000-0000000000A1', 'ORG-CASE-A', 'Org-aware case A', null, 'active', '71000000-0000-0000-0000-000000000002'),
  ('73000000-0000-0000-0000-0000000000B1', '72000000-0000-0000-0000-0000000000B1', 'ORG-CASE-B', 'Org-aware case B', null, 'active', '71000000-0000-0000-0000-000000000006');

-- Case members. u7 intentionally holds a case_members row for C_A with NO
-- organization membership — the org boundary must ignore that stale row.
insert into public.case_members (case_id, profile_id, role_in_case, added_by)
values
  ('73000000-0000-0000-0000-0000000000A1', '71000000-0000-0000-0000-000000000002', 'lead',         '71000000-0000-0000-0000-000000000002'),
  ('73000000-0000-0000-0000-0000000000A1', '71000000-0000-0000-0000-000000000004', 'investigator', '71000000-0000-0000-0000-000000000002'),
  ('73000000-0000-0000-0000-0000000000A1', '71000000-0000-0000-0000-000000000007', 'viewer',       '71000000-0000-0000-0000-000000000002'),
  ('73000000-0000-0000-0000-0000000000B1', '71000000-0000-0000-0000-000000000006', 'lead',         '71000000-0000-0000-0000-000000000006'),
  ('73000000-0000-0000-0000-0000000000B1', '71000000-0000-0000-0000-000000000005', 'member',       '71000000-0000-0000-0000-000000000006');

-- Evidence
insert into public.evidence (id, case_id, evidence_number, title, description, type, status, created_by)
values
  ('74000000-0000-0000-0000-0000000000A1', '73000000-0000-0000-0000-0000000000A1', 'EV-A1', 'Alpha evidence', null, 'document', 'received',  '71000000-0000-0000-0000-000000000004'),
  ('74000000-0000-0000-0000-0000000000B1', '73000000-0000-0000-0000-0000000000B1', 'EV-B1', 'Beta evidence',  null, 'document', 'received',  '71000000-0000-0000-0000-000000000005');

-- Document versions
insert into public.document_versions (id, evidence_id, version, prev_version_id, file_name, mime_type, file_size_bytes, sha256, storage_key, uploaded_by, notes)
values
  ('75000000-0000-0000-0000-0000000000A1', '74000000-0000-0000-0000-0000000000A1', 1, null, 'alpha.pdf', 'application/pdf', 10, repeat('a', 64), '73000000-0000-0000-0000-0000000000A1/74000000-0000-0000-0000-0000000000A1/75000000-0000-0000-0000-0000000000A1', '71000000-0000-0000-0000-000000000004', null),
  ('75000000-0000-0000-0000-0000000000B1', '74000000-0000-0000-0000-0000000000B1', 1, null, 'beta.pdf',  'application/pdf', 20, repeat('b', 64), '73000000-0000-0000-0000-0000000000B1/74000000-0000-0000-0000-0000000000B1/75000000-0000-0000-0000-0000000000B1', '71000000-0000-0000-0000-000000000005', null);

-- Chain of custody
insert into public.chain_of_custody (id, evidence_id, document_version_id, action, actor_id, from_profile_id, to_profile_id, notes)
values
  ('76000000-0000-0000-0000-0000000000A1', '74000000-0000-0000-0000-0000000000A1', '75000000-0000-0000-0000-0000000000A1', 'received', '71000000-0000-0000-0000-000000000004', null, '71000000-0000-0000-0000-000000000004', null),
  ('76000000-0000-0000-0000-0000000000B1', '74000000-0000-0000-0000-0000000000B1', '75000000-0000-0000-0000-0000000000B1', 'received', '71000000-0000-0000-0000-000000000005', null, '71000000-0000-0000-0000-000000000005', null);

-- Blockchain anchors
insert into public.blockchain_anchors (id, evidence_id, document_version_id, network, chain_id, contract_address, evidence_id_hash, version_id_hash, evidence_sha256, status, tx_hash, block_number, anchored_at)
values
  ('77000000-0000-0000-0000-0000000000A1', '74000000-0000-0000-0000-0000000000A1', '75000000-0000-0000-0000-0000000000A1', 'sepolia', 11155111, '0x' || repeat('0', 40), '0x' || repeat('a', 64), '0x' || repeat('a', 64), repeat('a', 64), 'anchored', '0x' || repeat('1', 64), 1, now()),
  ('77000000-0000-0000-0000-0000000000B1', '74000000-0000-0000-0000-0000000000B1', '75000000-0000-0000-0000-0000000000B1', 'sepolia', 11155111, '0x' || repeat('0', 40), '0x' || repeat('b', 64), '0x' || repeat('b', 64), repeat('b', 64), 'anchored', '0x' || repeat('2', 64), 1, now());

-- Minimal audit rows so the audit read RPCs return real, resolvable data.
insert into public.audit_logs (actor_id, action, entity_type, entity_id, after, meta)
values
  ('71000000-0000-0000-0000-000000000002', 'case.created',      'case',    '73000000-0000-0000-0000-0000000000A1', null, jsonb_build_object('case_number', 'ORG-CASE-A')),
  ('71000000-0000-0000-0000-000000000004', 'evidence.created',  'evidence', '74000000-0000-0000-0000-0000000000A1', null, jsonb_build_object('case_id', '73000000-0000-0000-0000-0000000000A1', 'evidence_number', 'EV-A1')),
  ('71000000-0000-0000-0000-000000000006', 'case.created',      'case',    '73000000-0000-0000-0000-0000000000B1', null, jsonb_build_object('case_number', 'ORG-CASE-B'));

-- =============================================================================
-- T1 — org admin reads a case in their org without explicit case membership
-- =============================================================================
set local role authenticated;
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000001"}';

do $$
begin
    if not exists (
        select 1
        from public.cases
        where id = '73000000-0000-0000-0000-0000000000A1'
    ) then
        raise exception 'FAIL T1: org admin cannot read a case of their org without explicit membership';
    end if;
end $$;

-- =============================================================================
-- T2 — org investigator with explicit lead membership reads the case
-- =============================================================================
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000002"}';

do $$
begin
    if not exists (
        select 1
        from public.cases
        where id = '73000000-0000-0000-0000-0000000000A1'
    ) then
        raise exception 'FAIL T2: explicit lead cannot read their case';
    end if;
end $$;

-- =============================================================================
-- T3 — org member WITHOUT explicit case membership cannot read the case
-- =============================================================================
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000003"}';

do $$
begin
    if exists (
        select 1
        from public.cases
        where id = '73000000-0000-0000-0000-0000000000A1'
    ) then
        raise exception 'FAIL T3: org member without explicit case membership can read the case';
    end if;
end $$;

-- =============================================================================
-- T4 — org member WITH explicit case membership can read the case
-- =============================================================================
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000004"}';

do $$
begin
    if not exists (
        select 1
        from public.cases
        where id = '73000000-0000-0000-0000-0000000000A1'
    ) then
        raise exception 'FAIL T4: org member with explicit case membership cannot read the case';
    end if;
    if not exists (
        select 1
        from public.case_members
        where case_id = '73000000-0000-0000-0000-0000000000A1'
          and profile_id = '71000000-0000-0000-0000-000000000004'
    ) then
        raise exception 'FAIL T4: member cannot read their own membership row';
    end if;
end $$;

-- =============================================================================
-- T5 — cross-org user cannot read the other org's case (but can read their own)
-- =============================================================================
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000005"}';

do $$
begin
    if exists (
        select 1
        from public.cases
        where id = '73000000-0000-0000-0000-0000000000A1'
    ) then
        raise exception 'FAIL T5: cross-org user can read the other org''s case';
    end if;
    if not exists (
        select 1
        from public.cases
        where id = '73000000-0000-0000-0000-0000000000B1'
    ) then
        raise exception 'FAIL T5: member cannot read their own org''s case';
    end if;
end $$;

-- org-beta admin reads org-beta case, never org-alpha.
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000006"}';

do $$
begin
    if not exists (
        select 1 from public.cases where id = '73000000-0000-0000-0000-0000000000B1'
    ) then
        raise exception 'FAIL T5: beta admin cannot read beta case';
    end if;
    if exists (
        select 1 from public.cases where id = '73000000-0000-0000-0000-0000000000A1'
    ) then
        raise exception 'FAIL T5: beta admin can read alpha case';
    end if;
end $$;

-- =============================================================================
-- T6 — create_case: org member creates a valid case and becomes lead
-- =============================================================================
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000003"}';

do $$
declare
    v_case_id uuid;
    v_case    public.cases;
begin
    -- create_case returns the full cases row; capture only its id into the
    -- uuid variable (never assign the composite value to a uuid).
    select (public.create_case(
        '72000000-0000-0000-0000-0000000000A1',
        'ORG-CASE-NEW',
        'Created by org member',
        null
    )).id into v_case_id;

    if v_case_id is null then
        raise exception 'FAIL T6: create_case returned no case';
    end if;

    -- reload the full row for the org_id assertion (u3 is the lead of the new
    -- case, so the read passes org-aware RLS).
    select c.* into v_case from public.cases c where c.id = v_case_id;
    if v_case.org_id <> '72000000-0000-0000-0000-0000000000A1' then
        raise exception 'FAIL T6: created case has wrong org_id';
    end if;
    -- the creator is always the lead (atomic invariant)
    if not exists (
        select 1
        from public.case_members
        where case_id = v_case_id
          and profile_id = '71000000-0000-0000-0000-000000000003'
          and role_in_case = 'lead'
    ) then
        raise exception 'FAIL T6: creator was not added as case lead';
    end if;
    -- a case.created audit row exists for the new case. Direct audit_logs
    -- reads are restricted to global admin/supervisor roles, so verify the
    -- write as the fixture owner the same way the audit suite does.
    set local role postgres;
    if not exists (
        select 1
        from public.audit_logs
        where entity_type = 'case'
          and entity_id = v_case_id
          and action = 'case.created'
    ) then
        raise exception 'FAIL T6: missing case.created audit row';
    end if;
    set local role authenticated;
end $$;

-- =============================================================================
-- T7 — create_case: rejected for an org the caller does not belong to
-- =============================================================================
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000005"}';

do $$
begin
    begin
        perform public.create_case(
            '72000000-0000-0000-0000-0000000000A1',
            'ORG-CASE-X',
            'Cross-org creation attempt',
            null
        );
        raise exception 'FAIL T7: create_case accepted an org the caller does not belong to';
    exception when others then
        if sqlerrm not like '%not_org_member%' then
            raise;
        end if;
    end;
end $$;

-- =============================================================================
-- T8 — create_case: nonexistent / missing org rejected; anon cannot create
-- =============================================================================
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000003"}';

do $$
begin
    begin
        perform public.create_case(
            '72000000-0000-0000-0000-0000000000FF',
            'ORG-CASE-Y',
            'Nonexistent org',
            null
        );
        raise exception 'FAIL T8: create_case accepted a nonexistent org';
    exception when others then
        if sqlerrm not like '%org_not_found%' then
            raise;
        end if;
    end;
end $$;

do $$
begin
    begin
        perform public.create_case(
            null,
            'ORG-CASE-Z',
            'Missing org',
            null
        );
        raise exception 'FAIL T8: create_case accepted a null org';
    exception when others then
        if sqlerrm not like '%org_required%' then
            raise;
        end if;
    end;
end $$;

set local role anon;
set local request.jwt.claims = '{"sub": null, "role": "anon"}';

do $$
begin
    begin
        perform public.create_case(
            '72000000-0000-0000-0000-0000000000A1',
            'ORG-CASE-ANON',
            'Anon creation attempt',
            null
        );
        raise exception 'FAIL T8: anon can execute create_case';
    exception when insufficient_privilege or undefined_function then
        null;
    end;
end $$;

-- =============================================================================
-- T9 — evidence read: org admin sees it; cross-org user does not
-- =============================================================================
set local role authenticated;
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000001"}';

do $$
begin
    if not exists (
        select 1 from public.evidence
        where id = '74000000-0000-0000-0000-0000000000A1'
    ) then
        raise exception 'FAIL T9: org admin cannot read evidence of their org';
    end if;
end $$;

set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000005"}';

do $$
begin
    if exists (
        select 1 from public.evidence
        where id = '74000000-0000-0000-0000-0000000000A1'
    ) then
        raise exception 'FAIL T9: cross-org user can read the other org''s evidence';
    end if;
    if not exists (
        select 1 from public.evidence
        where id = '74000000-0000-0000-0000-0000000000B1'
    ) then
        raise exception 'FAIL T9: member cannot read their own org''s evidence';
    end if;
end $$;

-- =============================================================================
-- T10 — document_versions read: same boundary
-- =============================================================================
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000001"}';

do $$
begin
    if not exists (
        select 1 from public.document_versions
        where id = '75000000-0000-0000-0000-0000000000A1'
    ) then
        raise exception 'FAIL T10: org admin cannot read document_versions of their org';
    end if;
end $$;

set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000005"}';

do $$
begin
    if exists (
        select 1 from public.document_versions
        where id = '75000000-0000-0000-0000-0000000000A1'
    ) then
        raise exception 'FAIL T10: cross-org user can read the other org''s document_versions';
    end if;
    if not exists (
        select 1 from public.document_versions
        where id = '75000000-0000-0000-0000-0000000000B1'
    ) then
        raise exception 'FAIL T10: member cannot read their own org''s document_versions';
    end if;
end $$;

-- =============================================================================
-- T11 — chain_of_custody read: same boundary
-- =============================================================================
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000001"}';

do $$
begin
    if not exists (
        select 1 from public.chain_of_custody
        where id = '76000000-0000-0000-0000-0000000000A1'
    ) then
        raise exception 'FAIL T11: org admin cannot read chain_of_custody of their org';
    end if;
end $$;

set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000005"}';

do $$
begin
    if exists (
        select 1 from public.chain_of_custody
        where id = '76000000-0000-0000-0000-0000000000A1'
    ) then
        raise exception 'FAIL T11: cross-org user can read the other org''s chain_of_custody';
    end if;
    if not exists (
        select 1 from public.chain_of_custody
        where id = '76000000-0000-0000-0000-0000000000B1'
    ) then
        raise exception 'FAIL T11: member cannot read their own org''s chain_of_custody';
    end if;
end $$;

-- =============================================================================
-- T12 — blockchain_anchors read: same boundary
-- =============================================================================
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000001"}';

do $$
begin
    if not exists (
        select 1 from public.blockchain_anchors
        where id = '77000000-0000-0000-0000-0000000000A1'
    ) then
        raise exception 'FAIL T12: org admin cannot read blockchain_anchors of their org';
    end if;
end $$;

set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000005"}';

do $$
begin
    if exists (
        select 1 from public.blockchain_anchors
        where id = '77000000-0000-0000-0000-0000000000A1'
    ) then
        raise exception 'FAIL T12: cross-org user can read the other org''s blockchain_anchors';
    end if;
    if not exists (
        select 1 from public.blockchain_anchors
        where id = '77000000-0000-0000-0000-0000000000B1'
    ) then
        raise exception 'FAIL T12: member cannot read their own org''s blockchain_anchors';
    end if;
end $$;

-- =============================================================================
-- T13 — list_case_audit_events: org admin yes; org non-member and cross-org no
-- =============================================================================
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000001"}';

do $$
begin
    if (select count(*) from public.list_case_audit_events('73000000-0000-0000-0000-0000000000A1')) <> 2 then
        raise exception 'FAIL T13: org admin does not see the full case audit trail';
    end if;
end $$;

-- org member without explicit case membership -> case_not_found (no leak).
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000003"}';

do $$
begin
    begin
        perform * from public.list_case_audit_events('73000000-0000-0000-0000-0000000000A1');
        raise exception 'FAIL T13: non-member org user can list another case''s audit trail';
    exception when others then
        if sqlerrm not like '%case_not_found%' then
            raise;
        end if;
    end;
end $$;

-- cross-org user -> case_not_found (no existence leak).
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000005"}';

do $$
begin
    begin
        perform * from public.list_case_audit_events('73000000-0000-0000-0000-0000000000A1');
        raise exception 'FAIL T13: cross-org user can list the other org''s audit trail';
    exception when others then
        if sqlerrm not like '%case_not_found%' then
            raise;
        end if;
    end;
end $$;

-- =============================================================================
-- T14 — list_evidence_audit_events: same boundary
-- =============================================================================
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000001"}';

do $$
begin
    if (select count(*) from public.list_evidence_audit_events('74000000-0000-0000-0000-0000000000A1')) <> 1 then
        raise exception 'FAIL T14: org admin does not see the evidence audit trail';
    end if;
end $$;

set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000005"}';

do $$
begin
    begin
        perform * from public.list_evidence_audit_events('74000000-0000-0000-0000-0000000000A1');
        raise exception 'FAIL T14: cross-org user can list the other org''s evidence audit trail';
    exception when others then
        if sqlerrm not like '%evidence_not_found%' then
            raise;
        end if;
    end;
end $$;

-- =============================================================================
-- T15/T16 — organization role change grants / revokes org-wide case access
-- =============================================================================
-- T15: promote org member u3 to org admin -> org-wide read without membership.
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000001"}';

do $$
declare
    v_role text;
begin
    select public.change_organization_member_role(
        '72000000-0000-0000-0000-0000000000A1',
        '71000000-0000-0000-0000-000000000003',
        'admin'
    ) into v_role;
    if v_role <> 'admin' then
        raise exception 'FAIL T15: change_organization_member_role returned %', v_role;
    end if;
end $$;

set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000003"}';

do $$
begin
    if not exists (
        select 1 from public.cases
        where id = '73000000-0000-0000-0000-0000000000A1'
    ) then
        raise exception 'FAIL T15: promoted org admin does not get org-wide case read';
    end if;
end $$;

-- T16: demote back to member -> org-wide access gone (C_A has no membership
-- for u3 now that the T6 case they lead is a different case).
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000001"}';

do $$
declare
    v_role text;
begin
    select public.change_organization_member_role(
        '72000000-0000-0000-0000-0000000000A1',
        '71000000-0000-0000-0000-000000000003',
        'member'
    ) into v_role;
    if v_role <> 'member' then
        raise exception 'FAIL T16: change_organization_member_role returned %', v_role;
    end if;
end $$;

set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000003"}';

do $$
begin
    if exists (
        select 1 from public.cases
        where id = '73000000-0000-0000-0000-0000000000A1'
    ) then
        raise exception 'FAIL T16: demoted org member keeps org-wide case read';
    end if;
end $$;

-- =============================================================================
-- T17 — removing org membership revokes case access even with stale rows
-- =============================================================================
-- u4 has an explicit case_members (investigator) row on C_A. Removing u4 from
-- org-alpha must strip read access to C_A, EV_A and the audit trail anyway —
-- stale case_members data alone grants nothing.
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000001"}';

do $$
begin
    perform public.remove_organization_member(
        '72000000-0000-0000-0000-0000000000A1',
        '71000000-0000-0000-0000-000000000004'
    );
end $$;

-- sanity: the stale case_members row still exists (org membership is gone only)
do $$
begin
    if not exists (
        select 1 from public.case_members
        where case_id = '73000000-0000-0000-0000-0000000000A1'
          and profile_id = '71000000-0000-0000-0000-000000000004'
    ) then
        raise exception 'FAIL T17: fixture stalled — stale case_members row missing';
    end if;
end $$;

set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000004"}';

do $$
begin
    if exists (
        select 1 from public.cases
        where id = '73000000-0000-0000-0000-0000000000A1'
    ) then
        raise exception 'FAIL T17: removed member keeps case read despite stale case_members';
    end if;
    if exists (
        select 1 from public.evidence
        where id = '74000000-0000-0000-0000-0000000000A1'
    ) then
        raise exception 'FAIL T17: removed member keeps evidence read despite stale case_members';
    end if;
    begin
        perform * from public.list_case_audit_events('73000000-0000-0000-0000-0000000000A1');
        raise exception 'FAIL T17: removed member can read the audit trail';
    exception when others then
        if sqlerrm not like '%case_not_found%' then
            raise;
        end if;
    end;
end $$;

-- u7 was NEVER in an org yet holds a case_members row on C_A: still blocked.
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000007"}';

do $$
begin
    if exists (
        select 1 from public.cases
        where id = '73000000-0000-0000-0000-0000000000A1'
    ) then
        raise exception 'FAIL T17: stale-only case member without any org membership can read';
    end if;
end $$;

-- =============================================================================
-- T18 — add_case_member: target from another organization is rejected
-- =============================================================================
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000002"}';

do $$
begin
    begin
        perform public.add_case_member(
            '73000000-0000-0000-0000-0000000000A1',
            '71000000-0000-0000-0000-000000000005',
            'investigator'
        );
        raise exception 'FAIL T18: cross-org target was added as case member';
    exception when others then
        if sqlerrm not like '%target_not_in_org%' then
            raise;
        end if;
    end;
    -- no membership row was created for the cross-org target
    if exists (
        select 1 from public.case_members
        where case_id = '73000000-0000-0000-0000-0000000000A1'
          and profile_id = '71000000-0000-0000-0000-000000000005'
    ) then
        raise exception 'FAIL T18: rejected cross-org add left a membership behind';
    end if;
end $$;

-- The same-org add succeeds (positive control for the check above).
do $$
begin
    perform public.add_case_member(
        '73000000-0000-0000-0000-0000000000A1',
        '71000000-0000-0000-0000-000000000003',
        'member'
    );
    if not exists (
        select 1 from public.case_members
        where case_id = '73000000-0000-0000-0000-0000000000A1'
          and profile_id = '71000000-0000-0000-0000-000000000003'
          and role_in_case = 'member'
    ) then
        raise exception 'FAIL T18: same-org member add did not persist';
    end if;
end $$;

-- =============================================================================
-- T19 — add_case_member: non-lead and org admin (no explicit lead) rejected
-- =============================================================================
-- u3 (org-alpha member with a 'member' role on C_A added in T18 — a valid case
-- member who is NOT the lead) cannot add members. NOTE: u4 is NOT usable here:
-- T17 removed u4 from org-alpha, so its stale case_members row grants nothing
-- and the attempt fails visibility (case_not_found) instead of not_lead.
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000003"}';

do $$
begin
    begin
        perform public.add_case_member(
            '73000000-0000-0000-0000-0000000000A1',
            '71000000-0000-0000-0000-000000000002',
            'investigator'
        );
        raise exception 'FAIL T19: non-lead case member added a member';
    exception when others then
        if sqlerrm not like '%not_lead%' then
            raise;
        end if;
    end;
end $$;

-- u1 (org ADMIN of alpha, but NOT an explicit lead of C_A) cannot add members.
-- Documented decision: org admins get org-wide READ/AUDIT, not lead-equivalent
-- WRITE authority. Case write authority requires explicit case membership.
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000001"}';

do $$
begin
    begin
        perform public.add_case_member(
            '73000000-0000-0000-0000-0000000000A1',
            '71000000-0000-0000-0000-000000000003',
            'member'
        );
        raise exception 'FAIL T19: org admin without explicit lead membership added a member';
    exception when others then
        if sqlerrm not like '%not_lead%' then
            raise;
        end if;
    end;
end $$;

-- =============================================================================
-- T20 — member management via RPC works; lead invariants hold; DML is revoked
-- =============================================================================
-- u2 (lead) can change u3's role and remove u3; the lead cannot be changed or
-- removed (target_is_lead) even by the org admin.
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000002"}';

do $$
declare
    v_member public.case_members;
begin
    -- change role
    select * into v_member
    from public.change_case_member_role(
        '73000000-0000-0000-0000-0000000000A1',
        '71000000-0000-0000-0000-000000000003',
        'viewer'
    );
    if v_member.role_in_case <> 'viewer' then
        raise exception 'FAIL T20: role change did not persist';
    end if;

    -- remove member
    select * into v_member
    from public.remove_case_member(
        '73000000-0000-0000-0000-0000000000A1',
        '71000000-0000-0000-0000-000000000003'
    );
    if exists (
        select 1 from public.case_members
        where case_id = '73000000-0000-0000-0000-0000000000A1'
          and profile_id = '71000000-0000-0000-0000-000000000003'
    ) then
        raise exception 'FAIL T20: member removal did not delete the row';
    end if;
end $$;

-- u2 (the lead) can never change or remove the lead — including trying to
-- change/remove their OWN lead row (target_is_lead). No other actor is a lead
-- of C_A, and an org admin without explicit lead is rejected earlier as
-- not_lead (T19), so the lead-lead guard is exercised at actor==target.
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000002"}';

do $$
begin
    begin
        perform public.change_case_member_role(
            '73000000-0000-0000-0000-0000000000A1',
            '71000000-0000-0000-0000-000000000002',
            'member'
        );
        raise exception 'FAIL T20: the case lead role was changed';
    exception when others then
        if sqlerrm not like '%target_is_lead%' then
            raise;
        end if;
    end;

    begin
        perform public.remove_case_member(
            '73000000-0000-0000-0000-0000000000A1',
            '71000000-0000-0000-0000-000000000002'
        );
        raise exception 'FAIL T20: the case lead was removed';
    exception when others then
        if sqlerrm not like '%target_is_lead%' then
            raise;
        end if;
    end;
end $$;

-- Direct DML on cases / case_members is revoked (RPC-only), as is case INSERT.
set local request.jwt.claims = '{"sub":"71000000-0000-0000-0000-000000000002"}';

do $$
begin
    begin
        insert into public.cases (org_id, case_number, title, description, status, created_by)
        values ('72000000-0000-0000-0000-0000000000A1', 'ORG-CASE-W1', 'Direct insert', null, 'active', '71000000-0000-0000-0000-000000000002');
        raise exception 'FAIL T20: authenticated can INSERT cases directly';
    exception when insufficient_privilege or check_violation then
        null;
    end;

    begin
        insert into public.case_members (case_id, profile_id, role_in_case, added_by)
        values ('73000000-0000-0000-0000-0000000000A1', '71000000-0000-0000-0000-000000000003', 'member', '71000000-0000-0000-0000-000000000002');
        raise exception 'FAIL T20: authenticated can INSERT case_members directly';
    exception when insufficient_privilege or check_violation then
        null;
    end;

    begin
        update public.case_members
        set role_in_case = 'viewer'
        where case_id = '73000000-0000-0000-0000-0000000000A1';
        raise exception 'FAIL T20: authenticated can UPDATE case_members directly';
    exception when insufficient_privilege or check_violation then
        null;
    end;

    begin
        delete from public.case_members
        where case_id = '73000000-0000-0000-0000-0000000000A1'
          and profile_id = '71000000-0000-0000-0000-000000000002';
        raise exception 'FAIL T20: authenticated can DELETE case_members directly';
    exception when insufficient_privilege or check_violation then
        null;
    end;
end $$;

-- =============================================================================
-- Final integrity sweep (owner context)
-- =============================================================================
reset role;

do $$
begin
    -- T17 deliberately left two STALE, org-less case_members rows behind (u4
    -- on C_A, u7 on C_A) to prove they grant nothing. They are test-only and
    -- were never created through a product path (add_case_member enforces the
    -- org boundary at write time). Remove them now so the invariant below can
    -- assert "no row violating the org boundary" — after these, every
    -- remaining case_members row must point at a member of its case's org.
    delete from public.case_members
    where case_id = '73000000-0000-0000-0000-0000000000A1'
      and profile_id in (
          '71000000-0000-0000-0000-000000000004',
          '71000000-0000-0000-0000-000000000007'
      );
end $$;

do $$
declare
    v_bad bigint;
begin
    -- Every case_members row must point at a member of the SAME org as its
    -- case: a cross-org membership is impossible via any product path.
    select count(*) into v_bad
    from public.case_members cm
    join public.cases c on c.id = cm.case_id
    where not exists (
        select 1 from public.organization_members om
        where om.org_id = c.org_id and om.profile_id = cm.profile_id
    );
    if v_bad > 0 then
        raise exception 'FAIL final: % case_members rows violate the org boundary', v_bad;
    end if;

    -- Case creation only via RPC: every case must have been created by a
    -- member of the case's organization.
    select count(*) into v_bad
    from public.cases c
    where not exists (
        select 1 from public.organization_members om
        where om.org_id = c.org_id and om.profile_id = c.created_by
    );
    if v_bad > 0 then
        raise exception 'FAIL final: % cases created by a non-org-member', v_bad;
    end if;
end $$;