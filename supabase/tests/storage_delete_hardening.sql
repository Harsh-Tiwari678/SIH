-- =============================================================================
-- SIH26190 Secure Evidence — H1 storage DELETE hardening tests
--
-- Verifies 20260920000000_harden_storage_delete.sql. The security model under
-- test:
--
--   EVIDENCE OBJECT DELETION:
--     An evidence object may be deleted ONLY via public.delete_evidence_object()
--     by a user who is ALL of:
--       * authenticated with a profile,
--       * a CURRENT member of the case's organization (stale membership fails),
--       * lead or investigator on the REAL case (case_members alone is not
--         enough without org membership),
--       * the case is open ('draft' | 'active'),
--       * the key is claimed by a real document_versions row whose evidence
--         belongs to the case named by the key (no orphan cleanup, no
--         cross-case / cross-org key forgery).
--     Direct storage.objects DELETE (storage API or SQL) is denied for all
--     application roles: the DELETE policy is dropped AND the table-level
--     DELETE grant is revoked.
--
--   EVIDENCE READ (regression): resolve_evidence_access is org-aware only; the
--     old creator-only branch is gone, so a stale-membership creator cannot
--     read/download.
--
-- Test inventory (T1..T15):
--   T1   lead: direct storage DELETE of an open-case object is denied
--   T2   investigator: direct storage DELETE of an open-case object is denied
--   T3   stale org member / stale creator: direct DELETE denied; RPC denied
--   T4   stale creator/member: resolve_evidence_access -> evidence_not_found
--   T5   lead: closed-case object delete denied (direct + RPC)
--   T6   lead: archived-case object delete denied (direct + RPC)
--   T7   investigator: closed-case object delete denied (direct + RPC)
--   T8   investigator: archived-case object delete denied (direct + RPC)
--   T9   RPC: key with no document_versions row is rejected
--   T10  RPC: cross-case key is rejected (storage_key_case_mismatch)
--   T11  RPC: cross-org key is rejected (not_org_member)
--   T12  RPC: authorized cleanup of an open-case object succeeds + audits
--   T13  resolve_evidence_access: current member still resolves (regression)
--   T14  resolve_evidence_access: non-member is reported as evidence_not_found
--   T15  audit: clients cannot insert; storage_key scrubbed on read
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Fixtures (run as postgres / owner; RLS is bypassed for the fixture writer)
-- ---------------------------------------------------------------------------

insert into auth.users (id, email, encrypted_password, email_confirmed_at, raw_app_meta_data, created_at, updated_at)
values
  ('80000000-0000-0000-0000-000000000001', 'h1.u1@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('80000000-0000-0000-0000-000000000002', 'h1.u2@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('80000000-0000-0000-0000-000000000003', 'h1.u3@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('80000000-0000-0000-0000-000000000004', 'h1.u4@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('80000000-0000-0000-0000-000000000005', 'h1.u5@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('80000000-0000-0000-0000-000000000006', 'h1.u6@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now());

-- u1 lead, u2 investigator, u3 stale member, u4 stale creator, u5 beta lead,
-- u6 outsider (no org, no case).
insert into public.profiles (id, full_name, role)
values
  ('80000000-0000-0000-0000-000000000001', 'H1 Lead Alpha',        'officer'),
  ('80000000-0000-0000-0000-000000000002', 'H1 Investigator Alpha', 'officer'),
  ('80000000-0000-0000-0000-000000000003', 'H1 Stale Member',      'officer'),
  ('80000000-0000-0000-0000-000000000004', 'H1 Stale Creator',     'officer'),
  ('80000000-0000-0000-0000-000000000005', 'H1 Lead Beta',         'officer'),
  ('80000000-0000-0000-0000-000000000006', 'H1 Outsider',          'officer')
on conflict (id) do nothing;

insert into public.organizations (id, name, slug, created_by)
values
  ('aa000000-0000-0000-0000-0000000000a0', 'H1 Org Alpha', 'h1-org-alpha', '80000000-0000-0000-0000-000000000001'),
  ('ab000000-0000-0000-0000-0000000000b0', 'H1 Org Beta',  'h1-org-beta',  '80000000-0000-0000-0000-000000000005');

-- Organization memberships: u1/u2 in alpha, u5 in beta. u3 (stale member) and
-- u4 (stale creator) are inserted then REMOVED — their case_members rows
-- survive on purpose to model a revoked user whose case row was never cleaned.
insert into public.organization_members (org_id, profile_id, role_in_org, added_by)
values
  ('aa000000-0000-0000-0000-0000000000a0', '80000000-0000-0000-0000-000000000001', 'member',       '80000000-0000-0000-0000-000000000001'),
  ('aa000000-0000-0000-0000-0000000000a0', '80000000-0000-0000-0000-000000000002', 'investigator', '80000000-0000-0000-0000-000000000001'),
  ('aa000000-0000-0000-0000-0000000000a0', '80000000-0000-0000-0000-000000000003', 'member',       '80000000-0000-0000-0000-000000000001'),
  ('aa000000-0000-0000-0000-0000000000a0', '80000000-0000-0000-0000-000000000004', 'member',       '80000000-0000-0000-0000-000000000001'),
  ('ab000000-0000-0000-0000-0000000000b0', '80000000-0000-0000-0000-000000000005', 'member',       '80000000-0000-0000-0000-000000000005');

delete from public.organization_members
where profile_id in (
    '80000000-0000-0000-0000-000000000003',
    '80000000-0000-0000-0000-000000000004'
);

-- Cases. C_open is created by the now-org-less u4 (stale creator).
insert into public.cases (id, org_id, case_number, title, description, status, created_by)
values
  ('81000000-0000-0000-0000-0000000000a0', 'aa000000-0000-0000-0000-0000000000a0', 'H1-CASE-OPEN',     'H1 open case',     null, 'active',   '80000000-0000-0000-0000-000000000004'),
  ('81000000-0000-0000-0000-0000000000b0', 'aa000000-0000-0000-0000-0000000000a0', 'H1-CASE-CLOSED',   'H1 closed case',   null, 'closed',   '80000000-0000-0000-0000-000000000001'),
  ('81000000-0000-0000-0000-0000000000b1', 'aa000000-0000-0000-0000-0000000000a0', 'H1-CASE-ARCHIVED', 'H1 archived case', null, 'archived', '80000000-0000-0000-0000-000000000001'),
  ('81000000-0000-0000-0000-0000000000c0', 'ab000000-0000-0000-0000-0000000000b0', 'H1-CASE-BETA',     'H1 beta case',     null, 'active',   '80000000-0000-0000-0000-000000000005');

-- Case members. u3 and u4 hold lead rows on C_open with NO current org
-- membership (stale). u6 holds nothing anywhere.
insert into public.case_members (case_id, profile_id, role_in_case, added_by)
values
  ('81000000-0000-0000-0000-0000000000a0', '80000000-0000-0000-0000-000000000001', 'lead',         '80000000-0000-0000-0000-000000000001'),
  ('81000000-0000-0000-0000-0000000000a0', '80000000-0000-0000-0000-000000000002', 'investigator', '80000000-0000-0000-0000-000000000001'),
  ('81000000-0000-0000-0000-0000000000a0', '80000000-0000-0000-0000-000000000003', 'lead',         '80000000-0000-0000-0000-000000000001'),
  ('81000000-0000-0000-0000-0000000000a0', '80000000-0000-0000-0000-000000000004', 'lead',         '80000000-0000-0000-0000-000000000004'),
  ('81000000-0000-0000-0000-0000000000b0', '80000000-0000-0000-0000-000000000001', 'lead',         '80000000-0000-0000-0000-000000000001'),
  ('81000000-0000-0000-0000-0000000000b0', '80000000-0000-0000-0000-000000000002', 'investigator', '80000000-0000-0000-0000-000000000001'),
  ('81000000-0000-0000-0000-0000000000b1', '80000000-0000-0000-0000-000000000001', 'lead',         '80000000-0000-0000-0000-000000000001'),
  ('81000000-0000-0000-0000-0000000000b1', '80000000-0000-0000-0000-000000000002', 'investigator', '80000000-0000-0000-0000-000000000001'),
  ('81000000-0000-0000-0000-0000000000c0', '80000000-0000-0000-0000-000000000005', 'lead',         '80000000-0000-0000-0000-000000000005');

insert into public.evidence (id, case_id, evidence_number, title, description, type, status, created_by)
values
  ('82000000-0000-0000-0000-0000000000a0', '81000000-0000-0000-0000-0000000000a0', 'H1-EV-OPEN1',    'H1 open evidence 1',    null, 'document', 'received', '80000000-0000-0000-0000-000000000001'),
  ('82000000-0000-0000-0000-0000000000a1', '81000000-0000-0000-0000-0000000000a0', 'H1-EV-OPEN2',    'H1 open evidence 2',    null, 'document', 'received', '80000000-0000-0000-0000-000000000001'),
  ('82000000-0000-0000-0000-0000000000b0', '81000000-0000-0000-0000-0000000000b0', 'H1-EV-CLOSED',   'H1 closed evidence',    null, 'document', 'received', '80000000-0000-0000-0000-000000000001'),
  ('82000000-0000-0000-0000-0000000000b1', '81000000-0000-0000-0000-0000000000b1', 'H1-EV-ARCHIVED', 'H1 archived evidence',  null, 'document', 'received', '80000000-0000-0000-0000-000000000001'),
  ('82000000-0000-0000-0000-0000000000c0', '81000000-0000-0000-0000-0000000000c0', 'H1-EV-BETA',     'H1 beta evidence',      null, 'document', 'received', '80000000-0000-0000-0000-000000000005');

-- Document versions. V_crosscase is the SECOND version of E_open2 (C_open) but
-- its storage key claims C_closed (v2 avoids a unique (evidence_id, version)
-- collision) — the cross-case forgery fixture.
insert into public.document_versions (id, evidence_id, version, prev_version_id, file_name, mime_type, file_size_bytes, sha256, storage_key, uploaded_by, notes)
values
  ('83000000-0000-0000-0000-0000000000a0', '82000000-0000-0000-0000-0000000000a0', 1, null, 'open1.pdf',     'application/pdf', 10, repeat('a', 64), '81000000-0000-0000-0000-0000000000a0/82000000-0000-0000-0000-0000000000a0/83000000-0000-0000-0000-0000000000a0', '80000000-0000-0000-0000-000000000001', null),
  ('83000000-0000-0000-0000-0000000000a1', '82000000-0000-0000-0000-0000000000a1', 1, null, 'open2.pdf',     'application/pdf', 11, repeat('b', 64), '81000000-0000-0000-0000-0000000000a0/82000000-0000-0000-0000-0000000000a1/83000000-0000-0000-0000-0000000000a1', '80000000-0000-0000-0000-000000000001', null),
  ('83000000-0000-0000-0000-0000000000b0', '82000000-0000-0000-0000-0000000000b0', 1, null, 'closed.pdf',    'application/pdf', 12, repeat('c', 64), '81000000-0000-0000-0000-0000000000b0/82000000-0000-0000-0000-0000000000b0/83000000-0000-0000-0000-0000000000b0', '80000000-0000-0000-0000-000000000001', null),
  ('83000000-0000-0000-0000-0000000000b1', '82000000-0000-0000-0000-0000000000b1', 1, null, 'archived.pdf',  'application/pdf', 13, repeat('d', 64), '81000000-0000-0000-0000-0000000000b1/82000000-0000-0000-0000-0000000000b1/83000000-0000-0000-0000-0000000000b1', '80000000-0000-0000-0000-000000000001', null),
  ('83000000-0000-0000-0000-0000000000c0', '82000000-0000-0000-0000-0000000000c0', 1, null, 'beta.pdf',      'application/pdf', 14, repeat('e', 64), '81000000-0000-0000-0000-0000000000c0/82000000-0000-0000-0000-0000000000c0/83000000-0000-0000-0000-0000000000c0', '80000000-0000-0000-0000-000000000005', null),
  ('83000000-0000-0000-0000-0000000000d0', '82000000-0000-0000-0000-0000000000a1', 2, null, 'crosscase.pdf', 'application/pdf', 15, repeat('f', 64), '81000000-0000-0000-0000-0000000000b0/82000000-0000-0000-0000-0000000000a1/83000000-0000-0000-0000-0000000000d0', '80000000-0000-0000-0000-000000000001', null);

-- Storage objects mirroring the versions (K9 has a row but NO version).
insert into storage.objects (id, bucket_id, name, metadata)
values
  ('84000000-0000-0000-0000-0000000000a0', 'evidence-files', '81000000-0000-0000-0000-0000000000a0/82000000-0000-0000-0000-0000000000a0/83000000-0000-0000-0000-0000000000a0', '{}'),
  ('84000000-0000-0000-0000-0000000000a1', 'evidence-files', '81000000-0000-0000-0000-0000000000a0/82000000-0000-0000-0000-0000000000a1/83000000-0000-0000-0000-0000000000a1', '{}'),
  ('84000000-0000-0000-0000-0000000000b0', 'evidence-files', '81000000-0000-0000-0000-0000000000b0/82000000-0000-0000-0000-0000000000b0/83000000-0000-0000-0000-0000000000b0', '{}'),
  ('84000000-0000-0000-0000-0000000000b1', 'evidence-files', '81000000-0000-0000-0000-0000000000b1/82000000-0000-0000-0000-0000000000b1/83000000-0000-0000-0000-0000000000b1', '{}'),
  ('84000000-0000-0000-0000-0000000000c0', 'evidence-files', '81000000-0000-0000-0000-0000000000c0/82000000-0000-0000-0000-0000000000c0/83000000-0000-0000-0000-0000000000c0', '{}'),
  ('84000000-0000-0000-0000-0000000000d0', 'evidence-files', '81000000-0000-0000-0000-0000000000b0/82000000-0000-0000-0000-0000000000a1/83000000-0000-0000-0000-0000000000d0', '{}'),
  ('84000000-0000-0000-0000-0000000000e9', 'evidence-files', '81000000-0000-0000-0000-0000000000a0/82000000-0000-0000-0000-0000000000ee/83000000-0000-0000-0000-0000000000ee', '{}');

-- =============================================================================
-- T1 — lead: direct storage DELETE of an open-case object is denied
-- =============================================================================
set local role authenticated;
set local request.jwt.claims = '{"sub":"80000000-0000-0000-0000-000000000001","role":"authenticated"}';

do $$
declare
    v_persists int;
begin
    begin
        delete from storage.objects
        where bucket_id = 'evidence-files'
          and name = '81000000-0000-0000-0000-0000000000a0/82000000-0000-0000-0000-0000000000a0/83000000-0000-0000-0000-0000000000a0';
    exception when others then
        null;
    end;

    set local role postgres;
    select count(*) into v_persists from storage.objects
    where name = '81000000-0000-0000-0000-0000000000a0/82000000-0000-0000-0000-0000000000a0/83000000-0000-0000-0000-0000000000a0';
    set local role authenticated;

    if v_persists <> 1 then
        raise exception 'FAIL T1: lead deleted an open-case object directly';
    end if;
end $$;

-- =============================================================================
-- T2 — investigator: direct storage DELETE of an open-case object is denied
-- =============================================================================
set local request.jwt.claims = '{"sub":"80000000-0000-0000-0000-000000000002","role":"authenticated"}';

do $$
declare
    v_persists int;
begin
    begin
        delete from storage.objects
        where bucket_id = 'evidence-files'
          and name = '81000000-0000-0000-0000-0000000000a0/82000000-0000-0000-0000-0000000000a1/83000000-0000-0000-0000-0000000000a1';
    exception when others then
        null;
    end;

    set local role postgres;
    select count(*) into v_persists from storage.objects
    where name = '81000000-0000-0000-0000-0000000000a0/82000000-0000-0000-0000-0000000000a1/83000000-0000-0000-0000-0000000000a1';
    set local role authenticated;

    if v_persists <> 1 then
        raise exception 'FAIL T2: investigator deleted an open-case object directly';
    end if;
end $$;

-- =============================================================================
-- T3 — stale org member / stale creator: direct DELETE denied; RPC denied
-- =============================================================================
set local request.jwt.claims = '{"sub":"80000000-0000-0000-0000-000000000003","role":"authenticated"}';

do $$
declare
    v_persists int;
    v_executed boolean := false;
    v_unexpected text;
begin
    -- direct deletion must not remove the object
    begin
        delete from storage.objects
        where bucket_id = 'evidence-files'
          and name = '81000000-0000-0000-0000-0000000000a0/82000000-0000-0000-0000-0000000000a0/83000000-0000-0000-0000-0000000000a0';
    exception when others then
        null;
    end;

    -- RPC must reject a revoked member even though a case_members lead row survives
    begin
        perform public.delete_evidence_object(
            '81000000-0000-0000-0000-0000000000a0/82000000-0000-0000-0000-0000000000a0/83000000-0000-0000-0000-0000000000a0'
        );
        v_executed := true;
    exception when others then
        if sqlerrm <> 'not_org_member' then
            v_unexpected := sqlerrm;
        end if;
    end;

    set local role postgres;
    select count(*) into v_persists from storage.objects
    where name = '81000000-0000-0000-0000-0000000000a0/82000000-0000-0000-0000-0000000000a0/83000000-0000-0000-0000-0000000000a0';
    set local role authenticated;

    if v_persists <> 1 then
        raise exception 'FAIL T3: stale member deleted an object';
    end if;
    if v_executed then
        raise exception 'FAIL T3: delete_evidence_object allowed a stale org member';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL T3: expected not_org_member, got: %', v_unexpected;
    end if;
end $$;

-- stale creator (org membership revoked, created C_open, lead row survives)
set local request.jwt.claims = '{"sub":"80000000-0000-0000-0000-000000000004","role":"authenticated"}';

do $$
declare
    v_executed boolean := false;
    v_unexpected text;
begin
    begin
        perform public.delete_evidence_object(
            '81000000-0000-0000-0000-0000000000a0/82000000-0000-0000-0000-0000000000a1/83000000-0000-0000-0000-0000000000a1'
        );
        v_executed := true;
    exception when others then
        if sqlerrm <> 'not_org_member' then
            v_unexpected := sqlerrm;
        end if;
    end;

    if v_executed then
        raise exception 'FAIL T3b: delete_evidence_object allowed a stale creator';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL T3b: expected not_org_member, got: %', v_unexpected;
    end if;
end $$;

-- =============================================================================
-- T4 — stale creator/member: resolve_evidence_access -> evidence_not_found
-- =============================================================================
set local request.jwt.claims = '{"sub":"80000000-0000-0000-0000-000000000004","role":"authenticated"}';

do $$
declare
    v_executed boolean := false;
    v_unexpected text;
begin
    begin
        perform public.resolve_evidence_access(
            '82000000-0000-0000-0000-0000000000a0', null, 'download'
        );
        v_executed := true;
    exception when others then
        if sqlerrm <> 'evidence_not_found' then
            v_unexpected := sqlerrm;
        end if;
    end;

    if v_executed then
        raise exception 'FAIL T4: stale creator resolved evidence via creator branch';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL T4: expected evidence_not_found, got: %', v_unexpected;
    end if;
end $$;

set local request.jwt.claims = '{"sub":"80000000-0000-0000-0000-000000000003","role":"authenticated"}';

do $$
declare
    v_executed boolean := false;
    v_unexpected text;
begin
    begin
        perform public.resolve_evidence_access(
            '82000000-0000-0000-0000-0000000000a1', null, 'preview'
        );
        v_executed := true;
    exception when others then
        if sqlerrm <> 'evidence_not_found' then
            v_unexpected := sqlerrm;
        end if;
    end;

    if v_executed then
        raise exception 'FAIL T4b: stale member resolved evidence';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL T4b: expected evidence_not_found, got: %', v_unexpected;
    end if;
end $$;

-- =============================================================================
-- T5 — lead: closed-case object delete denied (direct + RPC)
-- =============================================================================
set local request.jwt.claims = '{"sub":"80000000-0000-0000-0000-000000000001","role":"authenticated"}';

do $$
declare
    v_persists int;
    v_executed boolean := false;
    v_unexpected text;
begin
    begin
        delete from storage.objects
        where bucket_id = 'evidence-files'
          and name = '81000000-0000-0000-0000-0000000000b0/82000000-0000-0000-0000-0000000000b0/83000000-0000-0000-0000-0000000000b0';
    exception when others then
        null;
    end;

    begin
        perform public.delete_evidence_object(
            '81000000-0000-0000-0000-0000000000b0/82000000-0000-0000-0000-0000000000b0/83000000-0000-0000-0000-0000000000b0'
        );
        v_executed := true;
    exception when others then
        if sqlerrm <> 'case_not_open' then
            v_unexpected := sqlerrm;
        end if;
    end;

    set local role postgres;
    select count(*) into v_persists from storage.objects
    where name = '81000000-0000-0000-0000-0000000000b0/82000000-0000-0000-0000-0000000000b0/83000000-0000-0000-0000-0000000000b0';
    set local role authenticated;

    if v_persists <> 1 then
        raise exception 'FAIL T5: closed-case object was deleted';
    end if;
    if v_executed then
        raise exception 'FAIL T5: delete_evidence_object allowed a closed case';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL T5: expected case_not_open, got: %', v_unexpected;
    end if;
end $$;

-- =============================================================================
-- T6 — lead: archived-case object delete denied (direct + RPC)
-- =============================================================================
do $$
declare
    v_persists int;
    v_executed boolean := false;
    v_unexpected text;
begin
    begin
        delete from storage.objects
        where bucket_id = 'evidence-files'
          and name = '81000000-0000-0000-0000-0000000000b1/82000000-0000-0000-0000-0000000000b1/83000000-0000-0000-0000-0000000000b1';
    exception when others then
        null;
    end;

    begin
        perform public.delete_evidence_object(
            '81000000-0000-0000-0000-0000000000b1/82000000-0000-0000-0000-0000000000b1/83000000-0000-0000-0000-0000000000b1'
        );
        v_executed := true;
    exception when others then
        if sqlerrm <> 'case_not_open' then
            v_unexpected := sqlerrm;
        end if;
    end;

    set local role postgres;
    select count(*) into v_persists from storage.objects
    where name = '81000000-0000-0000-0000-0000000000b1/82000000-0000-0000-0000-0000000000b1/83000000-0000-0000-0000-0000000000b1';
    set local role authenticated;

    if v_persists <> 1 then
        raise exception 'FAIL T6: archived-case object was deleted';
    end if;
    if v_executed then
        raise exception 'FAIL T6: delete_evidence_object allowed an archived case';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL T6: expected case_not_open, got: %', v_unexpected;
    end if;
end $$;

-- =============================================================================
-- T7 — investigator: closed-case object delete denied (direct + RPC)
-- =============================================================================
set local request.jwt.claims = '{"sub":"80000000-0000-0000-0000-000000000002","role":"authenticated"}';

do $$
declare
    v_persists int;
    v_executed boolean := false;
    v_unexpected text;
begin
    begin
        delete from storage.objects
        where bucket_id = 'evidence-files'
          and name = '81000000-0000-0000-0000-0000000000b0/82000000-0000-0000-0000-0000000000b0/83000000-0000-0000-0000-0000000000b0';
    exception when others then
        null;
    end;

    begin
        perform public.delete_evidence_object(
            '81000000-0000-0000-0000-0000000000b0/82000000-0000-0000-0000-0000000000b0/83000000-0000-0000-0000-0000000000b0'
        );
        v_executed := true;
    exception when others then
        if sqlerrm <> 'case_not_open' then
            v_unexpected := sqlerrm;
        end if;
    end;

    set local role postgres;
    select count(*) into v_persists from storage.objects
    where name = '81000000-0000-0000-0000-0000000000b0/82000000-0000-0000-0000-0000000000b0/83000000-0000-0000-0000-0000000000b0';
    set local role authenticated;

    if v_persists <> 1 then
        raise exception 'FAIL T7: investigator deleted a closed-case object';
    end if;
    if v_executed then
        raise exception 'FAIL T7: delete_evidence_object allowed a closed case (investigator)';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL T7: expected case_not_open, got: %', v_unexpected;
    end if;
end $$;

-- =============================================================================
-- T8 — investigator: archived-case object delete denied (direct + RPC)
-- =============================================================================
do $$
declare
    v_persists int;
    v_executed boolean := false;
    v_unexpected text;
begin
    begin
        delete from storage.objects
        where bucket_id = 'evidence-files'
          and name = '81000000-0000-0000-0000-0000000000b1/82000000-0000-0000-0000-0000000000b1/83000000-0000-0000-0000-0000000000b1';
    exception when others then
        null;
    end;

    begin
        perform public.delete_evidence_object(
            '81000000-0000-0000-0000-0000000000b1/82000000-0000-0000-0000-0000000000b1/83000000-0000-0000-0000-0000000000b1'
        );
        v_executed := true;
    exception when others then
        if sqlerrm <> 'case_not_open' then
            v_unexpected := sqlerrm;
        end if;
    end;

    set local role postgres;
    select count(*) into v_persists from storage.objects
    where name = '81000000-0000-0000-0000-0000000000b1/82000000-0000-0000-0000-0000000000b1/83000000-0000-0000-0000-0000000000b1';
    set local role authenticated;

    if v_persists <> 1 then
        raise exception 'FAIL T8: investigator deleted an archived-case object';
    end if;
    if v_executed then
        raise exception 'FAIL T8: delete_evidence_object allowed an archived case (investigator)';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL T8: expected case_not_open, got: %', v_unexpected;
    end if;
end $$;

-- =============================================================================
-- T9 — RPC: key with no document_versions row is rejected
-- =============================================================================
set local request.jwt.claims = '{"sub":"80000000-0000-0000-0000-000000000001","role":"authenticated"}';

do $$
declare
    v_persists int;
    v_executed boolean := false;
    v_unexpected text;
begin
    begin
        perform public.delete_evidence_object(
            '81000000-0000-0000-0000-0000000000a0/82000000-0000-0000-0000-0000000000ee/83000000-0000-0000-0000-0000000000ee'
        );
        v_executed := true;
    exception when others then
        if sqlerrm <> 'object_not_found_in_document_versions' then
            v_unexpected := sqlerrm;
        end if;
    end;

    set local role postgres;
    select count(*) into v_persists from storage.objects
    where name = '81000000-0000-0000-0000-0000000000a0/82000000-0000-0000-0000-0000000000ee/83000000-0000-0000-0000-0000000000ee';
    set local role authenticated;

    if v_persists <> 1 then
        raise exception 'FAIL T9: orphan object was deleted';
    end if;
    if v_executed then
        raise exception 'FAIL T9: delete_evidence_object deleted an object no version claims';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL T9: expected object_not_found_in_document_versions, got: %', v_unexpected;
    end if;
end $$;

-- =============================================================================
-- T10 — RPC: cross-case key is rejected (storage_key_case_mismatch)
-- =============================================================================
do $$
declare
    v_persists int;
    v_executed boolean := false;
    v_unexpected text;
begin
    begin
        perform public.delete_evidence_object(
            '81000000-0000-0000-0000-0000000000b0/82000000-0000-0000-0000-0000000000a1/83000000-0000-0000-0000-0000000000d0'
        );
        v_executed := true;
    exception when others then
        if sqlerrm <> 'storage_key_case_mismatch' then
            v_unexpected := sqlerrm;
        end if;
    end;

    set local role postgres;
    select count(*) into v_persists from storage.objects
    where name = '81000000-0000-0000-0000-0000000000b0/82000000-0000-0000-0000-0000000000a1/83000000-0000-0000-0000-0000000000d0';
    set local role authenticated;

    if v_persists <> 1 then
        raise exception 'FAIL T10: cross-case key was deleted';
    end if;
    if v_executed then
        raise exception 'FAIL T10: delete_evidence_object accepted a cross-case key';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL T10: expected storage_key_case_mismatch, got: %', v_unexpected;
    end if;
end $$;

-- =============================================================================
-- T11 — RPC: cross-org key is rejected (not_org_member)
-- =============================================================================
do $$
declare
    v_persists int;
    v_executed boolean := false;
    v_unexpected text;
begin
    begin
        perform public.delete_evidence_object(
            '81000000-0000-0000-0000-0000000000c0/82000000-0000-0000-0000-0000000000c0/83000000-0000-0000-0000-0000000000c0'
        );
        v_executed := true;
    exception when others then
        if sqlerrm <> 'not_org_member' then
            v_unexpected := sqlerrm;
        end if;
    end;

    set local role postgres;
    select count(*) into v_persists from storage.objects
    where name = '81000000-0000-0000-0000-0000000000c0/82000000-0000-0000-0000-0000000000c0/83000000-0000-0000-0000-0000000000c0';
    set local role authenticated;

    if v_persists <> 1 then
        raise exception 'FAIL T11: cross-org key was deleted';
    end if;
    if v_executed then
        raise exception 'FAIL T11: delete_evidence_object accepted a cross-org key';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL T11: expected not_org_member, got: %', v_unexpected;
    end if;
end $$;

-- =============================================================================
-- T12 — RPC: authorized cleanup of an open-case object succeeds + audits
-- =============================================================================
do $$
declare
    v_deleted    jsonb;
    v_objects    int;
    v_versions   int;
    v_audit      int;
    v_custody    int;
begin
    v_deleted := public.delete_evidence_object(
        '81000000-0000-0000-0000-0000000000a0/82000000-0000-0000-0000-0000000000a0/83000000-0000-0000-0000-0000000000a0'
    );

    set local role postgres;
    select count(*) into v_objects from storage.objects
    where name = '81000000-0000-0000-0000-0000000000a0/82000000-0000-0000-0000-0000000000a0/83000000-0000-0000-0000-0000000000a0';
    select count(*) into v_versions from public.document_versions
    where id = '83000000-0000-0000-0000-0000000000a0';
    select count(*) into v_audit from public.audit_logs
    where action = 'evidence.object_deleted'
      and entity_id = '83000000-0000-0000-0000-0000000000a0'
      and actor_id = '80000000-0000-0000-0000-000000000001';
    set local role authenticated;

    if (v_deleted ->> 'deleted') <> 'true' then
        raise exception 'FAIL T12: authorized cleanup did not report success: %', v_deleted;
    end if;
    if v_objects <> 0 then
        raise exception 'FAIL T12: object row still present after authorized cleanup';
    end if;
    if v_versions <> 1 then
        raise exception 'FAIL T12: document_versions row was deleted (must be preserved)';
    end if;
    if v_audit <> 1 then
        raise exception 'FAIL T12: evidence.object_deleted audit row missing (got %)', v_audit;
    end if;
end $$;

-- cleanup works in another org for its own open case (u5, org beta)
set local request.jwt.claims = '{"sub":"80000000-0000-0000-0000-000000000005","role":"authenticated"}';

do $$
declare
    v_deleted  jsonb;
    v_objects  int;
begin
    v_deleted := public.delete_evidence_object(
        '81000000-0000-0000-0000-0000000000c0/82000000-0000-0000-0000-0000000000c0/83000000-0000-0000-0000-0000000000c0'
    );

    set local role postgres;
    select count(*) into v_objects from storage.objects
    where name = '81000000-0000-0000-0000-0000000000c0/82000000-0000-0000-0000-0000000000c0/83000000-0000-0000-0000-0000000000c0';
    set local role authenticated;

    if (v_deleted ->> 'deleted') <> 'true' or v_objects <> 0 then
        raise exception 'FAIL T12b: authorized beta cleanup failed: % / objects=%', v_deleted, v_objects;
    end if;
end $$;

-- =============================================================================
-- T13 — resolve_evidence_access: current member still resolves (regression)
-- =============================================================================
set local request.jwt.claims = '{"sub":"80000000-0000-0000-0000-000000000001","role":"authenticated"}';

do $$
declare
    v_resolved jsonb;
begin
    v_resolved := public.resolve_evidence_access(
        '82000000-0000-0000-0000-0000000000a0',
        '83000000-0000-0000-0000-0000000000a0',
        'download'
    );

    if v_resolved ->> 'storage_key' <>
        '81000000-0000-0000-0000-0000000000a0/82000000-0000-0000-0000-0000000000a0/83000000-0000-0000-0000-0000000000a0' then
        raise exception 'FAIL T13: current member could not resolve their evidence: %', v_resolved;
    end if;
end $$;

-- =============================================================================
-- T14 — resolve_evidence_access: non-member reported as evidence_not_found
-- =============================================================================
set local request.jwt.claims = '{"sub":"80000000-0000-0000-0000-000000000006","role":"authenticated"}';

do $$
declare
    v_executed boolean := false;
    v_unexpected text;
begin
    begin
        perform public.resolve_evidence_access(
            '82000000-0000-0000-0000-0000000000a0', null, 'download'
        );
        v_executed := true;
    exception when others then
        if sqlerrm <> 'evidence_not_found' then
            v_unexpected := sqlerrm;
        end if;
    end;

    if v_executed then
        raise exception 'FAIL T14: outsider resolved evidence';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL T14: expected evidence_not_found, got: %', v_unexpected;
    end if;

    -- and the outsider cannot read the case audit trail either
    v_executed := false;
    v_unexpected := null;
    begin
        perform * from public.list_case_audit_events('81000000-0000-0000-0000-0000000000a0');
        v_executed := true;
    exception when others then
        if sqlerrm <> 'case_not_found' then
            v_unexpected := sqlerrm;
        end if;
    end;

    if v_executed then
        raise exception 'FAIL T14b: outsider read the case audit trail';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL T14b: expected case_not_found, got: %', v_unexpected;
    end if;
end $$;

-- =============================================================================
-- T15 — audit: clients cannot insert; storage_key scrubbed on read
-- =============================================================================
set local request.jwt.claims = '{"sub":"80000000-0000-0000-0000-000000000001","role":"authenticated"}';

do $$
declare
    v_executed boolean := false;
    v_unexpected text;
begin
    -- (a) a client must not be able to forge an audit row
    begin
        insert into public.audit_logs (actor_id, action, entity_type, entity_id, meta)
        values (
            '80000000-0000-0000-0000-000000000001',
            'evidence.object_deleted',
            'document_version',
            '83000000-0000-0000-0000-0000000000a0',
            '{"forged": true}'::jsonb
        );
        v_executed := true;
    exception when others then
        null;
    end;

    if v_executed then
        raise exception 'FAIL T15: client inserted an audit_logs row directly';
    end if;
end $$;

do $$
declare
    v_meta    jsonb;
    v_raw     text;
    v_action  text;
begin
    -- (b) read path scrubs storage_key ...
    select a.meta, a.action into v_meta, v_action
    from public.list_case_audit_events('81000000-0000-0000-0000-0000000000a0') a
    where a.action = 'evidence.object_deleted';

    if v_action is null then
        raise exception 'FAIL T15: evidence.object_deleted not visible on the read path';
    end if;
    if v_meta ? 'storage_key' then
        raise exception 'FAIL T15: storage_key leaked through list_case_audit_events';
    end if;
    if v_meta ->> 'file_name' <> 'open1.pdf' then
        raise exception 'FAIL T15: expected display metadata missing from scrubbed meta: %', v_meta;
    end if;

    -- (c) the raw table still holds the key (scrub is a read-time concern only)
    set local role postgres;
    select a.meta ->> 'storage_key' into v_raw
    from public.audit_logs a
    where a.action = 'evidence.object_deleted'
      and a.entity_id = '83000000-0000-0000-0000-0000000000a0';
    set local role authenticated;

    if v_raw <>
        '81000000-0000-0000-0000-0000000000a0/82000000-0000-0000-0000-0000000000a0/83000000-0000-0000-0000-0000000000a0' then
        raise exception 'FAIL T15: raw audit meta lost storage_key: %', v_raw;
    end if;
end $$;

-- If we reach here, every H1 storage-delete hardening assertion passed.
select 'H1 storage delete hardening tests passed' as result;