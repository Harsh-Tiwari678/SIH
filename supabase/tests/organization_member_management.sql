-- =============================================================================
-- SIH26190 Secure Evidence — organization member management hardening tests
--
-- Verifies 20260917000000_organization_member_management_hardening.sql:
--
--   PART 1 — DANGEROUS GRANTS REVOKED. authenticated loses TRUNCATE on every
--     core table and INSERT/UPDATE/DELETE on all tables; only the RPC/SELECT
--     paths remain.
--   PART 2 — COLUMN-LEVEL UPDATE NARROWED. Only the documented safe columns
--     stay updatable: cases(title,description,status,closed_at,closed_by,
--     updated_at), evidence(title,description,type,updated_at), profiles(
--     full_name,badge_number,updated_at), organizations(name,slug,updated_at).
--     document_versions / audit_logs / blockchain_anchors / case_members /
--     organization_members / chain_of_custody have ZERO column UPDATE.
--   PARTS 3-6 — WRITE RCPS ORG-AWARE. update_case, update_evidence_status,
--     create_evidence, create_blockchain_anchor now require is_case_member
--     before the explicit-role check, so a stale case_members row (org
--     membership removed) grants no write; an org admin without an explicit
--     lead membership still cannot write.
--   PARTS 7-9 — READ RCPS. list_organization_members,
--     list_organization_audit_events, lookup_profiles_for_organization exist,
--     are org-scoped, and leak nothing across organizations.
--
-- Test inventory (T21..T30; continues after the org_case_security T1..T20):
--   T21  TRUNCATE revoked on all 10 tables
--   T22  INSERT / DELETE revoked; SELECT / REFERENCES / TRIGGER retained
--   T23  column-level UPDATE narrowed to the safe set
--   T24  direct DML attempts: evidence.status denied, cases provenance denied,
--        audit_logs INSERT denied, TRUNCATE denied; cases.title direct edit
--        still allowed for the lead (positive control)
--   T25  stale org member (u4 removed from org, stale case_members row) is
--        blocked by ALL four hardened write RPCs
--   T26  org admin WITHOUT explicit lead membership cannot write (any RPC)
--   T27  valid lead/investigator still works (update_case / evidence status /
--        create_evidence / create_blockchain_anchor positive controls)
--   T28  list_organization_members: org-scoped, member-roster correct,
--        cross-org denied (org_not_found), anon denied
--   T29  list_organization_audit_events: complete org trail (org + case +
--        evidence + member events), meta scrubbed of storage_key, cross-org
--        denied, anon denied
--   T30  lookup_profiles_for_organization: candidate search — existing members
--        excluded, no-org profile found by name + badge, other-org member
--        returnable, 10-result cap, minimal fields only, cross-org and
--        org-less callers denied, anon denied
--
-- HOW TO RUN (single transaction required — the script relies on `set local`):
--   supabase start          # needs Docker
--   supabase db reset       # apply all migrations on a fresh DB
--   psql "$SUPABASE_DB_URL" -1 -v ON_ERROR_STOP=1 \
--       -f supabase/tests/organization_member_management.sql
--
-- Every test either passes silently or aborts with a `FAIL T<n>` exception.
-- The script mutates only rows it creates itself; run against a throwaway DB.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Test users / fixture ids (deterministic, never collide with real data)
-- ---------------------------------------------------------------------------
-- u1  81000000-0000-0000-0000-000000000001  org-alpha admin (no explicit case role)
-- u2  81000000-0000-0000-0000-000000000002  org-alpha investigator, lead of C_A
-- u3  81000000-0000-0000-0000-000000000003  org-alpha investigator of C_A
-- u4  81000000-0000-0000-0000-000000000004  org-alpha member, investigator of C_A
--                                            (removed in T25 -> stale case_members)
-- u5  81000000-0000-0000-0000-000000000005  org-beta member (cross-org actor)
-- u6  81000000-0000-0000-0000-000000000006  candidate, no org membership (name search)
-- u7  81000000-0000-0000-0000-000000000007  candidate, no org membership (badge search)
-- u8  81000000-0000-0000-0000-000000000008  ORG-BETA member -> still a candidate for alpha
-- u09..u19  81000000-0000-0000-0000-0000000000xx  eleven candidates sharing "Limit Tester"
-- org_alpha 82000000-0000-0000-0000-0000000000A1
-- org_beta  82000000-0000-0000-0000-0000000000B1
-- C_A       83000000-0000-0000-0000-0000000000A1  (org-alpha)
-- EV_A      84000000-0000-0000-0000-0000000000A1  (case C_A)
-- V_A       85000000-0000-0000-0000-0000000000A1  (evidence EV_A)
-- EV_ADD    84000000-0000-0000-0000-0000000000A2  (created via RPC, T27)
-- V_ADD     85000000-0000-0000-0000-0000000000A2  (created via RPC, T27)

-- ---------------------------------------------------------------------------
-- Fixtures (run as postgres / owner; RLS is bypassed for the fixture writer)
-- ---------------------------------------------------------------------------

insert into auth.users (id, email, encrypted_password, email_confirmed_at, raw_app_meta_data, created_at, updated_at)
values
  ('81000000-0000-0000-0000-000000000001', 'om.u1@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('81000000-0000-0000-0000-000000000002', 'om.u2@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('81000000-0000-0000-0000-000000000003', 'om.u3@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('81000000-0000-0000-0000-000000000004', 'om.u4@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('81000000-0000-0000-0000-000000000005', 'om.u5@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('81000000-0000-0000-0000-000000000006', 'om.u6@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('81000000-0000-0000-0000-000000000007', 'om.u7@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('81000000-0000-0000-0000-000000000008', 'om.u8@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('81000000-0000-0000-0000-000000000009', 'om.u09@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('81000000-0000-0000-0000-00000000000A', 'om.u10@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('81000000-0000-0000-0000-00000000000B', 'om.u11@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('81000000-0000-0000-0000-00000000000C', 'om.u12@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('81000000-0000-0000-0000-00000000000D', 'om.u13@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('81000000-0000-0000-0000-00000000000E', 'om.u14@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('81000000-0000-0000-0000-00000000000F', 'om.u15@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('81000000-0000-0000-0000-000000000010', 'om.u16@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('81000000-0000-0000-0000-000000000011', 'om.u17@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('81000000-0000-0000-0000-000000000012', 'om.u18@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('81000000-0000-0000-0000-000000000013', 'om.u19@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now());

-- handle_new_user (bootstrap trigger) auto-creates profiles from each
-- auth.users row as 'New Officer'; upsert so the fixture identity is exact.
insert into public.profiles (id, full_name, badge_number, role)
values
  ('81000000-0000-0000-0000-000000000001', 'Member Admin Alpha',      null,           'officer'),
  ('81000000-0000-0000-0000-000000000002', 'Member Lead Alpha',       'INV-ALPHA-02', 'officer'),
  ('81000000-0000-0000-0000-000000000003', 'Member Investigator A',   null,           'officer'),
  ('81000000-0000-0000-0000-000000000004', 'Member Investigator B',   null,           'officer'),
  ('81000000-0000-0000-0000-000000000005', 'Member Beta',             null,           'officer'),
  ('81000000-0000-0000-0000-000000000006', 'Candidate Searchable',    null,           'officer'),
  ('81000000-0000-0000-0000-000000000007', 'Another Candidate',       'CAND-0007',    'officer'),
  ('81000000-0000-0000-0000-000000000008', 'Beta Candidate',          null,           'officer'),
  ('81000000-0000-0000-0000-000000000009', 'Limit Tester 01',         null,           'officer'),
  ('81000000-0000-0000-0000-00000000000A', 'Limit Tester 02',         null,           'officer'),
  ('81000000-0000-0000-0000-00000000000B', 'Limit Tester 03',         null,           'officer'),
  ('81000000-0000-0000-0000-00000000000C', 'Limit Tester 04',         null,           'officer'),
  ('81000000-0000-0000-0000-00000000000D', 'Limit Tester 05',         null,           'officer'),
  ('81000000-0000-0000-0000-00000000000E', 'Limit Tester 06',         null,           'officer'),
  ('81000000-0000-0000-0000-00000000000F', 'Limit Tester 07',         null,           'officer'),
  ('81000000-0000-0000-0000-000000000010', 'Limit Tester 08',         null,           'officer'),
  ('81000000-0000-0000-0000-000000000011', 'Limit Tester 09',         null,           'officer'),
  ('81000000-0000-0000-0000-000000000012', 'Limit Tester 10',         null,           'officer'),
  ('81000000-0000-0000-0000-000000000013', 'Limit Tester 11',         null,           'officer')
on conflict (id) do update
    set full_name    = excluded.full_name,
        badge_number = excluded.badge_number,
        role         = excluded.role;

insert into public.organizations (id, name, slug, created_by)
values
  ('82000000-0000-0000-0000-0000000000A1', 'Org Alpha', 'om-alpha', '81000000-0000-0000-0000-000000000001'),
  ('82000000-0000-0000-0000-0000000000B1', 'Org Beta',  'om-beta',  '81000000-0000-0000-0000-000000000005');

insert into public.organization_members (org_id, profile_id, role_in_org, added_by)
values
  ('82000000-0000-0000-0000-0000000000A1', '81000000-0000-0000-0000-000000000001', 'admin',        '81000000-0000-0000-0000-000000000001'),
  ('82000000-0000-0000-0000-0000000000A1', '81000000-0000-0000-0000-000000000002', 'investigator', '81000000-0000-0000-0000-000000000001'),
  ('82000000-0000-0000-0000-0000000000A1', '81000000-0000-0000-0000-000000000003', 'investigator', '81000000-0000-0000-0000-000000000001'),
  ('82000000-0000-0000-0000-0000000000A1', '81000000-0000-0000-0000-000000000004', 'member',       '81000000-0000-0000-0000-000000000001'),
  ('82000000-0000-0000-0000-0000000000B1', '81000000-0000-0000-0000-000000000005', 'member',       '81000000-0000-0000-0000-000000000005'),
  ('82000000-0000-0000-0000-0000000000B1', '81000000-0000-0000-0000-000000000008', 'member',       '81000000-0000-0000-0000-000000000005');

insert into public.cases (id, org_id, case_number, title, description, status, created_by)
values
  ('83000000-0000-0000-0000-0000000000A1', '82000000-0000-0000-0000-0000000000A1', 'OM-CASE-A1', 'Org member management case', null, 'active', '81000000-0000-0000-0000-000000000002');

insert into public.case_members (case_id, profile_id, role_in_case, added_by)
values
  ('83000000-0000-0000-0000-0000000000A1', '81000000-0000-0000-0000-000000000002', 'lead',         '81000000-0000-0000-0000-000000000002'),
  ('83000000-0000-0000-0000-0000000000A1', '81000000-0000-0000-0000-000000000003', 'investigator', '81000000-0000-0000-0000-000000000002'),
  ('83000000-0000-0000-0000-0000000000A1', '81000000-0000-0000-0000-000000000004', 'investigator', '81000000-0000-0000-0000-000000000002');

insert into public.evidence (id, case_id, evidence_number, title, description, type, status, created_by)
values
  ('84000000-0000-0000-0000-0000000000A1', '83000000-0000-0000-0000-0000000000A1', 'OM-EV-NO1', 'Org mgmt evidence', null, 'document', 'received', '81000000-0000-0000-0000-000000000003');

insert into public.document_versions (id, evidence_id, version, prev_version_id, file_name, mime_type, file_size_bytes, sha256, storage_key, uploaded_by, notes)
values
  ('85000000-0000-0000-0000-0000000000A1', '84000000-0000-0000-0000-0000000000A1', 1, null, 'om.pdf', 'application/pdf', 1234, repeat('a', 64), '83000000-0000-0000-0000-0000000000A1/84000000-0000-0000-0000-0000000000A1/85000000-0000-0000-0000-0000000000A1', '81000000-0000-0000-0000-000000000003', null);

-- Audit fixture rows. The 'case'/'evidence' rows intentionally leave the
-- org_id COLUMN null — mirroring the real writers (which store org only in
-- meta) — so T29 exercises the read-time resolution path. The
-- 'organization' row carries org_id directly (the 20260915 writers).
insert into public.audit_logs (actor_id, action, entity_type, entity_id, after, org_id, meta)
values
  ('81000000-0000-0000-0000-000000000002', 'case.created',              'case',            '83000000-0000-0000-0000-0000000000A1', null, null, jsonb_build_object('case_number', 'OM-CASE-A1')),
  ('81000000-0000-0000-0000-000000000003', 'evidence.created',          'evidence',        '84000000-0000-0000-0000-0000000000A1', null, null, jsonb_build_object('case_id', '83000000-0000-0000-0000-0000000000A1', 'evidence_number', 'OM-EV-NO1')),
  ('81000000-0000-0000-0000-000000000001', 'organization.created',       'organization',    '82000000-0000-0000-0000-0000000000A1', null, '82000000-0000-0000-0000-0000000000A1', jsonb_build_object('name', 'Org Alpha'));

-- =============================================================================
-- T21 — TRUNCATE revoked on all 10 core tables
-- =============================================================================
set local role authenticated;
set local request.jwt.claims = '{"sub":"81000000-0000-0000-0000-000000000001"}';

do $$
declare
    v_bad text := null;
begin
    -- Every one of these tables must be TRUNCATE-proof for authenticated.
    select t.tbl into v_bad
    from unnest(array[
        'profiles', 'cases', 'case_members', 'evidence', 'document_versions',
        'chain_of_custody', 'audit_logs', 'organizations', 'organization_members',
        'blockchain_anchors'
    ]) t(tbl)
    where has_table_privilege('authenticated', ('public.' || t.tbl), 'TRUNCATE')
    limit 1;
    if v_bad is not null then
        raise exception 'FAIL T21: authenticated still holds TRUNCATE';
    end if;
end $$;

-- =============================================================================
-- T22 — INSERT / DELETE revoked; SELECT / REFERENCES / TRIGGER retained
-- =============================================================================
do $$
declare
    v_bad text := null;
begin
    -- No table keeps a write grant (INSERT/UPDATE/DELETE) for authenticated.
    select min(t.tbl) into v_bad
    from unnest(array[
        'profiles', 'cases', 'case_members', 'evidence', 'document_versions',
        'chain_of_custody', 'audit_logs', 'organizations', 'organization_members',
        'blockchain_anchors'
    ]) t(tbl)
    where exists (
        select 1
        from information_schema.role_table_grants g
        where g.table_schema = 'public'
          and g.table_name = t.tbl
          and g.grantee = 'authenticated'
          and g.privilege_type in ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE')
    );
    if v_bad is not null then
        raise exception 'FAIL T22: authenticated keeps write grant on %', v_bad;
    end if;

    -- reads must survive: SELECT, REFERENCES and TRIGGER are unchanged.
    if not has_table_privilege('authenticated', 'public.cases', 'SELECT')
       or not has_table_privilege('authenticated', 'public.evidence', 'SELECT')
       or not has_table_privilege('authenticated', 'public.organization_members', 'SELECT')
       or not has_table_privilege('authenticated', 'public.organizations', 'SELECT')
       or not has_table_privilege('authenticated', 'public.cases', 'REFERENCES')
       or not has_table_privilege('authenticated', 'public.cases', 'TRIGGER')
    then
        raise exception 'FAIL T22: read grants were over-revoked';
    end if;
end $$;

-- =============================================================================
-- T23 — column-level UPDATE narrowed to the documented safe set
-- =============================================================================
do $$
begin
    -- cases: provenance/identity columns are NOT updatable...
    if has_column_privilege('authenticated', 'public.cases', 'id', 'UPDATE')
       or has_column_privilege('authenticated', 'public.cases', 'case_number', 'UPDATE')
       or has_column_privilege('authenticated', 'public.cases', 'org_id', 'UPDATE')
       or has_column_privilege('authenticated', 'public.cases', 'created_by', 'UPDATE')
       or has_column_privilege('authenticated', 'public.cases', 'created_at', 'UPDATE')
    then
        raise exception 'FAIL T23: cases provenance columns are updatable';
    end if;
    -- ...while the legit metadata set stays updatable.
    if not has_column_privilege('authenticated', 'public.cases', 'title', 'UPDATE')
       or not has_column_privilege('authenticated', 'public.cases', 'status', 'UPDATE')
       or not has_column_privilege('authenticated', 'public.cases', 'updated_at', 'UPDATE')
       or has_column_privilege('authenticated', 'public.cases', 'id', 'UPDATE')
    then
        raise exception 'FAIL T23: cases safe columns no longer updatable';
    end if;

    -- evidence: status is NOT updatable directly; metadata columns are.
    if has_column_privilege('authenticated', 'public.evidence', 'status', 'UPDATE')
       or has_column_privilege('authenticated', 'public.evidence', 'id', 'UPDATE')
       or has_column_privilege('authenticated', 'public.evidence', 'case_id', 'UPDATE')
       or has_column_privilege('authenticated', 'public.evidence', 'evidence_number', 'UPDATE')
       or not has_column_privilege('authenticated', 'public.evidence', 'description', 'UPDATE')
       or not has_column_privilege('authenticated', 'public.evidence', 'type', 'UPDATE')
    then
        raise exception 'FAIL T23: evidence column grants wrong';
    end if;

    -- append-only tables: zero column UPDATE.
    if has_column_privilege('authenticated', 'public.audit_logs', 'meta', 'UPDATE')
       or has_column_privilege('authenticated', 'public.audit_logs', 'actor_id', 'UPDATE')
       or has_column_privilege('authenticated', 'public.document_versions', 'sha256', 'UPDATE')
       or has_column_privilege('authenticated', 'public.blockchain_anchors', 'status', 'UPDATE')
       or has_column_privilege('authenticated', 'public.blockchain_anchors', 'evidence_sha256', 'UPDATE')
    then
        raise exception 'FAIL T23: append-only tables keep column UPDATE';
    end if;

    -- organizations/profiles: safe set only.
    if has_column_privilege('authenticated', 'public.organizations', 'created_by', 'UPDATE')
       or not has_column_privilege('authenticated', 'public.organizations', 'name', 'UPDATE')
       or has_column_privilege('authenticated', 'public.profiles', 'role', 'UPDATE')
       or not has_column_privilege('authenticated', 'public.profiles', 'full_name', 'UPDATE')
    then
        raise exception 'FAIL T23: organizations/profiles column grants wrong';
    end if;
end $$;

-- =============================================================================
-- T24 — direct DML attempts fail; the legit direct-metadata control works
-- =============================================================================
-- As the lead (u2), direct UPDATE of evidence status, ingest of audit rows and
-- provenance tampering must all fail, while a plain cases.title edit succeeds.
set local request.jwt.claims = '{"sub":"81000000-0000-0000-0000-000000000002"}';

do $$
declare
    v_n integer;
begin
    -- direct evidence.status UPDATE denied (column grant revoked)
    begin
        update public.evidence
        set status = 'archived'
        where id = '84000000-0000-0000-0000-0000000000A1';
        raise exception 'FAIL T24: direct evidence.status UPDATE succeeded';
    exception when insufficient_privilege then
        null;
    end;

    -- direct provenance UPDATE on cases denied (case_number / org_id / created_by)
    begin
        update public.cases
        set case_number = 'FORGED'
        where id = '83000000-0000-0000-0000-0000000000A1';
        raise exception 'FAIL T24: direct cases.case_number UPDATE succeeded';
    exception when insufficient_privilege then
        null;
    end;

    begin
        update public.cases
        set org_id = '82000000-0000-0000-0000-0000000000B1'
        where id = '83000000-0000-0000-0000-0000000000A1';
        raise exception 'FAIL T24: direct cases.org_id UPDATE succeeded';
    exception when insufficient_privilege then
        null;
    end;

    begin
        update public.cases
        set created_by = '81000000-0000-0000-0000-000000000005'
        where id = '83000000-0000-0000-0000-0000000000A1';
        raise exception 'FAIL T24: direct cases.created_by UPDATE succeeded';
    exception when insufficient_privilege then
        null;
    end;

    -- audit_logs is append-only: direct INSERT denied
    begin
        insert into public.audit_logs (actor_id, action, entity_type, entity_id, meta)
        values ('81000000-0000-0000-0000-000000000002', 'case.forged', 'case', '83000000-0000-0000-0000-0000000000A1', '{}');
        raise exception 'FAIL T24: direct audit_logs INSERT succeeded';
    exception when insufficient_privilege or check_violation then
        null;
    end;

    -- TRUNCATE denied
    begin
        execute 'truncate table public.evidence';
        raise exception 'FAIL T24: TRUNCATE succeeded';
    exception when insufficient_privilege then
        null;
    end;

    -- positive control: the lead can still edit the safe cases.title column
    update public.cases
    set title = 'Direct-edited title'
    where id = '83000000-0000-0000-0000-0000000000A1';
    get diagnostics v_n = row_count;
    if v_n <> 1 then
        raise exception 'FAIL T24: lead direct title edit did not affect exactly 1 row (%)', v_n;
    end if;

    -- restore
    update public.cases
    set title = 'Org member management case'
    where id = '83000000-0000-0000-0000-0000000000A1';
end $$;

-- =============================================================================
-- T25 — stale org member is blocked by all four hardened write RPCs
-- =============================================================================
-- u1 removes u4 from org-alpha. u4 keeps the stale case_members (investigator)
-- row on C_A. Every hardened write RPC must refuse u4 now.
set local request.jwt.claims = '{"sub":"81000000-0000-0000-0000-000000000001"}';

do $$
begin
    perform public.remove_organization_member(
        '82000000-0000-0000-0000-0000000000A1',
        '81000000-0000-0000-0000-000000000004'
    );
end $$;

-- sanity: the stale case_members row still exists (org membership gone only).
set local request.jwt.claims = '{"sub":"81000000-0000-0000-0000-000000000001"}';

do $$
begin
    if not exists (
        select 1 from public.case_members
        where case_id = '83000000-0000-0000-0000-0000000000A1'
          and profile_id = '81000000-0000-0000-0000-000000000004'
    ) then
        raise exception 'FAIL T25: fixture stalled — stale case_members row missing';
    end if;
    if exists (
        select 1 from public.organization_members
        where org_id = '82000000-0000-0000-0000-0000000000A1'
          and profile_id = '81000000-0000-0000-0000-000000000004'
    ) then
        raise exception 'FAIL T25: fixture stalled — u4 still in org-alpha';
    end if;
end $$;

-- u4 now attempts every write RPC. RLS would reject anyway; the RPC-level
-- is_case_member guard must fire first (defense in depth for SECURITY DEFINER).
set local role authenticated;
set local request.jwt.claims = '{"sub":"81000000-0000-0000-0000-000000000004"}';

do $$
begin
    begin
        perform public.update_case(
            '83000000-0000-0000-0000-0000000000A1',
            p_title => 'Stale attempt'
        );
        raise exception 'FAIL T25: stale member updated a case';
    exception when others then
        if sqlerrm not like '%not_case_member%' then
            raise;
        end if;
    end;

    begin
        perform public.update_evidence_status(
            '84000000-0000-0000-0000-0000000000A1',
            'under_review'
        );
        raise exception 'FAIL T25: stale member changed evidence status';
    exception when others then
        if sqlerrm not like '%not_case_member%' then
            raise;
        end if;
    end;

    begin
        perform public.create_evidence(
            p_case_id              => '83000000-0000-0000-0000-0000000000A1',
            p_evidence_id          => '84000000-0000-0000-0000-0000000000A3',
            p_document_version_id  => '85000000-0000-0000-0000-0000000000A3',
            p_title                => 'Stale upload',
            p_description          => null,
            p_type                 => 'document',
            p_file_name            => 'stale.pdf',
            p_mime_type            => 'application/pdf',
            p_file_size_bytes      => 10,
            p_sha256               => repeat('d', 64),
            p_storage_key          => '83000000-0000-0000-0000-0000000000a1/84000000-0000-0000-0000-0000000000a3/85000000-0000-0000-0000-0000000000a3',
            p_notes                => null
        );
        raise exception 'FAIL T25: stale member created evidence';
    exception when others then
        if sqlerrm not like '%case_not_found%' then
            raise;
        end if;
    end;

    begin
        perform public.create_blockchain_anchor(
            '85000000-0000-0000-0000-0000000000A1'
        );
        raise exception 'FAIL T25: stale member anchored a version';
    exception when others then
        if sqlerrm not like '%not_case_member%' then
            raise;
        end if;
    end;
end $$;

-- =============================================================================
-- T26 — org admin WITHOUT explicit lead membership cannot write
-- =============================================================================
-- u1 is an org admin (org-wide READ), but has no case_members row on C_A.
-- Documented decision: org admins get read/audit, never lead-equivalent write.
set local request.jwt.claims = '{"sub":"81000000-0000-0000-0000-000000000001"}';

do $$
begin
    begin
        perform public.update_case(
            '83000000-0000-0000-0000-0000000000A1',
            p_title => 'Admin takeover'
        );
        raise exception 'FAIL T26: org admin updated a case without explicit lead';
    exception when others then
        if sqlerrm not like '%not_lead%' then
            raise;
        end if;
    end;

    begin
        perform public.update_evidence_status(
            '84000000-0000-0000-0000-0000000000A1',
            'under_review'
        );
        raise exception 'FAIL T26: org admin changed evidence status without explicit case role';
    exception when others then
        if sqlerrm not like '%not_authorized_to_update%' then
            raise;
        end if;
    end;

    begin
        perform public.create_evidence(
            p_case_id              => '83000000-0000-0000-0000-0000000000A1',
            p_evidence_id          => '84000000-0000-0000-0000-0000000000A4',
            p_document_version_id  => '85000000-0000-0000-0000-0000000000A4',
            p_title                => 'Admin upload',
            p_description          => null,
            p_type                 => 'document',
            p_file_name            => 'admin.pdf',
            p_mime_type            => 'application/pdf',
            p_file_size_bytes      => 10,
            p_sha256               => repeat('e', 64),
            p_storage_key          => '83000000-0000-0000-0000-0000000000a1/84000000-0000-0000-0000-0000000000a4/85000000-0000-0000-0000-0000000000a4',
            p_notes                => null
        );
        raise exception 'FAIL T26: org admin uploaded evidence without explicit case role';
    exception when others then
        if sqlerrm not like '%not_authorized_to_upload%' then
            raise;
        end if;
    end;

    begin
        perform public.create_blockchain_anchor(
            '85000000-0000-0000-0000-0000000000A1'
        );
        raise exception 'FAIL T26: org admin anchored a version without explicit case role';
    exception when others then
        if sqlerrm not like '%not_authorized_to_anchor%' then
            raise;
        end if;
    end;
end $$;

-- =============================================================================
-- T27 — valid actors still work (positive controls for the hardening)
-- =============================================================================
-- u2 (lead, org member) still updates the case.
set local request.jwt.claims = '{"sub":"81000000-0000-0000-0000-000000000002"}';

do $$
declare
    v_title text;
begin
    select (public.update_case(
        '83000000-0000-0000-0000-0000000000A1',
        p_title => 'Renamed case'
    )).title into v_title;
    if v_title <> 'Renamed case' then
        raise exception 'FAIL T27: update_case did not persist the new title (%)', v_title;
    end if;

    -- revert to the fixture title
    select (public.update_case(
        '83000000-0000-0000-0000-0000000000A1',
        p_title => 'Org member management case'
    )).title into v_title;
end $$;

-- u3 (investigator, org member) transitions evidence status (no anchor required
-- for under_review) and anchors the version.
set local request.jwt.claims = '{"sub":"81000000-0000-0000-0000-000000000003"}';

do $$
declare
    v_status text;
    v_anchor jsonb;
begin
    select (public.update_evidence_status(
        '84000000-0000-0000-0000-0000000000A1',
        'under_review'
    )).status into v_status;
    if v_status <> 'under_review' then
        raise exception 'FAIL T27: evidence status transition did not persist';
    end if;

    select public.create_blockchain_anchor('85000000-0000-0000-0000-0000000000A1') into v_anchor;
    if (v_anchor ->> 'reused') is null then
        raise exception 'FAIL T27: create_blockchain_anchor returned no result';
    end if;
end $$;

-- u2 (lead) creates fresh evidence through the real intake RPC.
set local request.jwt.claims = '{"sub":"81000000-0000-0000-0000-000000000002"}';

do $$
declare
    v_n integer;
begin
    perform public.create_evidence(
        p_case_id              => '83000000-0000-0000-0000-0000000000A1',
        p_evidence_id          => '84000000-0000-0000-0000-0000000000A2',
        p_document_version_id  => '85000000-0000-0000-0000-0000000000A2',
        p_title                => 'Intake evidence',
        p_description          => null,
        p_type                 => 'document',
        p_file_name            => 'intake.pdf',
        p_mime_type            => 'application/pdf',
        p_file_size_bytes      => 2048,
        p_sha256               => repeat('b', 64),
        p_storage_key          => '83000000-0000-0000-0000-0000000000a1/84000000-0000-0000-0000-0000000000a2/85000000-0000-0000-0000-0000000000a2',
        p_notes                => null
    );

    -- the intake custody 'received' row must exist (T22 regression stays green)
    select count(*) into v_n
    from public.chain_of_custody
    where evidence_id = '84000000-0000-0000-0000-0000000000A2'
      and action = 'received';
    if v_n <> 1 then
        raise exception 'FAIL T27: intake custody row missing (found %)', v_n;
    end if;
end $$;

-- =============================================================================
-- T28 — list_organization_members: org-scoped roster
-- =============================================================================
set local request.jwt.claims = '{"sub":"81000000-0000-0000-0000-000000000001"}';

do $$
declare
    v_n integer;
begin
    -- u4 was removed from org-alpha in T25, so the roster is u1/u2/u3.
    select count(*) into v_n
    from public.list_organization_members('82000000-0000-0000-0000-0000000000A1');
    if v_n <> 3 then
        raise exception 'FAIL T28: org-alpha roster has % rows, expected 3', v_n;
    end if;
end $$;

do $$
declare
    v_admin_exists boolean;
    v_added_ok     boolean;
begin
    select
        bool_or(m.role_in_org = 'admin'),
        bool_or(m.added_by_name is not null)
    into v_admin_exists, v_added_ok
    from public.list_organization_members('82000000-0000-0000-0000-0000000000A1') m;
    if not v_admin_exists then
        raise exception 'FAIL T28: org-alpha roster has no admin row';
    end if;
    if not v_added_ok then
        raise exception 'FAIL T28: roster missing added_by_name';
    end if;
end $$;

-- access control: cross-org member gets the same error as a nonexistent org.
set local request.jwt.claims = '{"sub":"81000000-0000-0000-0000-000000000005"}';

do $$
begin
    begin
        perform * from public.list_organization_members('82000000-0000-0000-0000-0000000000A1');
        raise exception 'FAIL T28: cross-org user listed another org''s members';
    exception when others then
        if sqlerrm not like '%org_not_found%' then
            raise;
        end if;
    end;

    -- ...but their own org's roster is visible (member-scoped read). u5/u8
    -- are the org-beta members (u8 added as the T30 candidate fixture).
    if (select count(*) from public.list_organization_members('82000000-0000-0000-0000-0000000000B1')) <> 2 then
        raise exception 'FAIL T28: member cannot list their own org';
    end if;
end $$;

set local role anon;
set local request.jwt.claims = '{"sub": null, "role": "anon"}';

do $$
begin
    begin
        perform * from public.list_organization_members('82000000-0000-0000-0000-0000000000A1');
        raise exception 'FAIL T28: anon listed organization members';
    exception when insufficient_privilege or undefined_function then
        null;
    end;
end $$;

-- =============================================================================
-- T29 — list_organization_audit_events: complete org trail, cross-org safe
-- =============================================================================
set local role authenticated;
set local request.jwt.claims = '{"sub":"81000000-0000-0000-0000-000000000001"}';

do $$
declare
    v_n              integer;
    v_has_org_ev     boolean;
    v_has_case_ev    boolean;
    v_has_member_ev  boolean;
    v_leak           bigint;
    v_label          text;
begin
    -- the org-alpha trail must include: organization.created, case.created,
    -- evidence.created (fixture) + T25 removal + T27 writes.
    select count(*) into v_n
    from public.list_organization_audit_events('82000000-0000-0000-0000-0000000000A1');
    if v_n < 5 then
        raise exception 'FAIL T29: org trail too small (%), expected >= 5', v_n;
    end if;

    -- the resolved organization event resolves with its name as label.
    select bool_or(e.entity_type = 'organization' and e.entity_label = 'Org Alpha')
    into v_has_org_ev
    from public.list_organization_audit_events('82000000-0000-0000-0000-0000000000A1') e;
    if not v_has_org_ev then
        raise exception 'FAIL T29: organization.created event missing or mislabeled';
    end if;

    -- the resolved case event (org_id column NULL in fixture) is picked up via
    -- the entity chain resolution.
    select bool_or(e.entity_type = 'case' and e.entity_label = 'Org member management case')
    into v_has_case_ev
    from public.list_organization_audit_events('82000000-0000-0000-0000-0000000000A1') e;
    if not v_has_case_ev then
        raise exception 'FAIL T29: case.created event not resolved into the org trail';
    end if;

    -- T25's remove_organization_member wrote an org-membership event.
    select bool_or(e.action = 'organization.member_removed')
    into v_has_member_ev
    from public.list_organization_audit_events('82000000-0000-0000-0000-0000000000A1') e;
    if not v_has_member_ev then
        raise exception 'FAIL T29: organization.member_removed event missing from trail';
    end if;

    -- every meta must be scrubbed of storage_key, and no row may leak.
    select count(*) into v_leak
    from public.list_organization_audit_events('82000000-0000-0000-0000-0000000000A1') e
    where e.meta ? 'storage_key';
    if v_leak > 0 then
        raise exception 'FAIL T29: % rows leak storage_key in the org trail', v_leak;
    end if;
end $$;

-- access control: cross-org member denied identically to nonexistent org.
set local request.jwt.claims = '{"sub":"81000000-0000-0000-0000-000000000005"}';

do $$
begin
    begin
        perform * from public.list_organization_audit_events('82000000-0000-0000-0000-0000000000A1');
        raise exception 'FAIL T29: cross-org user read the other org''s audit trail';
    exception when others then
        if sqlerrm not like '%org_not_found%' then
            raise;
        end if;
    end;
end $$;

set local role anon;
set local request.jwt.claims = '{"sub": null, "role": "anon"}';

do $$
begin
    begin
        perform * from public.list_organization_audit_events('82000000-0000-0000-0000-0000000000A1');
        raise exception 'FAIL T29: anon read the org audit trail';
    exception when insufficient_privilege or undefined_function then
        null;
    end;
end $$;

-- =============================================================================
-- T30 — lookup_profiles_for_organization: candidate search (non-members)
--
-- The Add-Member lookup must return profiles who are NOT yet members of the
-- target org — never the current roster. It searches full_name/badge_number
-- (case-insensitive substring), caps at 10, exposes only id/full_name/
-- badge_number, and requires the caller to belong to the target org.
-- =============================================================================
set local role authenticated;
set local request.jwt.claims = '{"sub":"81000000-0000-0000-0000-000000000001"}';

do $$
declare
    v_n    integer;
    v_ids  uuid[];
    v_keys text[];
begin
    -- (a) Existing org-alpha members are NEVER returned, even by exact name.
    select count(*) into v_n
    from public.lookup_profiles_for_organization(
        '82000000-0000-0000-0000-0000000000A1', 'Member Admin Alpha');
    if v_n <> 0 then
        raise exception 'FAIL T30: org member u1 returned as candidate (%)', v_n;
    end if;

    select count(*) into v_n
    from public.lookup_profiles_for_organization(
        '82000000-0000-0000-0000-0000000000A1', 'Member Lead Alpha');
    if v_n <> 0 then
        raise exception 'FAIL T30: org member u2 returned as candidate (%)', v_n;
    end if;

    select count(*) into v_n
    from public.lookup_profiles_for_organization(
        '82000000-0000-0000-0000-0000000000A1', 'Member Investigator A');
    if v_n <> 0 then
        raise exception 'FAIL T30: org member u3 returned as candidate (%)', v_n;
    end if;

    -- (b) Existing members are excluded even when matched via badge_number.
    select count(*) into v_n
    from public.lookup_profiles_for_organization(
        '82000000-0000-0000-0000-0000000000A1', 'INV-ALPHA');
    if v_n <> 0 then
        raise exception 'FAIL T30: org member badge surfaced in candidates (%)', v_n;
    end if;

    -- (c) A profile with no org membership at all is found by full_name ...
    select count(*) into v_n
    from public.lookup_profiles_for_organization(
        '82000000-0000-0000-0000-0000000000A1', 'Candidate Searchable');
    if v_n <> 1 then
        raise exception 'FAIL T30: no-org candidate not found by full_name (%)', v_n;
    end if;

    -- (d) ... and by badge_number.
    select count(*) into v_n
    from public.lookup_profiles_for_organization(
        '82000000-0000-0000-0000-0000000000A1', 'CAND-0007');
    if v_n <> 1 then
        raise exception 'FAIL T30: no-org candidate not found by badge (%)', v_n;
    end if;

    -- (e) A member of ANOTHER org (org-beta's u8) is a valid candidate for
    -- org-alpha: organization_members is per-org, so profiles may belong to
    -- several organizations, and anything not in the TARGET org is add-able.
    select count(*) into v_n
    from public.lookup_profiles_for_organization(
        '82000000-0000-0000-0000-0000000000A1', 'Beta Candidate');
    if v_n <> 1 then
        raise exception 'FAIL T30: other-org member not returned as candidate (%)', v_n;
    end if;

    -- (f) Combined case-insensitive substring 'Candidate' yields exactly the
    -- three candidates (u6/u7/u8) and never a current org member.
    select array_agg(c.id order by c.full_name, c.id) into v_ids
    from public.lookup_profiles_for_organization(
        '82000000-0000-0000-0000-0000000000A1', 'Candidate') c;
    if v_ids <> array[
        '81000000-0000-0000-0000-000000000007'::uuid,
        '81000000-0000-0000-0000-000000000008'::uuid,
        '81000000-0000-0000-0000-000000000006'::uuid
    ] then
        raise exception 'FAIL T30: candidate set wrong (got %)', v_ids;
    end if;

    -- (g) Results are capped at 10 even when 11 profiles match.
    select count(*) into v_n
    from public.lookup_profiles_for_organization(
        '82000000-0000-0000-0000-0000000000A1', 'Limit Tester');
    if v_n <> 10 then
        raise exception 'FAIL T30: result limit not enforced (got %)', v_n;
    end if;

    -- (h) Only id / full_name / badge_number are exposed — no global role,
    -- org membership role, email, or other sensitive field appears.
    select array_agg(k order by k) into v_keys
    from (
        select jsonb_object_keys(to_jsonb(c)) as k
        from public.lookup_profiles_for_organization(
            '82000000-0000-0000-0000-0000000000A1', 'Candidate Searchable') c
    ) s;
    if v_keys <> array['badge_number', 'full_name', 'id'] then
        raise exception 'FAIL T30: returned fields % (expected id/full_name/badge_number)', v_keys;
    end if;
end $$;

-- access control: a caller from another org cannot search relative to org-alpha.
set local request.jwt.claims = '{"sub":"81000000-0000-0000-0000-000000000005"}';

do $$
begin
    begin
        perform * from public.lookup_profiles_for_organization('82000000-0000-0000-0000-0000000000A1', 'Member');
        raise exception 'FAIL T30: cross-org user searched another org''s candidates';
    exception when others then
        if sqlerrm not like '%org_not_found%' then
            raise;
        end if;
    end;
end $$;

-- access control: a caller with NO org membership cannot search at all.
set local request.jwt.claims = '{"sub":"81000000-0000-0000-0000-000000000006"}';

do $$
begin
    begin
        perform * from public.lookup_profiles_for_organization('82000000-0000-0000-0000-0000000000A1', 'Candidate');
        raise exception 'FAIL T30: org-less user searched org-alpha candidates';
    exception when others then
        if sqlerrm not like '%org_not_found%' then
            raise;
        end if;
    end;
end $$;

set local role anon;
set local request.jwt.claims = '{"sub": null, "role": "anon"}';

do $$
begin
    begin
        perform * from public.lookup_profiles_for_organization('82000000-0000-0000-0000-0000000000A1', 'Member');
        raise exception 'FAIL T30: anon searched organization candidates';
    exception when insufficient_privilege or undefined_function then
        null;
    end;
end $$;

-- =============================================================================
-- Final integrity sweep (owner context)
-- =============================================================================
reset role;

do $$
declare
    v_bad bigint;
begin
    -- Every case_members row must point at a member of the SAME org as its
    -- case. T25 deliberately left one stale, org-less row behind (u4 on C_A)
    -- to prove it grants nothing; it is test-only and must not survive the
    -- invariant below. Remove it, then assert no boundary violation remains.
    delete from public.case_members
    where case_id = '83000000-0000-0000-0000-0000000000A1'
      and profile_id = '81000000-0000-0000-0000-000000000004';

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

    -- No evidence/document version may have been created by the stale member
    -- or the org admin: all rows were produced by legitimate actors.
    select count(*) into v_bad
    from public.evidence e
    where e.case_id = '83000000-0000-0000-0000-0000000000A1'
      and e.created_by = '81000000-0000-0000-0000-000000000004';
    if v_bad > 0 then
        raise exception 'FAIL final: stale member created evidence';
    end if;
end $$;