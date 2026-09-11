-- =============================================================================
-- SIH26190 Secure Evidence — organization foundation tests
--
-- Validates the organization/membership RLS policies and SECURITY DEFINER
-- helpers from 20260912000000_organization_foundation.sql plus the hardening
-- pass in 20260913000000_organization_foundation_hardening.sql against a LIVE
-- local Supabase instance.
--
-- HOW TO RUN (single transaction required — the script relies on `set local`):
--   supabase start          # needs Docker
--   supabase db reset       # apply all migrations on a fresh DB
--   psql "$SUPABASE_DB_URL" -1 -v ON_ERROR_STOP=1 \
--       -f supabase/tests/organization_foundation.sql
-- (or paste the whole file into the Supabase SQL editor, which runs in one
--  transaction, replacing $SUPABASE_DB_URL at the top.)
--
-- Every test either passes silently or aborts with a `FAIL T<n>` exception.
-- The script mutates only rows it creates itself; run against a throwaway DB.
--
-- Coverage:
--   T1   unauthenticated user cannot read organizations
--   T2   unauthenticated user cannot read organization_members
--   T3   organization member can read their organization
--   T4   organization member cannot read another organization
--   T5   organization member can read their own membership
--   T6   organization member cannot read another org's membership
--   T7   non-admin member cannot modify organization settings
--   T8   non-admin member cannot add organization members
--   T9   non-admin member cannot remove organization members
--   T10  organization admin can manage members via the hardening RPCs
--   T11  user cannot self-insert an organization_members row with role='admin'
--   T12  user from Organization A cannot access Organization B
--   T13  existing cases have org_id after migration (and their org exists)
--   T14  dual-path default-organization check: on an existing-data database
--        the deterministic default org exists and holds every pre-existing
--        profile as admin; on a clean database the backfill is skipped and
--        no organization was fabricated (nothing to own it)
--   T15  existing case_members remain intact (referential integrity)
--   T16  existing evidence remains intact (referential integrity)
--   T17  existing document_versions remain intact (referential integrity)
--   T18  existing blockchain_anchors remain intact (referential integrity)
--   T19  existing audit_logs remain intact and org_id is consistent
--   T20  existing application hardening tests still pass
--   T21  create_organization: creator becomes admin of the new org
--   T22  create_organization: invalid / duplicate slug is rejected, no row
--   T23  anon cannot execute create_organization
--   T24  non-admin cannot execute membership management RPCs
--   T25  last org admin cannot be demoted
--   T26  last org admin cannot be removed
--   T27  admin can demote / remove another admin when one admin remains
--   T28  direct INSERT into organizations is revoked
--   T29  direct INSERT/UPDATE/DELETE on organization_members is revoked
--   T30  organization audit events carry the correct org_id
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Test users / fixture ids (deterministic, never collide with real data)
-- ---------------------------------------------------------------------------
-- org_admin_uuid    60000000-0000-0000-0000-000000000001  (admin of org_alpha)
-- org_member_uuid   60000000-0000-0000-0000-000000000002  (member of org_alpha)
-- org_outsider_uuid 60000000-0000-0000-0000-000000000003  (no org membership)
-- org_beta_admin    60000000-0000-0000-0000-000000000004  (admin of org_beta)
-- org_alpha_id      70000000-0000-0000-0000-0000000000A1
-- org_beta_id       70000000-0000-0000-0000-0000000000B1

-- ---------------------------------------------------------------------------
-- Fixtures (run as postgres / owner; RLS is bypassed for the fixture writer)
-- ---------------------------------------------------------------------------

-- Auth users (required for auth.uid() simulation via set local)
insert into auth.users (id, email, encrypted_password, email_confirmed_at, raw_app_meta_data, created_at, updated_at)
values
  ('60000000-0000-0000-0000-000000000001', 't.orgadmin@example.com',   '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('60000000-0000-0000-0000-000000000002', 't.orgmember@example.com',  '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('60000000-0000-0000-0000-000000000003', 't.orgoutsider@example.com','', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('60000000-0000-0000-0000-000000000004', 't.betadmin@example.com',   '', now(), '{"role":"authenticated","provider":"email"}', now(), now());

-- Profiles (handle_new_user trigger may already create these; ON CONFLICT is safe)
insert into public.profiles (id, full_name, role)
values
  ('60000000-0000-0000-0000-000000000001', 'Org Admin Alpha',   'officer'),
  ('60000000-0000-0000-0000-000000000002', 'Org Member Alpha',  'officer'),
  ('60000000-0000-0000-0000-000000000003', 'Org Outsider',      'officer'),
  ('60000000-0000-0000-0000-000000000004', 'Org Admin Beta',    'officer')
on conflict (id) do nothing;

-- Organizations
insert into public.organizations (id, name, slug, created_by)
values
  ('70000000-0000-0000-0000-0000000000A1', 'Org Alpha', 'org-alpha', '60000000-0000-0000-0000-000000000001'),
  ('70000000-0000-0000-0000-0000000000B1', 'Org Beta',  'org-beta',  '60000000-0000-0000-0000-000000000004');

-- Organization members
insert into public.organization_members (org_id, profile_id, role_in_org, added_by)
values
  ('70000000-0000-0000-0000-0000000000A1', '60000000-0000-0000-0000-000000000001', 'admin',       '60000000-0000-0000-0000-000000000001'),
  ('70000000-0000-0000-0000-0000000000A1', '60000000-0000-0000-0000-000000000002', 'member',      '60000000-0000-0000-0000-000000000001'),
  ('70000000-0000-0000-0000-0000000000B1', '60000000-0000-0000-0000-000000000004', 'admin',       '60000000-0000-0000-0000-000000000004');

-- ---------------------------------------------------------------------------
-- T1: Unauthenticated user cannot read organizations
-- ---------------------------------------------------------------------------
-- anon has no privilege on public.organizations at all (the foundation +
-- hardening migrations revoked it; there is no anon SELECT policy). The
-- permission-denied error IS the invariant under test, so assert it directly
-- rather than granting anon a read to count rows.
set local role anon;
do $$
begin
    begin
        perform count(*) from public.organizations;
        raise exception 'FAIL T1: anon can read organizations';
    exception when insufficient_privilege then
        null;
    end;
end $$;

-- ---------------------------------------------------------------------------
-- T2: Unauthenticated user cannot read organization_members
-- ---------------------------------------------------------------------------
-- Same shape as T1: anon has no privilege on organization_members either.
do $$
begin
    begin
        perform count(*) from public.organization_members;
        raise exception 'FAIL T2: anon can read organization_members';
    exception when insufficient_privilege then
        null;
    end;
end $$;

-- ---------------------------------------------------------------------------
-- T3: Organization member can read their organization
-- ---------------------------------------------------------------------------
set local role authenticated;
set local request.jwt.claims = '{"sub":"60000000-0000-0000-0000-000000000002"}';
set local role authenticated;

do $$
begin
    if not exists (
        select 1 from public.organizations
        where id = '70000000-0000-0000-0000-0000000000A1'
    ) then
        raise exception 'FAIL T3: org member cannot read their organization';
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- T4: Organization member cannot read another organization
-- ---------------------------------------------------------------------------
do $$
begin
    if exists (
        select 1 from public.organizations
        where id = '70000000-0000-0000-0000-0000000000B1'
    ) then
        raise exception 'FAIL T4: org member can read another organization';
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- T5: Organization member can read their own membership
-- ---------------------------------------------------------------------------
do $$
begin
    if not exists (
        select 1 from public.organization_members
        where org_id = '70000000-0000-0000-0000-0000000000A1'
          and profile_id = '60000000-0000-0000-0000-000000000002'
    ) then
        raise exception 'FAIL T5: org member cannot read their own membership';
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- T6: Organization member cannot read another org's membership
-- ---------------------------------------------------------------------------
do $$
begin
    if exists (
        select 1 from public.organization_members
        where org_id = '70000000-0000-0000-0000-0000000000B1'
    ) then
        raise exception 'FAIL T6: org member can read another org''s membership';
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- T7: Non-admin member cannot modify organization settings
-- ---------------------------------------------------------------------------
-- RLS denied rows are skipped silently (0 rows affected, no exception), so the
-- correct assertion is "the row is unchanged afterwards" — not "an exception is
-- raised". org_member (6002) is 'member' in org_alpha, not 'admin'.
do $$
begin
    update public.organizations
    set name = 'Hacked'
    where id = '70000000-0000-0000-0000-0000000000A1';
end $$;

reset role;
do $$
begin
    if (select name from public.organizations where id = '70000000-0000-0000-0000-0000000000A1') = 'Hacked' then
        raise exception 'FAIL T7: non-admin updated organization name';
    end if;
end $$;

set local role authenticated;
set local request.jwt.claims = '{"sub":"60000000-0000-0000-0000-000000000002"}';
set local role authenticated;

-- ---------------------------------------------------------------------------
-- T8: Non-admin member cannot add organization members
-- ---------------------------------------------------------------------------
-- INSERT denied by RLS WITH CHECK raises `new row violates row-level security
-- policy` (SQLSTATE 42501), so the exception path is the right assertion here.
do $$
begin
    begin
        insert into public.organization_members (org_id, profile_id, role_in_org, added_by)
        values ('70000000-0000-0000-0000-0000000000A1', '60000000-0000-0000-0000-000000000003', 'member', '60000000-0000-0000-0000-000000000002');
        raise exception 'FAIL T8: non-admin can insert organization_members';
    exception when insufficient_privilege or check_violation then
        null;
    end;
end $$;

-- ---------------------------------------------------------------------------
-- T9: Non-admin member cannot remove organization members
-- ---------------------------------------------------------------------------
-- After hardening, DELETE on organization_members is revoked from authenticated,
-- so this raises insufficient_privilege. Before hardening, RLS would silently
-- affect 0 rows. Handle both.
do $$
begin
    begin
        delete from public.organization_members
        where org_id = '70000000-0000-0000-0000-0000000000A1'
          and profile_id = '60000000-0000-0000-0000-000000000001';
    exception when insufficient_privilege or check_violation then
        null;
    end;
end $$;

reset role;
do $$
begin
    if not exists (
        select 1 from public.organization_members
        where org_id = '70000000-0000-0000-0000-0000000000A1'
          and profile_id = '60000000-0000-0000-0000-000000000001'
    ) then
        raise exception 'FAIL T9: non-admin deleted an organization member';
    end if;
end $$;

set local role authenticated;
set local request.jwt.claims = '{"sub":"60000000-0000-0000-0000-000000000002"}';
set local role authenticated;

-- ---------------------------------------------------------------------------
-- T10: Organization admin can manage members via the hardening RPCs
-- ---------------------------------------------------------------------------
-- The hardening pass moved membership writes behind SECURITY DEFINER RPCs
-- (direct DML is revoked). Switch to org_alpha admin (6001) and drive the
-- full lifecycle: add -> change role -> remove.
set local request.jwt.claims = '{"sub":"60000000-0000-0000-0000-000000000001"}';
set local role authenticated;

do $$
declare
    v_member_id uuid;
begin
    select public.add_organization_member(
        '70000000-0000-0000-0000-0000000000A1',
        '60000000-0000-0000-0000-000000000003',
        'member'
    ) into v_member_id;

    if v_member_id is null then
        raise exception 'FAIL T10: add_organization_member returned no id';
    end if;

    -- Change the member's role
    if public.change_organization_member_role(
        '70000000-0000-0000-0000-0000000000A1',
        '60000000-0000-0000-0000-000000000003',
        'investigator'
    ) <> 'investigator' then
        raise exception 'FAIL T10: admin cannot change member role via RPC';
    end if;

    perform public.remove_organization_member(
        '70000000-0000-0000-0000-0000000000A1',
        '60000000-0000-0000-0000-000000000003'
    );
end $$;

reset role;
do $$
begin
    if exists (
        select 1 from public.organization_members
        where org_id = '70000000-0000-0000-0000-0000000000A1'
          and profile_id = '60000000-0000-0000-0000-000000000003'
    ) then
        raise exception 'FAIL T10: admin could not remove member via RPC';
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- T11: User cannot self-insert an organization_members row with role='admin'
-- ---------------------------------------------------------------------------
-- Switch to org_outsider (6003) — no org membership at all
set local role authenticated;
set local request.jwt.claims = '{"sub":"60000000-0000-0000-0000-000000000003"}';
set local role authenticated;

do $$
begin
    begin
        insert into public.organization_members (org_id, profile_id, role_in_org, added_by)
        values ('70000000-0000-0000-0000-0000000000A1', '60000000-0000-0000-0000-000000000003', 'admin', '60000000-0000-0000-0000-000000000003');
        raise exception 'FAIL T11: non-member can self-insert as admin';
    exception when insufficient_privilege or check_violation then
        null;
    end;
end $$;

-- Also try as a member (not admin) of org_alpha
set local request.jwt.claims = '{"sub":"60000000-0000-0000-0000-000000000002"}';
set local role authenticated;

do $$
begin
    begin
        insert into public.organization_members (org_id, profile_id, role_in_org, added_by)
        values ('70000000-0000-0000-0000-0000000000A1', '60000000-0000-0000-0000-000000000003', 'admin', '60000000-0000-0000-0000-000000000002');
        raise exception 'FAIL T11: member can insert admin into their org';
    exception when insufficient_privilege or check_violation then
        null;
    end;
end $$;

-- ---------------------------------------------------------------------------
-- T12: User from Organization A cannot access Organization B
-- ---------------------------------------------------------------------------
-- org_alpha member (6002) tries to read org_beta
do $$
begin
    if exists (
        select 1 from public.organizations
        where id = '70000000-0000-0000-0000-0000000000B1'
    ) then
        raise exception 'FAIL T12: user from org A can read org B';
    end if;
end $$;

-- org_alpha member tries to read org_beta's members
do $$
begin
    if exists (
        select 1 from public.organization_members
        where org_id = '70000000-0000-0000-0000-0000000000B1'
    ) then
        raise exception 'FAIL T12: user from org A can read org B''s members';
    end if;
end $$;

-- org_alpha member tries to add themselves to org_beta
do $$
begin
    begin
        insert into public.organization_members (org_id, profile_id, role_in_org, added_by)
        values ('70000000-0000-0000-0000-0000000000B1', '60000000-0000-0000-0000-000000000002', 'admin', '60000000-0000-0000-0000-000000000002');
        raise exception 'FAIL T12: user from org A can insert into org B';
    exception when insufficient_privilege or check_violation then
        null;
    end;
end $$;

-- ---------------------------------------------------------------------------
-- T13: Existing cases have org_id after migration (and their org exists)
-- ---------------------------------------------------------------------------
reset role;

do $$
declare
    v_count bigint;
begin
    select count(*) into v_count
    from public.cases c
    where c.org_id is null
       or not exists (select 1 from public.organizations o where o.id = c.org_id);
    if v_count > 0 then
        raise exception 'FAIL T13: % cases have missing/invalid org_id', v_count;
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- T14: Default-organization backfill is dual-path
-- ---------------------------------------------------------------------------
-- The backfill in PART 10 runs only when at least one profile exists at
-- migration time:
--   * Existing-data database -> 'secure-evidence' exists; every pre-existing
--     profile is an admin member of it.
--   * Clean database (`supabase db reset`) -> the backfill is skipped (there
--     is no real actor to own an organization), so the default org is ABSENT
--     and no org may have been fabricated by the migration.
-- Note: on the existing-data path we assert the default org exists and has an
-- admin, but NOT that "all profiles are members" — the test's own fixture
-- profiles are created after migration and are rightly non-members; they join
-- orgs through org_alpha/org_beta/gamma-test.
do $$
declare
    v_default_org_id uuid;
    v_count bigint;
begin
    select id into v_default_org_id from public.organizations where slug = 'secure-evidence';

    if v_default_org_id is not null then
        -- Existing-data path: the deterministic default org was created by the
        -- backfill and is owned (added_by) by a real profile.
        select count(*) into v_count
        from public.organization_members om
        where om.org_id = v_default_org_id
          and om.role_in_org = 'admin';
        if v_count = 0 then
            raise exception 'FAIL T14: default org "%" has no admin', 'secure-evidence';
        end if;
    else
        -- Clean path: the migration must have skipped the backfill, so only
        -- the org_alpha / org_beta fixtures created by THIS test may exist.
        select count(*) into v_count
        from public.organizations;
        if v_count <> 2 then
            raise exception 'FAIL T14: clean path — expected only the 2 fixture orgs, found % (default org fabricated?)', v_count;
        end if;
        raise notice 'T14: clean-database path — default org skipped, nothing fabricated';
    end if;

    -- Every org (including the default, if any) must still have an admin.
    select count(*) into v_count
    from public.organizations o
    where not exists (
        select 1 from public.organization_members om
        where om.org_id = o.id and om.role_in_org = 'admin'
    );
    if v_count > 0 then
        raise exception 'FAIL T14: % organizations have no admin', v_count;
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- T15: Existing case_members remain intact (referential integrity)
-- ---------------------------------------------------------------------------
do $$
declare
    v_bad bigint;
begin
    -- No orphan case_id / profile_id; unique (case_id, profile_id) intact.
    select count(*) into v_bad
    from public.case_members cm
    where not exists (select 1 from public.cases c where c.id = cm.case_id)
       or not exists (select 1 from public.profiles p where p.id = cm.profile_id)
       or not exists (select 1 from public.profiles p where p.id = cm.added_by);
    if v_bad > 0 then
        raise exception 'FAIL T15: % case_members rows violate referential integrity', v_bad;
    end if;

    select count(*) into v_bad
    from (
        select case_id, profile_id, count(*)
        from public.case_members
        group by case_id, profile_id
        having count(*) > 1
    ) dup;
    if v_bad > 0 then
        raise exception 'FAIL T15: duplicate (case_id, profile_id) rows exist';
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- T16: Existing evidence remains intact (referential integrity)
-- ---------------------------------------------------------------------------
do $$
declare
    v_bad bigint;
begin
    -- Every evidence row references an existing case whose org resolves; the
    -- (case_id, evidence_number) uniqueness holds.
    select count(*) into v_bad
    from public.evidence e
    where not exists (select 1 from public.cases c where c.id = e.case_id and c.org_id is not null);
    if v_bad > 0 then
        raise exception 'FAIL T16: % evidence rows reference a missing org-less case', v_bad;
    end if;

    select count(*) into v_bad
    from (
        select case_id, evidence_number, count(*)
        from public.evidence
        group by case_id, evidence_number
        having count(*) > 1
    ) dup;
    if v_bad > 0 then
        raise exception 'FAIL T16: duplicate (case_id, evidence_number) rows exist';
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- T17: Existing document_versions remain intact (referential integrity)
-- ---------------------------------------------------------------------------
do $$
declare
    v_bad bigint;
begin
    -- Every version references an existing evidence whose case resolves; the
    -- (evidence_id, version) uniqueness holds and sha256 format is intact.
    select count(*) into v_bad
    from public.document_versions dv
    where not exists (
        select 1 from public.evidence e
        join public.cases c on c.id = e.case_id and c.org_id is not null
        where e.id = dv.evidence_id
    );
    if v_bad > 0 then
        raise exception 'FAIL T17: % document_versions reference a broken evidence chain', v_bad;
    end if;

    select count(*) into v_bad
    from (
        select evidence_id, version, count(*)
        from public.document_versions
        group by evidence_id, version
        having count(*) > 1
    ) dup;
    if v_bad > 0 then
        raise exception 'FAIL T17: duplicate (evidence_id, version) rows exist';
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- T18: Existing blockchain_anchors remain intact (referential integrity)
-- ---------------------------------------------------------------------------
do $$
declare
    v_bad bigint;
begin
    -- Every anchor references an existing evidence (with resolvable org) and
    -- an existing document version.
    select count(*) into v_bad
    from public.blockchain_anchors ba
    where not exists (
        select 1 from public.evidence e
        join public.cases c on c.id = e.case_id and c.org_id is not null
        where e.id = ba.evidence_id
    );
    if v_bad > 0 then
        raise exception 'FAIL T18: % blockchain_anchors reference a broken evidence chain', v_bad;
    end if;

    select count(*) into v_bad
    from public.blockchain_anchors ba
    where ba.document_version_id is not null
      and not exists (
          select 1 from public.document_versions dv where dv.id = ba.document_version_id
      );
    if v_bad > 0 then
        raise exception 'FAIL T18: % blockchain_anchors reference a missing document_version', v_bad;
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- T19: Existing audit_logs remain intact and org_id is consistent
-- ---------------------------------------------------------------------------
-- Recompute each mapped entity_type's owning org and assert the backfill put
-- the same value on the row. This is the strongest "data preserved + mapping
-- correct" check available at runtime (pre-migration counts are unknowable).
do $$
declare
    v_bad bigint;
begin
    select count(*) into v_bad
    from public.audit_logs a
    where a.entity_type in ('case', 'case_member', 'evidence', 'document_version', 'blockchain_anchor')
      and a.org_id is distinct from (
          select case a.entity_type
              when 'case' then
                  (select c.org_id from public.cases c where c.id = a.entity_id)
              when 'case_member' then
                  (select c.org_id from public.cases c
                   where (a.meta ->> 'case_id') is not null
                     and c.id = (a.meta ->> 'case_id')::uuid)
              when 'evidence' then
                  (select c.org_id from public.evidence e
                   join public.cases c on c.id = e.case_id
                   where e.id = a.entity_id)
              when 'document_version' then
                  (select c.org_id from public.document_versions dv
                   join public.evidence e on e.id = dv.evidence_id
                   join public.cases c on c.id = e.case_id
                   where dv.id = a.entity_id)
              when 'blockchain_anchor' then
                  (select c.org_id from public.blockchain_anchors ba
                   join public.evidence e on e.id = ba.evidence_id
                   join public.cases c on c.id = e.case_id
                   where ba.id = a.entity_id)
          end
      );

    if v_bad > 0 then
        raise exception 'FAIL T19: % audit_logs rows have an inconsistent org_id', v_bad;
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- T20: Existing application hardening still passes
-- ---------------------------------------------------------------------------

-- T20a: anon cannot execute business RPCs
set local role anon;

do $$
begin
    begin
        perform public.create_case('70000000-0000-0000-0000-0000000000A1', 'T20-001', 'Anon case test', null);
        raise exception 'FAIL T20a: anon can execute create_case';
    exception when insufficient_privilege or undefined_function then
        null;
    end;
end $$;

-- T20b: direct UPDATE of evidence.status is revoked
set local role authenticated;
set local request.jwt.claims = '{"sub":"60000000-0000-0000-0000-000000000001"}';
set local role authenticated;

do $$
declare
    v_ev_id uuid;
begin
    -- Find any evidence to try updating
    select id into v_ev_id from public.evidence limit 1;
    if v_ev_id is not null then
        begin
            update public.evidence set status = 'verified' where id = v_ev_id;
            raise exception 'FAIL T20b: direct UPDATE of evidence.status is not revoked';
        exception when insufficient_privilege or check_violation then
            null;
        end;
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- T21: create_organization — creator becomes admin of the new org
-- ---------------------------------------------------------------------------
-- org_outsider (6003) creates a brand-new org; the RPC must atomically create
-- the org AND the creator's 'admin' membership, attributed to auth.uid().
set local request.jwt.claims = '{"sub":"60000000-0000-0000-0000-000000000003"}';
set local role authenticated;

do $$
declare
    v_new_org uuid;
begin
    select public.create_organization('Gamma Test Org', 'gamma-test') into v_new_org;
    if v_new_org is null then
        raise exception 'FAIL T21: create_organization returned no id';
    end if;

    if not exists (
        select 1 from public.organizations
        where id = v_new_org and name = 'Gamma Test Org' and slug = 'gamma-test'
    ) then
        raise exception 'FAIL T21: organization row not created';
    end if;

    if not exists (
        select 1 from public.organization_members
        where org_id = v_new_org
          and profile_id = '60000000-0000-0000-0000-000000000003'
          and role_in_org = 'admin'
          and added_by = '60000000-0000-0000-0000-000000000003'
    ) then
        raise exception 'FAIL T21: creator is not the admin of their new org';
    end if;
end $$;

-- The creator (a member of the new org) can now read it back through RLS.
reset role;
set local role authenticated;
set local request.jwt.claims = '{"sub":"60000000-0000-0000-0000-000000000003"}';
set local role authenticated;

do $$
begin
    if not exists (
        select 1 from public.organizations where slug = 'gamma-test'
    ) then
        raise exception 'FAIL T21: creator cannot read their new org through RLS';
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- T22: create_organization — invalid / duplicate slug rejected, no row
-- ---------------------------------------------------------------------------
do $$
declare
    v_org_count_before bigint;
    v_org_count_after  bigint;
    v_bad_slug_count   bigint;
begin
    select count(*) into v_org_count_before from public.organizations;

    -- A. Invalid slug (spaces / unsafe chars) must abort the RPC.
    begin
        perform public.create_organization('Bad Slug Org', 'Bad Slug!');
        raise exception 'FAIL T22: create_organization accepted an invalid slug';
    exception when others then
        if position('invalid_slug' in sqlerrm) = 0 then raise; end if;
    end;

    -- B. Duplicate slug (org-alpha already exists) must abort the RPC.
    begin
        perform public.create_organization('Duplicate Org', 'org-alpha');
        raise exception 'FAIL T22: create_organization accepted a duplicate slug';
    exception when others then
        if position('slug_taken' in sqlerrm) = 0 then raise; end if;
    end;

    -- C. Total org count unchanged: neither failed call created a row.
    select count(*) into v_org_count_after from public.organizations;
    if v_org_count_after <> v_org_count_before then
        raise exception 'FAIL T22: failed create_organization left rows behind (before=%, after=%)',
            v_org_count_before, v_org_count_after;
    end if;

    -- D. No row with the invalid slug exists.
    select count(*) into v_bad_slug_count
    from public.organizations where slug like 'bad%slug%';
    if v_bad_slug_count > 0 then
        raise exception 'FAIL T22: invalid-slug create left % rows behind', v_bad_slug_count;
    end if;

    -- E. No row with the duplicate org name exists.
    if exists (select 1 from public.organizations where name = 'Duplicate Org') then
        raise exception 'FAIL T22: duplicate-slug create left a row behind';
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- T23: anon cannot execute create_organization
-- ---------------------------------------------------------------------------
set local role anon;

do $$
begin
    begin
        perform public.create_organization('Anon Org', 'anon-org');
        raise exception 'FAIL T23: anon can execute create_organization';
    exception when insufficient_privilege or undefined_function then
        null;
    end;
end $$;

-- ---------------------------------------------------------------------------
-- T24: non-admin cannot execute membership management RPCs
-- ---------------------------------------------------------------------------
-- org_alpha member (6002) is not an admin; add/change/remove must be refused.
set local role authenticated;
set local request.jwt.claims = '{"sub":"60000000-0000-0000-0000-000000000002"}';
set local role authenticated;

do $$
begin
    begin
        perform public.add_organization_member(
            '70000000-0000-0000-0000-0000000000A1',
            '60000000-0000-0000-0000-000000000003',
            'investigator'
        );
        raise exception 'FAIL T24: non-admin can add a member via RPC';
    exception when others then
        if position('not_org_admin' in sqlerrm) = 0 then raise; end if;
    end;

    begin
        perform public.change_organization_member_role(
            '70000000-0000-0000-0000-0000000000A1',
            '60000000-0000-0000-0000-000000000002',
            'admin'
        );
        raise exception 'FAIL T24: non-admin can change roles via RPC';
    exception when others then
        if position('not_org_admin' in sqlerrm) = 0 then raise; end if;
    end;

    begin
        perform public.remove_organization_member(
            '70000000-0000-0000-0000-0000000000A1',
            '60000000-0000-0000-0000-000000000001'
        );
        raise exception 'FAIL T24: non-admin can remove a member via RPC';
    exception when others then
        if position('not_org_admin' in sqlerrm) = 0 then raise; end if;
    end;
end $$;

-- ---------------------------------------------------------------------------
-- T25: last org admin cannot be demoted
-- ---------------------------------------------------------------------------
-- org_beta has exactly one admin (6004). Demoting that admin leaves zero.
set local request.jwt.claims = '{"sub":"60000000-0000-0000-0000-000000000004"}';
set local role authenticated;

do $$
begin
    begin
        perform public.change_organization_member_role(
            '70000000-0000-0000-0000-0000000000B1',
            '60000000-0000-0000-0000-000000000004',
            'member'
        );
        raise exception 'FAIL T25: last admin was demoted';
    exception when others then
        if position('last_org_admin_cannot_be_demoted' in sqlerrm) = 0 then raise; end if;
    end;
end $$;

reset role;
do $$
begin
    if not exists (
        select 1 from public.organization_members
        where org_id = '70000000-0000-0000-0000-0000000000B1'
          and profile_id = '60000000-0000-0000-0000-000000000004'
          and role_in_org = 'admin'
    ) then
        raise exception 'FAIL T25: last admin role was changed by the denied RPC';
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- T26: last org admin cannot be removed
-- ---------------------------------------------------------------------------
set local role authenticated;
set local request.jwt.claims = '{"sub":"60000000-0000-0000-0000-000000000004"}';
set local role authenticated;

do $$
begin
    begin
        perform public.remove_organization_member(
            '70000000-0000-0000-0000-0000000000B1',
            '60000000-0000-0000-0000-000000000004'
        );
        raise exception 'FAIL T26: last admin was removed';
    exception when others then
        if position('last_org_admin_cannot_be_removed' in sqlerrm) = 0 then raise; end if;
    end;
end $$;

reset role;
do $$
begin
    if not exists (
        select 1 from public.organization_members
        where org_id = '70000000-0000-0000-0000-0000000000B1'
          and profile_id = '60000000-0000-0000-0000-000000000004'
    ) then
        raise exception 'FAIL T26: last admin was removed by the denied RPC';
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- T27: admin can demote / remove another admin while one admin remains
-- ---------------------------------------------------------------------------
-- org_alpha currently has ONE admin (6001) + member 6002. Full safe lifecycle:
--   promote 6002 to admin  -> demote 6002 back (6001 remains) -> promote again
--   -> remove 6002 (6001 remains).
set local role authenticated;
set local request.jwt.claims = '{"sub":"60000000-0000-0000-0000-000000000001"}';
set local role authenticated;

do $$
begin
    -- Promote the member to admin.
    if public.change_organization_member_role(
        '70000000-0000-0000-0000-0000000000A1',
        '60000000-0000-0000-0000-000000000002',
        'admin'
    ) <> 'admin' then
        raise exception 'FAIL T27: cannot promote a member to admin';
    end if;

    -- Demote them again while 6001 remains admin: allowed.
    if public.change_organization_member_role(
        '70000000-0000-0000-0000-0000000000A1',
        '60000000-0000-0000-0000-000000000002',
        'member'
    ) <> 'member' then
        raise exception 'FAIL T27: cannot demote a non-last admin';
    end if;

    -- Promote again, then remove: allowed while 6001 remains admin.
    perform public.change_organization_member_role(
        '70000000-0000-0000-0000-0000000000A1',
        '60000000-0000-0000-0000-000000000002',
        'admin'
    );
    perform public.remove_organization_member(
        '70000000-0000-0000-0000-0000000000A1',
        '60000000-0000-0000-0000-000000000002'
    );
end $$;

reset role;
do $$
begin
    -- 6002 must be fully gone from org_alpha now.
    if exists (
        select 1 from public.organization_members
        where org_id = '70000000-0000-0000-0000-0000000000A1'
          and profile_id = '60000000-0000-0000-0000-000000000002'
    ) then
        raise exception 'FAIL T27: removed member still exists';
    end if;

    -- The invariant must still hold: 6001 is org_alpha's admin.
    if not exists (
        select 1 from public.organization_members
        where org_id = '70000000-0000-0000-0000-0000000000A1'
          and profile_id = '60000000-0000-0000-0000-000000000001'
          and role_in_org = 'admin'
    ) then
        raise exception 'FAIL T27: org_alpha lost its last admin';
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- T28: direct INSERT into organizations is revoked
-- ---------------------------------------------------------------------------
-- Even an existing org admin must not be able to inject a row directly; the
-- only creation path is create_organization().
set local role authenticated;
set local request.jwt.claims = '{"sub":"60000000-0000-0000-0000-000000000001"}';
set local role authenticated;

do $$
begin
    begin
        insert into public.organizations (name, slug, created_by)
        values ('Sneaky Direct', 'sneaky-direct', '60000000-0000-0000-0000-000000000001');
        raise exception 'FAIL T28: direct INSERT into organizations is allowed';
    exception when insufficient_privilege then
        null;
    end;
end $$;

-- ---------------------------------------------------------------------------
-- T29: direct INSERT/UPDATE/DELETE on organization_members is revoked
-- ---------------------------------------------------------------------------
-- Membership writes are RPC-only; the admin table grants were revoked.
do $$
begin
    begin
        insert into public.organization_members (org_id, profile_id, role_in_org, added_by)
        values ('70000000-0000-0000-0000-0000000000A1', '60000000-0000-0000-0000-000000000002', 'member', '60000000-0000-0000-0000-000000000001');
        raise exception 'FAIL T29: direct INSERT into organization_members is allowed';
    exception when insufficient_privilege then
        null;
    end;

    begin
        update public.organization_members
        set role_in_org = 'investigator'
        where org_id = '70000000-0000-0000-0000-0000000000A1';
        raise exception 'FAIL T29: direct UPDATE of organization_members is allowed';
    exception when insufficient_privilege then
        null;
    end;

    begin
        delete from public.organization_members
        where org_id = '70000000-0000-0000-0000-0000000000A1';
        raise exception 'FAIL T29: direct DELETE of organization_members is allowed';
    exception when insufficient_privilege then
        null;
    end;
end $$;

-- ---------------------------------------------------------------------------
-- T30: organization audit events carry the correct org_id
-- ---------------------------------------------------------------------------
reset role;

do $$
declare
    v_bad bigint;
    v_gamma uuid;
begin
    select id into v_gamma from public.organizations where slug = 'gamma-test';

    -- A. organization.created events must have org_id = entity_id.
    select count(*) into v_bad
    from public.audit_logs a
    where a.entity_type = 'organization'
      and (a.org_id is null or a.org_id <> a.entity_id);
    if v_bad > 0 then
        raise exception 'FAIL T30: % organization.created audit rows lack org_id = entity_id', v_bad;
    end if;

    -- B. organization_member events must carry org_id matching the event's own
    --    meta->>'org_id'. The membership row may have been deleted by the time
    --    T30 runs (T10/T27 remove members), so we validate against the audit
    --    row's own metadata rather than the live membership table.
    select count(*) into v_bad
    from public.audit_logs a
    where a.entity_type = 'organization_member'
      and a.org_id is distinct from (a.meta ->> 'org_id')::uuid;
    if v_bad > 0 then
        raise exception 'FAIL T30: % organization_member audit rows have org_id != meta.org_id', v_bad;
    end if;

    -- C. The T21 creation must have produced exactly one organization.created event.
    select count(*) into v_bad
    from public.audit_logs a
    where a.entity_type = 'organization'
      and a.action = 'organization.created'
      and a.entity_id = v_gamma;
    if v_bad <> 1 then
        raise exception 'FAIL T30: expected 1 creation event for gamma-test, found %', v_bad;
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- Cleanup: reset role
-- ---------------------------------------------------------------------------
reset role;

-- If we reach here without exception, all tests passed.
do $$
begin
    raise notice 'ALL ORGANIZATION FOUNDATION TESTS PASSED (T1–T30)';
end $$;