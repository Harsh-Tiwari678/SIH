-- =============================================================================
-- SIH26190 Secure Evidence — M1: organization administrative read hardening
--
-- Verifies 20260921000000_organization_admin_read_hardening.sql:
--
--   list_organization_members / list_organization_audit_events /
--   lookup_profiles_for_organization now authorize on the caller's CURRENT
--   organization membership with role_in_org = 'admin'. General membership,
--   investigator membership, case roles and system roles grant nothing.
--   Denied callers (non-member, member, investigator, stale member) all receive
--   the same 'org_not_found'.
--
-- What is preserved (regression surface):
--   * org admins list members / audit events / search candidates
--   * add / change-role / remove member workflows + last-admin protection
--   * lookup returns only id/full_name/badge_number, capped at 10, and never
--     returns profiles already in the target org
--
-- HOW TO RUN (single transaction required — relies on set local):
--   supabase db reset
--   psql "$SUPABASE_DB_URL" -1 -v ON_ERROR_STOP=1 \
--       -f supabase/tests/organization_admin_read_hardening.sql
--
-- Every test either passes silently or aborts with `FAIL TM<n>`. The negative
-- tests use the established C1 nested-block/flag pattern: assertions live
-- OUTSIDE the catching block, so a FAIL can never be swallowed by it. If the
-- admin gate is removed, the unauthorized call simply succeeds, v_allowed is
-- set, and the FAIL fires — the tests are non-vacuous.
--
-- Test inventory:
--   TM1   org admin lists the member roster
--   TM2   org member cannot list the roster
--   TM3   org investigator cannot list the roster
--   TM4   non-member cannot list the roster (cross-org + anon)
--   TM5   org admin lists the org audit trail (org + resolved case events)
--   TM6   org member cannot list the org audit trail
--   TM7   org investigator cannot list the org audit trail
--   TM8   non-member cannot list the org audit trail (cross-org + anon)
--   TM9   org admin searches candidate profiles
--   TM10  org member cannot search candidate profiles
--   TM11  org investigator cannot search candidate profiles
--   TM12  non-member cannot search candidate profiles (cross-org + anon)
--   TM13  stale membership (removed org member with live case_members row)
--         cannot authorize ANY of the three RPCs
--   TM14  system role alone (admin/supervisor profiles, no org) cannot bypass
--   TM15  case lead / investigator role alone cannot bypass
--   TM16  lookup exposes only id / full_name / badge_number
--   TM17  lookup never returns profiles already in the target org
--   TM18  member-management workflows still pass (add/change/remove +
--         last-admin protection)
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Test users / fixture ids (deterministic, unique across suites)
-- ---------------------------------------------------------------------------
-- A1  91000000-...-001  M1 Admin Alpha          org_m1 admin (system role officer)
-- A2  91000000-...-002  M1 Member Beta          org_m1 member, ALSO case lead of C_M1
-- A3  91000000-...-003  M1 Investigator Gamma   org_m1 investigator + case investigator
-- A4  91000000-...-004  M1 Member Delta         org_m1 member + case investigator;
--                                               removed in TM18 -> stale case row
-- A5  91000000-...-005  M2 Member Epsilon       org_m2 member (cross-org / non-member)
-- A6  91000000-...-006  Sys Admin NoOrg         system role 'admin', NO org membership
-- A7  91000000-...-007  Sys Supv NoOrg          system role 'supervisor', NO org membership
-- A8  91000000-...-008  (reserved; org-less case roles do not exist in this
--                       model — the org boundary requires case members to be
--                       org members, and TM15 proves case roles never elevate)
-- A9  91000000-...-009  Findable Candidate      no org (full_name search target)
-- A10 91000000-...-00A  Another Candidate       no org (badge search target)
-- org_m1 92000000-0000-0000-0000-0000000000A1
-- org_m2 92000000-0000-0000-0000-0000000000B1
-- C_M1   93000000-0000-0000-0000-0000000000A1  (org_m1)
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- Fixtures (run as the owner / postgres; RLS is bypassed for the writer)
-- ---------------------------------------------------------------------------

insert into auth.users (id, email, encrypted_password, email_confirmed_at, raw_app_meta_data, created_at, updated_at)
values
  ('91000000-0000-0000-0000-000000000001', 'ih.a1@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('91000000-0000-0000-0000-000000000002', 'ih.a2@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('91000000-0000-0000-0000-000000000003', 'ih.a3@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('91000000-0000-0000-0000-000000000004', 'ih.a4@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('91000000-0000-0000-0000-000000000005', 'ih.a5@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('91000000-0000-0000-0000-000000000006', 'ih.a6@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('91000000-0000-0000-0000-000000000007', 'ih.a7@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('91000000-0000-0000-0000-000000000009', 'ih.a9@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('91000000-0000-0000-0000-00000000000A', 'ih.a10@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now());

-- handle_new_user auto-creates each profile as 'New Officer'/'officer'; upsert
-- so the fixture identity is exact. A6/A7 carry system roles admin/supervisor.
insert into public.profiles (id, full_name, badge_number, role)
values
  ('91000000-0000-0000-0000-000000000001', 'M1 Admin Alpha',        null,            'officer'),
  ('91000000-0000-0000-0000-000000000002', 'M1 Member Beta',        'M1-MEM-0002',   'officer'),
  ('91000000-0000-0000-0000-000000000003', 'M1 Investigator Gamma', null,            'officer'),
  ('91000000-0000-0000-0000-000000000004', 'M1 Member Delta',       null,            'officer'),
  ('91000000-0000-0000-0000-000000000005', 'M2 Member Epsilon',     null,            'officer'),
  ('91000000-0000-0000-0000-000000000006', 'Sys Admin NoOrg',       null,            'admin'),
  ('91000000-0000-0000-0000-000000000007', 'Sys Supv NoOrg',        null,            'supervisor'),
  ('91000000-0000-0000-0000-000000000009', 'Findable Candidate',    'M1-CAND-0009',  'officer'),
  ('91000000-0000-0000-0000-00000000000A', 'Another Candidate',     'M1-CAND-000A',  'officer')
on conflict (id) do update
    set full_name    = excluded.full_name,
        badge_number = excluded.badge_number,
        role         = excluded.role;

insert into public.organizations (id, name, slug, created_by)
values
  ('92000000-0000-0000-0000-0000000000A1', 'Org M1', 'ih-m1', '91000000-0000-0000-0000-000000000001'),
  ('92000000-0000-0000-0000-0000000000B1', 'Org M2', 'ih-m2', '91000000-0000-0000-0000-000000000005');

insert into public.organization_members (org_id, profile_id, role_in_org, added_by)
values
  ('92000000-0000-0000-0000-0000000000A1', '91000000-0000-0000-0000-000000000001', 'admin',        '91000000-0000-0000-0000-000000000001'),
  ('92000000-0000-0000-0000-0000000000A1', '91000000-0000-0000-0000-000000000002', 'member',       '91000000-0000-0000-0000-000000000001'),
  ('92000000-0000-0000-0000-0000000000A1', '91000000-0000-0000-0000-000000000003', 'investigator', '91000000-0000-0000-0000-000000000001'),
  ('92000000-0000-0000-0000-0000000000A1', '91000000-0000-0000-0000-000000000004', 'member',       '91000000-0000-0000-0000-000000000001'),
  ('92000000-0000-0000-0000-0000000000B1', '91000000-0000-0000-0000-000000000005', 'member',       '91000000-0000-0000-0000-000000000005');

insert into public.cases (id, org_id, case_number, title, description, status, created_by)
values
  ('93000000-0000-0000-0000-0000000000A1', '92000000-0000-0000-0000-0000000000A1', 'IH-CASE-A1', 'M1 admin hardening case', null, 'active', '91000000-0000-0000-0000-000000000002');

-- A2 lead, A3 investigator, A4 investigator. A4's row becomes STALE after TM18
-- removes A4 from org_m1 (TM13 proves it authorizes nothing).
insert into public.case_members (case_id, profile_id, role_in_case, added_by)
values
  ('93000000-0000-0000-0000-0000000000A1', '91000000-0000-0000-0000-000000000002', 'lead',         '91000000-0000-0000-0000-000000000002'),
  ('93000000-0000-0000-0000-0000000000A1', '91000000-0000-0000-0000-000000000003', 'investigator', '91000000-0000-0000-0000-000000000002'),
  ('93000000-0000-0000-0000-0000000000A1', '91000000-0000-0000-0000-000000000004', 'investigator', '91000000-0000-0000-0000-000000000002');

-- Audit fixture rows (mirror real writers: 'case' rows store org only in meta).
insert into public.audit_logs (actor_id, action, entity_type, entity_id, after, org_id, meta)
values
  ('91000000-0000-0000-0000-000000000001', 'organization.created', 'organization', '92000000-0000-0000-0000-0000000000A1', null, '92000000-0000-0000-0000-0000000000A1', jsonb_build_object('name', 'Org M1')),
  ('91000000-0000-0000-0000-000000000002', 'case.created',         'case',         '93000000-0000-0000-0000-0000000000A1', null, null, jsonb_build_object('case_number', 'IH-CASE-A1'));

-- =============================================================================
-- TM1 — org admin lists the member roster
-- =============================================================================
set local role authenticated;
set local request.jwt.claims = '{"sub":"91000000-0000-0000-0000-000000000001"}';

do $$
declare
    v_n         integer;
    v_has_admin boolean;
begin
    select count(*) into v_n
    from public.list_organization_members('92000000-0000-0000-0000-0000000000A1');
    if v_n <> 4 then
        raise exception 'FAIL TM1: org_m1 roster has % rows, expected 4', v_n;
    end if;

    select bool_or(m.role_in_org = 'admin') into v_has_admin
    from public.list_organization_members('92000000-0000-0000-0000-0000000000A1') m;
    if not v_has_admin then
        raise exception 'FAIL TM1: roster has no admin row';
    end if;
end $$;

-- =============================================================================
-- TM2 — org member cannot list the roster
-- =============================================================================
set local request.jwt.claims = '{"sub":"91000000-0000-0000-0000-000000000002"}';

do $$
declare
    v_allowed   boolean := false;
    v_unexpected text   := null;
begin
    begin
        perform public.list_organization_members('92000000-0000-0000-0000-0000000000A1');
        v_allowed := true;
    exception when others then
        if sqlerrm not like '%org_not_found%' then
            v_unexpected := sqlerrm;
        end if;
    end;
    if v_allowed then
        raise exception 'FAIL TM2: org member listed the roster';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL TM2: unexpected error: %', v_unexpected;
    end if;
end $$;

-- =============================================================================
-- TM3 — org investigator cannot list the roster
-- =============================================================================
set local request.jwt.claims = '{"sub":"91000000-0000-0000-0000-000000000003"}';

do $$
declare
    v_allowed   boolean := false;
    v_unexpected text   := null;
begin
    begin
        perform public.list_organization_members('92000000-0000-0000-0000-0000000000A1');
        v_allowed := true;
    exception when others then
        if sqlerrm not like '%org_not_found%' then
            v_unexpected := sqlerrm;
        end if;
    end;
    if v_allowed then
        raise exception 'FAIL TM3: org investigator listed the roster';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL TM3: unexpected error: %', v_unexpected;
    end if;
end $$;

-- =============================================================================
-- TM4 — non-member cannot list the roster (cross-org member + anon)
-- =============================================================================
set local request.jwt.claims = '{"sub":"91000000-0000-0000-0000-000000000005"}';

do $$
declare
    v_allowed   boolean := false;
    v_unexpected text   := null;
begin
    begin
        perform public.list_organization_members('92000000-0000-0000-0000-0000000000A1');
        v_allowed := true;
    exception when others then
        if sqlerrm not like '%org_not_found%' then
            v_unexpected := sqlerrm;
        end if;
    end;
    if v_allowed then
        raise exception 'FAIL TM4: cross-org member listed org_m1''s roster';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL TM4: unexpected error: %', v_unexpected;
    end if;
end $$;

set local role anon;
set local request.jwt.claims = '{"sub": null, "role": "anon"}';

do $$
declare
    v_allowed   boolean := false;
    v_unexpected text   := null;
begin
    begin
        perform public.list_organization_members('92000000-0000-0000-0000-0000000000A1');
        v_allowed := true;
    exception
        when insufficient_privilege or undefined_function then
            null; -- EXECUTE revoked from anon: expected
        when others then
            v_unexpected := sqlerrm;
    end;
    if v_allowed then
        raise exception 'FAIL TM4: anon listed the roster';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL TM4: unexpected error: %', v_unexpected;
    end if;
end $$;

-- =============================================================================
-- TM5 — org admin lists the org audit trail
-- =============================================================================
set local role authenticated;
set local request.jwt.claims = '{"sub":"91000000-0000-0000-0000-000000000001"}';

do $$
declare
    v_n           integer;
    v_has_org_ev  boolean;
    v_has_case_ev boolean;
begin
    select count(*) into v_n
    from public.list_organization_audit_events('92000000-0000-0000-0000-0000000000A1');
    if v_n < 2 then
        raise exception 'FAIL TM5: org trail too small (%)', v_n;
    end if;

    select bool_or(e.entity_type = 'organization' and e.entity_label = 'Org M1')
    into v_has_org_ev
    from public.list_organization_audit_events('92000000-0000-0000-0000-0000000000A1') e;
    if not v_has_org_ev then
        raise exception 'FAIL TM5: organization.created event missing from trail';
    end if;

    select bool_or(e.entity_type = 'case' and e.entity_label = 'M1 admin hardening case')
    into v_has_case_ev
    from public.list_organization_audit_events('92000000-0000-0000-0000-0000000000A1') e;
    if not v_has_case_ev then
        raise exception 'FAIL TM5: case.created event not resolved into the org trail';
    end if;
end $$;

-- =============================================================================
-- TM6 — org member cannot list the org audit trail
-- =============================================================================
set local request.jwt.claims = '{"sub":"91000000-0000-0000-0000-000000000002"}';

do $$
declare
    v_allowed   boolean := false;
    v_unexpected text   := null;
begin
    begin
        perform public.list_organization_audit_events('92000000-0000-0000-0000-0000000000A1');
        v_allowed := true;
    exception when others then
        if sqlerrm not like '%org_not_found%' then
            v_unexpected := sqlerrm;
        end if;
    end;
    if v_allowed then
        raise exception 'FAIL TM6: org member read the org audit trail';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL TM6: unexpected error: %', v_unexpected;
    end if;
end $$;

-- =============================================================================
-- TM7 — org investigator cannot list the org audit trail
-- =============================================================================
set local request.jwt.claims = '{"sub":"91000000-0000-0000-0000-000000000003"}';

do $$
declare
    v_allowed   boolean := false;
    v_unexpected text   := null;
begin
    begin
        perform public.list_organization_audit_events('92000000-0000-0000-0000-0000000000A1');
        v_allowed := true;
    exception when others then
        if sqlerrm not like '%org_not_found%' then
            v_unexpected := sqlerrm;
        end if;
    end;
    if v_allowed then
        raise exception 'FAIL TM7: org investigator read the org audit trail';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL TM7: unexpected error: %', v_unexpected;
    end if;
end $$;

-- =============================================================================
-- TM8 — non-member cannot list the org audit trail (cross-org member + anon)
-- =============================================================================
set local request.jwt.claims = '{"sub":"91000000-0000-0000-0000-000000000005"}';

do $$
declare
    v_allowed   boolean := false;
    v_unexpected text   := null;
begin
    begin
        perform public.list_organization_audit_events('92000000-0000-0000-0000-0000000000A1');
        v_allowed := true;
    exception when others then
        if sqlerrm not like '%org_not_found%' then
            v_unexpected := sqlerrm;
        end if;
    end;
    if v_allowed then
        raise exception 'FAIL TM8: cross-org member read org_m1''s audit trail';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL TM8: unexpected error: %', v_unexpected;
    end if;
end $$;

set local role anon;
set local request.jwt.claims = '{"sub": null, "role": "anon"}';

do $$
declare
    v_allowed   boolean := false;
    v_unexpected text   := null;
begin
    begin
        perform public.list_organization_audit_events('92000000-0000-0000-0000-0000000000A1');
        v_allowed := true;
    exception
        when insufficient_privilege or undefined_function then
            null; -- EXECUTE revoked from anon: expected
        when others then
            v_unexpected := sqlerrm;
    end;
    if v_allowed then
        raise exception 'FAIL TM8: anon read the org audit trail';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL TM8: unexpected error: %', v_unexpected;
    end if;
end $$;

-- =============================================================================
-- TM9 — org admin searches candidate profiles
-- =============================================================================
set local role authenticated;
set local request.jwt.claims = '{"sub":"91000000-0000-0000-0000-000000000001"}';

do $$
declare
    v_n integer;
begin
    select count(*) into v_n
    from public.lookup_profiles_for_organization(
        '92000000-0000-0000-0000-0000000000A1', 'Candidate');
    if v_n <> 2 then
        raise exception 'FAIL TM9: admin candidate search returned %, expected 2', v_n;
    end if;
end $$;

-- =============================================================================
-- TM10 — org member cannot search candidate profiles
-- =============================================================================
set local request.jwt.claims = '{"sub":"91000000-0000-0000-0000-000000000002"}';

do $$
declare
    v_allowed   boolean := false;
    v_unexpected text   := null;
begin
    begin
        perform public.lookup_profiles_for_organization(
            '92000000-0000-0000-0000-0000000000A1', 'Candidate');
        v_allowed := true;
    exception when others then
        if sqlerrm not like '%org_not_found%' then
            v_unexpected := sqlerrm;
        end if;
    end;
    if v_allowed then
        raise exception 'FAIL TM10: org member searched candidate profiles';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL TM10: unexpected error: %', v_unexpected;
    end if;
end $$;

-- =============================================================================
-- TM11 — org investigator cannot search candidate profiles
-- =============================================================================
set local request.jwt.claims = '{"sub":"91000000-0000-0000-0000-000000000003"}';

do $$
declare
    v_allowed   boolean := false;
    v_unexpected text   := null;
begin
    begin
        perform public.lookup_profiles_for_organization(
            '92000000-0000-0000-0000-0000000000A1', 'Candidate');
        v_allowed := true;
    exception when others then
        if sqlerrm not like '%org_not_found%' then
            v_unexpected := sqlerrm;
        end if;
    end;
    if v_allowed then
        raise exception 'FAIL TM11: org investigator searched candidate profiles';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL TM11: unexpected error: %', v_unexpected;
    end if;
end $$;

-- =============================================================================
-- TM12 — non-member cannot search candidate profiles (cross-org member + anon)
-- =============================================================================
set local request.jwt.claims = '{"sub":"91000000-0000-0000-0000-000000000005"}';

do $$
declare
    v_allowed   boolean := false;
    v_unexpected text   := null;
begin
    begin
        perform public.lookup_profiles_for_organization(
            '92000000-0000-0000-0000-0000000000A1', 'Candidate');
        v_allowed := true;
    exception when others then
        if sqlerrm not like '%org_not_found%' then
            v_unexpected := sqlerrm;
        end if;
    end;
    if v_allowed then
        raise exception 'FAIL TM12: cross-org member searched org_m1 candidates';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL TM12: unexpected error: %', v_unexpected;
    end if;
end $$;

set local role anon;
set local request.jwt.claims = '{"sub": null, "role": "anon"}';

do $$
declare
    v_allowed   boolean := false;
    v_unexpected text   := null;
begin
    begin
        perform public.lookup_profiles_for_organization(
            '92000000-0000-0000-0000-0000000000A1', 'Candidate');
        v_allowed := true;
    exception
        when insufficient_privilege or undefined_function then
            null; -- EXECUTE revoked from anon: expected
        when others then
            v_unexpected := sqlerrm;
    end;
    if v_allowed then
        raise exception 'FAIL TM12: anon searched candidate profiles';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL TM12: unexpected error: %', v_unexpected;
    end if;
end $$;

-- =============================================================================
-- TM14 — system role alone cannot bypass organization-admin authorization.
-- A6 holds the SYSTEM role 'admin' and A7 the system role 'supervisor'; neither
-- has any organization membership. They must be denied identically, proving
-- profiles.role and organization_members.role_in_org are separate worlds.
-- (TM13 comes after TM18, which creates A4's stale-membership state.)
-- =============================================================================
set local role authenticated;
set local request.jwt.claims = '{"sub":"91000000-0000-0000-0000-000000000006"}';

do $$
declare
    v_allowed   boolean := false;
    v_unexpected text   := null;
begin
    begin
        perform public.list_organization_members('92000000-0000-0000-0000-0000000000A1');
        v_allowed := true;
    exception when others then
        if sqlerrm not like '%org_not_found%' then
            v_unexpected := sqlerrm;
        end if;
    end;
    if v_allowed then
        raise exception 'FAIL TM14: system admin listed a roster';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL TM14: unexpected error: %', v_unexpected;
    end if;
end $$;

do $$
declare
    v_allowed   boolean := false;
    v_unexpected text   := null;
begin
    begin
        perform public.list_organization_audit_events('92000000-0000-0000-0000-0000000000A1');
        v_allowed := true;
    exception when others then
        if sqlerrm not like '%org_not_found%' then
            v_unexpected := sqlerrm;
        end if;
    end;
    if v_allowed then
        raise exception 'FAIL TM14: system admin read an org audit trail';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL TM14: unexpected error: %', v_unexpected;
    end if;
end $$;

do $$
declare
    v_allowed   boolean := false;
    v_unexpected text   := null;
begin
    begin
        perform public.lookup_profiles_for_organization(
            '92000000-0000-0000-0000-0000000000A1', 'Candidate');
        v_allowed := true;
    exception when others then
        if sqlerrm not like '%org_not_found%' then
            v_unexpected := sqlerrm;
        end if;
    end;
    if v_allowed then
        raise exception 'FAIL TM14: system admin searched candidates';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL TM14: unexpected error: %', v_unexpected;
    end if;
end $$;

set local request.jwt.claims = '{"sub":"91000000-0000-0000-0000-000000000007"}';

do $$
declare
    v_allowed   boolean := false;
    v_unexpected text   := null;
begin
    begin
        perform public.list_organization_members('92000000-0000-0000-0000-0000000000A1');
        v_allowed := true;
    exception when others then
        if sqlerrm not like '%org_not_found%' then
            v_unexpected := sqlerrm;
        end if;
    end;
    if v_allowed then
        raise exception 'FAIL TM14: system supervisor listed a roster';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL TM14: unexpected error: %', v_unexpected;
    end if;
end $$;

do $$
declare
    v_allowed   boolean := false;
    v_unexpected text   := null;
begin
    begin
        perform public.list_organization_audit_events('92000000-0000-0000-0000-0000000000A1');
        v_allowed := true;
    exception when others then
        if sqlerrm not like '%org_not_found%' then
            v_unexpected := sqlerrm;
        end if;
    end;
    if v_allowed then
        raise exception 'FAIL TM14: system supervisor read an org audit trail';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL TM14: unexpected error: %', v_unexpected;
    end if;
end $$;

do $$
declare
    v_allowed   boolean := false;
    v_unexpected text   := null;
begin
    begin
        perform public.lookup_profiles_for_organization(
            '92000000-0000-0000-0000-0000000000A1', 'Candidate');
        v_allowed := true;
    exception when others then
        if sqlerrm not like '%org_not_found%' then
            v_unexpected := sqlerrm;
        end if;
    end;
    if v_allowed then
        raise exception 'FAIL TM14: system supervisor searched candidates';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL TM14: unexpected error: %', v_unexpected;
    end if;
end $$;

-- =============================================================================
-- TM15 — case lead / investigator role alone cannot bypass organization-admin
-- authorization. Case roles (case_members.role_in_case) never factor into the
-- org-admin decision. A2 is org_m1 'member' AND the CASE LEAD of C_M1; A3 is
-- org_m1 'investigator' AND a CASE INVESTIGATOR of C_M1. Both are denied across
-- all three RPCs even though their case roles are real and current.
-- =============================================================================
set local request.jwt.claims = '{"sub":"91000000-0000-0000-0000-000000000002"}';

do $$
begin
    -- sanity: A2 really is the current case lead of C_M1.
    if coalesce(public.case_role('93000000-0000-0000-0000-0000000000A1'), '') <> 'lead' then
        raise exception 'FAIL TM15: fixture stalled — A2 is not the case lead';
    end if;
end $$;

do $$
declare
    v_allowed   boolean := false;
    v_unexpected text   := null;
begin
    begin
        perform public.list_organization_members('92000000-0000-0000-0000-0000000000A1');
        v_allowed := true;
    exception when others then
        if sqlerrm not like '%org_not_found%' then
            v_unexpected := sqlerrm;
        end if;
    end;
    if v_allowed then
        raise exception 'FAIL TM15: case lead listed the roster';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL TM15: unexpected error: %', v_unexpected;
    end if;
end $$;

do $$
declare
    v_allowed   boolean := false;
    v_unexpected text   := null;
begin
    begin
        perform public.list_organization_audit_events('92000000-0000-0000-0000-0000000000A1');
        v_allowed := true;
    exception when others then
        if sqlerrm not like '%org_not_found%' then
            v_unexpected := sqlerrm;
        end if;
    end;
    if v_allowed then
        raise exception 'FAIL TM15: case lead read the audit trail';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL TM15: unexpected error: %', v_unexpected;
    end if;
end $$;

do $$
declare
    v_allowed   boolean := false;
    v_unexpected text   := null;
begin
    begin
        perform public.lookup_profiles_for_organization(
            '92000000-0000-0000-0000-0000000000A1', 'Candidate');
        v_allowed := true;
    exception when others then
        if sqlerrm not like '%org_not_found%' then
            v_unexpected := sqlerrm;
        end if;
    end;
    if v_allowed then
        raise exception 'FAIL TM15: case lead searched candidates';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL TM15: unexpected error: %', v_unexpected;
    end if;
end $$;

-- case investigator (A3): same denial on all three RPCs.
set local request.jwt.claims = '{"sub":"91000000-0000-0000-0000-000000000003"}';

do $$
begin
    if coalesce(public.case_role('93000000-0000-0000-0000-0000000000A1'), '') <> 'investigator' then
        raise exception 'FAIL TM15: fixture stalled — A3 is not the case investigator';
    end if;
end $$;

do $$
declare
    v_allowed   boolean := false;
    v_unexpected text   := null;
begin
    begin
        perform public.list_organization_members('92000000-0000-0000-0000-0000000000A1');
        v_allowed := true;
    exception when others then
        if sqlerrm not like '%org_not_found%' then
            v_unexpected := sqlerrm;
        end if;
    end;
    if v_allowed then
        raise exception 'FAIL TM15: case investigator listed the roster';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL TM15: unexpected error: %', v_unexpected;
    end if;
end $$;

do $$
declare
    v_allowed   boolean := false;
    v_unexpected text   := null;
begin
    begin
        perform public.list_organization_audit_events('92000000-0000-0000-0000-0000000000A1');
        v_allowed := true;
    exception when others then
        if sqlerrm not like '%org_not_found%' then
            v_unexpected := sqlerrm;
        end if;
    end;
    if v_allowed then
        raise exception 'FAIL TM15: case investigator read the audit trail';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL TM15: unexpected error: %', v_unexpected;
    end if;
end $$;

do $$
declare
    v_allowed   boolean := false;
    v_unexpected text   := null;
begin
    begin
        perform public.lookup_profiles_for_organization(
            '92000000-0000-0000-0000-0000000000A1', 'Candidate');
        v_allowed := true;
    exception when others then
        if sqlerrm not like '%org_not_found%' then
            v_unexpected := sqlerrm;
        end if;
    end;
    if v_allowed then
        raise exception 'FAIL TM15: case investigator searched candidates';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL TM15: unexpected error: %', v_unexpected;
    end if;
end $$;

-- =============================================================================
-- TM16 — lookup exposes only id / full_name / badge_number.
-- =============================================================================
set local request.jwt.claims = '{"sub":"91000000-0000-0000-0000-000000000001"}';

do $$
declare
    v_keys text[];
begin
    select array_agg(k order by k) into v_keys
    from (
        select jsonb_object_keys(to_jsonb(c)) as k
        from public.lookup_profiles_for_organization(
            '92000000-0000-0000-0000-0000000000A1', 'Findable Candidate') c
    ) s;
    if v_keys <> array['badge_number', 'full_name', 'id'] then
        raise exception 'FAIL TM16: returned fields % (expected id/full_name/badge_number)', v_keys;
    end if;
end $$;

-- =============================================================================
-- TM17 — lookup never returns profiles already in the target org.
-- =============================================================================
do $$
declare
    v_n integer;
begin
    select count(*) into v_n
    from public.lookup_profiles_for_organization(
        '92000000-0000-0000-0000-0000000000A1', 'M1 Admin Alpha');
    if v_n <> 0 then
        raise exception 'FAIL TM17: current admin returned as candidate';
    end if;

    select count(*) into v_n
    from public.lookup_profiles_for_organization(
        '92000000-0000-0000-0000-0000000000A1', 'M1 Member Beta');
    if v_n <> 0 then
        raise exception 'FAIL TM17: current member returned as candidate';
    end if;

    select count(*) into v_n
    from public.lookup_profiles_for_organization(
        '92000000-0000-0000-0000-0000000000A1', 'M1 Investigator Gamma');
    if v_n <> 0 then
        raise exception 'FAIL TM17: current investigator returned as candidate';
    end if;

    -- a genuinely eligible profile is still found in the same run.
    select count(*) into v_n
    from public.lookup_profiles_for_organization(
        '92000000-0000-0000-0000-0000000000A1', 'M1-CAND-000A');
    if v_n <> 1 then
        raise exception 'FAIL TM17: eligible candidate not found (badge search)';
    end if;
end $$;

-- =============================================================================
-- TM18 — existing member-management workflows still pass (admin-only RPCs).
-- As the org admin: add a cross-org member (multi-org membership is allowed),
-- reject the duplicate, change A4's role, and verify the last-admin protections
-- on A1 still hold. Removing A4 leaves A4's case_members row STALE for TM13.
-- =============================================================================
do $$
declare
    v_member uuid;
    v_role   text;
    v_ok     boolean := false;
begin
    -- add A5 (org_m2 member) to org_m1 as 'member'.
    select public.add_organization_member(
        '92000000-0000-0000-0000-0000000000A1',
        '91000000-0000-0000-0000-000000000005',
        'member'
    ) into v_member;
    if v_member is null then
        raise exception 'FAIL TM18: add_organization_member returned no row';
    end if;

    -- duplicate add must be rejected.
    begin
        perform public.add_organization_member(
            '92000000-0000-0000-0000-0000000000A1',
            '91000000-0000-0000-0000-000000000005',
            'member');
        raise exception 'FAIL TM18: duplicate add succeeded';
    exception when others then
        if sqlerrm not like '%already_org_member%' then
            raise;
        end if;
    end;

    -- change A4 (member) to investigator.
    select public.change_organization_member_role(
        '92000000-0000-0000-0000-0000000000A1',
        '91000000-0000-0000-0000-000000000004',
        'investigator'
    ) into v_role;
    if v_role <> 'investigator' then
        raise exception 'FAIL TM18: role change returned %, expected investigator', v_role;
    end if;

    -- last-admin protections: A1 is the only admin of org_m1.
    begin
        perform public.change_organization_member_role(
            '92000000-0000-0000-0000-0000000000A1',
            '91000000-0000-0000-0000-000000000001',
            'member');
        raise exception 'FAIL TM18: last-admin demotion succeeded';
    exception when others then
        if sqlerrm not like '%last_org_admin_cannot_be_demoted%' then
            raise;
        end if;
    end;

    begin
        perform public.remove_organization_member(
            '92000000-0000-0000-0000-0000000000A1',
            '91000000-0000-0000-0000-000000000001');
        raise exception 'FAIL TM18: last-admin removal succeeded';
    exception when others then
        if sqlerrm not like '%last_org_admin_cannot_be_removed%' then
            raise;
        end if;
    end;

    -- removing ordinary members still works (A4 -> stale case row, A5 cleanup).
    perform public.remove_organization_member(
        '92000000-0000-0000-0000-0000000000A1',
        '91000000-0000-0000-0000-000000000004');
    perform public.remove_organization_member(
        '92000000-0000-0000-0000-0000000000A1',
        '91000000-0000-0000-0000-000000000005');

    -- post-conditions: A4/A5 are out of org_m1, A1 is still the admin.
    if coalesce(public.org_role('92000000-0000-0000-0000-0000000000A1'), '') = 'admin'
       and public.is_org_member('92000000-0000-0000-0000-0000000000A1') is not false then
        v_ok := true;
    end if;
    if not v_ok then
        raise exception 'FAIL TM18: admin still not org_m1 admin after mutations';
    end if;
end $$;

-- TM18 also restored A4's org_m1 membership expectations for TM13 by removing
-- A4 entirely: A4 now has a STALE case_members row on C_M1 and NO org row.

-- =============================================================================
-- TM13 — stale organization membership cannot authorize ANY of the three RPCs.
-- A4 was removed from org_m1 (TM18); the fixture case_members row on C_M1 is
-- still present. Stale membership must grant nothing.
-- =============================================================================
set local request.jwt.claims = '{"sub":"91000000-0000-0000-0000-000000000004"}';

do $$
begin
    -- sanity: A4 is really a stale case member (org row gone, case row present).
    if exists (
        select 1 from public.organization_members
        where org_id = '92000000-0000-0000-0000-0000000000A1'
          and profile_id = '91000000-0000-0000-0000-000000000004'
    ) then
        raise exception 'FAIL TM13: fixture stalled — A4 still in org_m1';
    end if;
    if not exists (
        select 1 from public.case_members
        where case_id = '93000000-0000-0000-0000-0000000000A1'
          and profile_id = '91000000-0000-0000-0000-000000000004'
    ) then
        raise exception 'FAIL TM13: fixture stalled — A4 stale case row missing';
    end if;
end $$;

do $$
declare
    v_allowed   boolean := false;
    v_unexpected text   := null;
begin
    begin
        perform public.list_organization_members('92000000-0000-0000-0000-0000000000A1');
        v_allowed := true;
    exception when others then
        if sqlerrm not like '%org_not_found%' then
            v_unexpected := sqlerrm;
        end if;
    end;
    if v_allowed then
        raise exception 'FAIL TM13: stale member listed the roster';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL TM13: unexpected error: %', v_unexpected;
    end if;
end $$;

do $$
declare
    v_allowed   boolean := false;
    v_unexpected text   := null;
begin
    begin
        perform public.list_organization_audit_events('92000000-0000-0000-0000-0000000000A1');
        v_allowed := true;
    exception when others then
        if sqlerrm not like '%org_not_found%' then
            v_unexpected := sqlerrm;
        end if;
    end;
    if v_allowed then
        raise exception 'FAIL TM13: stale member read the audit trail';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL TM13: unexpected error: %', v_unexpected;
    end if;
end $$;

do $$
declare
    v_allowed   boolean := false;
    v_unexpected text   := null;
begin
    begin
        perform public.lookup_profiles_for_organization(
            '92000000-0000-0000-0000-0000000000A1', 'Candidate');
        v_allowed := true;
    exception when others then
        if sqlerrm not like '%org_not_found%' then
            v_unexpected := sqlerrm;
        end if;
    end;
    if v_allowed then
        raise exception 'FAIL TM13: stale member searched candidates';
    end if;
    if v_unexpected is not null then
        raise exception 'FAIL TM13: unexpected error: %', v_unexpected;
    end if;
end $$;

-- =============================================================================
-- Final integrity sweep (owner context): every case_members row must still
-- point at a CURRENT member of its case's org. TM18 deliberately left A4's
-- stale case row; remove it (test-only), then assert no boundary violation.
-- =============================================================================
reset role;

do $$
declare
    v_bad bigint;
begin
    delete from public.case_members
    where case_id = '93000000-0000-0000-0000-0000000000A1'
      and profile_id = '91000000-0000-0000-0000-000000000004';

    select count(*) into v_bad
    from public.case_members cm
    join public.cases c on c.id = cm.case_id
    where not exists (
        select 1 from public.organization_members om
        where om.org_id = c.org_id and om.profile_id = cm.profile_id
    );
    if v_bad > 0 then
        raise exception 'FAIL TM-final: % case_members rows violate the org boundary', v_bad;
    end if;
end $$;