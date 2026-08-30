-- =============================================================================
-- SIH26190 Secure Evidence — RLS policy migration
--
-- Adds row level security policies plus SECURITY DEFINER read helpers to the
-- seven core tables created by 20260829000000_initial_core_schema.sql.
--
-- Approved design decisions encoded here:
--   * RLS is a database-level defense layer. Route Handler authorization in
--     the application remains mandatory; RLS is not a replacement for it.
--   * Case membership (case_members) is the data-access boundary. Global roles
--     (profiles.role) grant NO blanket access to case data in this MVP.
--   * Evidence, document_versions, chain_of_custody and audit_logs are
--     append-only. They have no UPDATE or DELETE policies.
--   * audit_logs has NO direct INSERT policy. Writes will arrive later through
--     a dedicated SECURITY DEFINER write RPC in the case-workflows milestone,
--     never through client-side table writes.
--   * No service-role usage. No new tables or columns.
--
-- SECURITY DEFINER helpers are the only place a policy inspects case_members /
-- profiles for membership. They run as their owner (postgres) and therefore
-- never re-enter the RLS engine, avoiding infinite policy recursion. search_path
-- is pinned to '' so every identifier in the helper bodies must be
-- schema-qualified, eliminating search_path hijacking.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 0) Re-assert RLS is enabled (idempotent; Supabase may already have enabled it)
-- -----------------------------------------------------------------------------
alter table public.profiles enable row level security;
alter table public.cases enable row level security;
alter table public.case_members enable row level security;
alter table public.evidence enable row level security;
alter table public.document_versions enable row level security;
alter table public.chain_of_custody enable row level security;
alter table public.audit_logs enable row level security;

-- -----------------------------------------------------------------------------
-- 1) SECURITY DEFINER read helpers (avoid RLS recursion)
-- -----------------------------------------------------------------------------

create or replace function public.is_case_member(case_uuid uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $function$
    select exists (
        select 1
        from public.case_members m
        where m.case_id = is_case_member.case_uuid
          and m.profile_id = auth.uid()
    );
$function$;

-- Two-argument variant used when a policy must check whether an arbitrary
-- profile (not necessarily the caller) is a member of the evidence's case,
-- e.g. validating from_profile_id / to_profile_id on chain_of_custody.
-- security definer with search_path = '' so it never re-enters RLS.
create or replace function public.is_case_member(profile_uuid uuid, case_uuid uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $function$
    select exists (
        select 1
        from public.case_members m
        where m.case_id = is_case_member.case_uuid
          and m.profile_id = is_case_member.profile_uuid
    );
$function$;

create or replace function public.case_role(case_uuid uuid)
returns text
language sql
stable
security definer
set search_path = ''
as $function$
    select m.role_in_case
    from public.case_members m
    where m.case_id = case_role.case_uuid
      and m.profile_id = auth.uid();
$function$;

create or replace function public.global_role()
returns text
language sql
stable
security definer
set search_path = ''
as $function$
    select p.role
    from public.profiles p
    where p.id = auth.uid();
$function$;

-- Owned by a trusted role; EXECUTE is locked to authenticated only.
alter function public.is_case_member(uuid) owner to postgres;
alter function public.is_case_member(uuid, uuid) owner to postgres;
alter function public.case_role(uuid) owner to postgres;
alter function public.global_role() owner to postgres;

revoke execute on function public.is_case_member(uuid) from public, anon;
revoke execute on function public.is_case_member(uuid, uuid) from public, anon;
revoke execute on function public.case_role(uuid) from public, anon;
revoke execute on function public.global_role() from public, anon;

grant execute on function public.is_case_member(uuid) to authenticated;
grant execute on function public.is_case_member(uuid, uuid) to authenticated;
grant execute on function public.case_role(uuid) to authenticated;
grant execute on function public.global_role() to authenticated;

-- -----------------------------------------------------------------------------
-- 2) Privileges: anon has zero access; authenticated gets only what the
--    policies and workflows require. Column-level UPDATE grants make immutable
--    identity columns (created_by / uploaded_by / actor_id / role / ids)
--    unmodifiable even through an allowed UPDATE row.
-- -----------------------------------------------------------------------------

revoke all on public.profiles from anon;
grant select, insert on public.profiles to authenticated;
grant update (full_name, badge_number, updated_at) on public.profiles to authenticated;

revoke all on public.cases from anon;
grant select, insert on public.cases to authenticated;
grant update (title, description, status, closed_at, closed_by, updated_at) on public.cases to authenticated;

revoke all on public.case_members from anon;
grant select, insert, delete on public.case_members to authenticated;
grant update (role_in_case) on public.case_members to authenticated;

revoke all on public.evidence from anon;
grant select, insert on public.evidence to authenticated;
grant update (title, description, type, status, updated_at) on public.evidence to authenticated;

revoke all on public.document_versions from anon;
grant select, insert on public.document_versions to authenticated;

revoke all on public.chain_of_custody from anon;
grant select, insert on public.chain_of_custody to authenticated;

revoke all on public.audit_logs from anon;
grant select on public.audit_logs to authenticated;

-- -----------------------------------------------------------------------------
-- 3) Role vocabulary CHECK constraints
--
-- Enforce the RBAC role vocabularies at the database level as defense in
-- depth. Previously these columns were free-form text constrained only by the
-- RLS insert/update policies; a CHECK constraint makes a mistyped or rogue
-- value impossible at any write path, not just the policy-gated ones.
--
-- Both vocabularies are a superset of the values the policies already emit:
--   profiles.role         -> 'officer' on insert (policy-gated); admin /
--                            supervisor are reserved for later provisioning.
--   case_members.role_in_case -> insert/update policies allow only
--                            member / investigator / viewer; 'lead' is granted
--                            only by approved lead-transfer logic later.
-- -----------------------------------------------------------------------------

alter table public.profiles
    add constraint profiles_role_check
    check (role in ('admin', 'supervisor', 'officer'));

alter table public.case_members
    add constraint case_members_role_in_case_check
    check (role_in_case in ('lead', 'investigator', 'member', 'viewer'));

-- -----------------------------------------------------------------------------
-- 4) Policies
-- -----------------------------------------------------------------------------

-- ---------- profiles ----------------------------------------------------------

drop policy if exists "profiles_select_self_or_shared_case" on public.profiles;
create policy "profiles_select_self_or_shared_case"
on public.profiles
for select
to authenticated
using (
    id = auth.uid()
    or exists (
        select 1
        from public.case_members cm
        where cm.profile_id = public.profiles.id
          and public.is_case_member(cm.case_id)
    )
);

drop policy if exists "profiles_insert_own_officer" on public.profiles;
create policy "profiles_insert_own_officer"
on public.profiles
for insert
to authenticated
with check (
    id = auth.uid()
    and role = 'officer'
);

drop policy if exists "profiles_update_own_role_invariant" on public.profiles;
create policy "profiles_update_own_role_invariant"
on public.profiles
for update
to authenticated
using (id = auth.uid())
with check (
    id = auth.uid()
    and role = (select p.role from public.profiles p where p.id = auth.uid())
);

-- DELETE: no policy -> denied

-- ---------- cases -------------------------------------------------------------

drop policy if exists "cases_select_creator_or_member" on public.cases;
create policy "cases_select_creator_or_member"
on public.cases
for select
to authenticated
using (
    created_by = auth.uid()
    or public.is_case_member(id)
);

drop policy if exists "cases_insert_authenticated_own" on public.cases;
create policy "cases_insert_authenticated_own"
on public.cases
for insert
to authenticated
with check (
    created_by = auth.uid()
    and exists (
        select 1 from public.profiles p where p.id = auth.uid()
    )
);

drop policy if exists "cases_update_lead_only" on public.cases;
create policy "cases_update_lead_only"
on public.cases
for update
to authenticated
using (public.case_role(id) = 'lead')
with check (public.case_role(id) = 'lead');

-- DELETE: no policy -> denied

-- ---------- case_members ------------------------------------------------------

drop policy if exists "case_members_select_member_or_self" on public.case_members;
create policy "case_members_select_member_or_self"
on public.case_members
for select
to authenticated
using (
    profile_id = auth.uid()
    or public.is_case_member(case_id)
);

drop policy if exists "case_members_insert_lead_no_self_no_lead" on public.case_members;
create policy "case_members_insert_lead_no_self_no_lead"
on public.case_members
for insert
to authenticated
with check (
    added_by = auth.uid()
    and profile_id <> auth.uid()
    and public.case_role(case_id) = 'lead'
    and role_in_case in ('member', 'investigator', 'viewer')
);

drop policy if exists "case_members_update_lead_others_no_lead" on public.case_members;
create policy "case_members_update_lead_others_no_lead"
on public.case_members
for update
to authenticated
using (
    profile_id <> auth.uid()
    and public.case_role(case_id) = 'lead'
)
with check (
    profile_id <> auth.uid()
    and public.case_role(case_id) = 'lead'
    and role_in_case in ('member', 'investigator', 'viewer')
);

drop policy if exists "case_members_delete_lead_others" on public.case_members;
create policy "case_members_delete_lead_others"
on public.case_members
for delete
to authenticated
using (
    -- Only a case lead can remove another member.
    public.case_role(case_id) = 'lead'
    -- The target cannot be auth.uid() (no self-removal).
    and profile_id <> auth.uid()
    -- The target cannot be a lead (no lead removal through this policy).
    and role_in_case <> 'lead'
);

-- ---------- evidence ----------------------------------------------------------

drop policy if exists "evidence_select_case_members" on public.evidence;
create policy "evidence_select_case_members"
on public.evidence
for select
to authenticated
using (public.is_case_member(case_id));

drop policy if exists "evidence_insert_lead_or_investigator" on public.evidence;
create policy "evidence_insert_lead_or_investigator"
on public.evidence
for insert
to authenticated
with check (
    created_by = auth.uid()
    and public.case_role(case_id) in ('lead', 'investigator')
);

drop policy if exists "evidence_update_lead_or_investigator" on public.evidence;
create policy "evidence_update_lead_or_investigator"
on public.evidence
for update
to authenticated
using (public.case_role(case_id) in ('lead', 'investigator'))
with check (public.case_role(case_id) in ('lead', 'investigator'));

-- DELETE: no policy -> denied

-- ---------- document_versions -------------------------------------------------

drop policy if exists "document_versions_select_member_of_evidence_case" on public.document_versions;
create policy "document_versions_select_member_of_evidence_case"
on public.document_versions
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

drop policy if exists "document_versions_insert_lead_or_investigator" on public.document_versions;
create policy "document_versions_insert_lead_or_investigator"
on public.document_versions
for insert
to authenticated
with check (
    uploaded_by = auth.uid()
    and exists (
        select 1
        from public.evidence e
        where e.id = evidence_id
          and public.case_role(e.case_id) in ('lead', 'investigator')
    )
);

-- UPDATE / DELETE: no policies -> denied

-- ---------- chain_of_custody --------------------------------------------------

drop policy if exists "chain_of_custody_select_member_of_evidence_case" on public.chain_of_custody;
create policy "chain_of_custody_select_member_of_evidence_case"
on public.chain_of_custody
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

drop policy if exists "chain_of_custody_insert_lead_or_investigator" on public.chain_of_custody;
create policy "chain_of_custody_insert_lead_or_investigator"
on public.chain_of_custody
for insert
to authenticated
with check (
    -- Only the acting user can appear as the actor (no forged actor_id).
    actor_id = auth.uid()
    -- The actor must be lead or investigator for the evidence's case.
    and exists (
        select 1
        from public.evidence e
        where e.id = evidence_id
          and public.case_role(e.case_id) in ('lead', 'investigator')
    )
    -- from_profile_id, when set, must belong to the same case.
    and (
        from_profile_id is null
        or exists (
            select 1
            from public.evidence e
            where e.id = evidence_id
              and public.is_case_member(from_profile_id, e.case_id)
        )
    )
    -- to_profile_id, when set, must belong to the same case.
    and (
        to_profile_id is null
        or exists (
            select 1
            from public.evidence e
            where e.id = evidence_id
              and public.is_case_member(to_profile_id, e.case_id)
        )
    )
);

-- UPDATE / DELETE: no policies -> denied

-- ---------- audit_logs --------------------------------------------------------

drop policy if exists "audit_logs_select_admin_or_supervisor" on public.audit_logs;
create policy "audit_logs_select_admin_or_supervisor"
on public.audit_logs
for select
to authenticated
using (public.global_role() in ('admin', 'supervisor'));

-- INSERT / UPDATE / DELETE: no policies -> denied (writes only via future
-- SECURITY DEFINER write RPC, never client-side)