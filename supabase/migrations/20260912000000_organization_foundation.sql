-- =============================================================================
-- SIH26190 Secure Evidence — organization foundation migration
--
-- Introduces organization boundaries into the database schema. This is the
-- first step toward multi-agency support: every case will eventually belong
-- to an organization, and every user will access cases through organization
-- membership.
--
-- Security decisions:
--   * organizations and organization_members have RLS enabled from the start.
--   * is_org_member() and org_role() are SECURITY DEFINER helpers that
--     bypass RLS to check organization_members, following the same pattern
--     as is_case_member() and case_role().
--   * organization_members INSERT/UPDATE/DELETE policies require org admin
--     role. No user can self-assign admin or inject arbitrary membership.
--   * The existing cases RLS policies are NOT modified in this migration.
--     Organization-scoped case authorization will be added in a subsequent
--     migration after this foundation is validated.
--   * The existing case_members, evidence, document_versions, chain_of_custody,
--     blockchain_anchors, storage, and audit-read policies are NOT modified.
--   * Backfill creates a default organization and migrates all existing data
--     so no existing user loses access. On a clean database (zero profiles)
--     the backfill is skipped: nothing exists to migrate, and an organization
--     cannot own itself. FIRST signups create/join orgs via the application.
--   * cases.org_id is set to NOT NULL after backfill to prevent NULL bypass.
--   * audit_logs.org_id remains nullable for system events without an org.
-- =============================================================================

-- =============================================================================
-- PART 1: Create organizations table
-- =============================================================================

create table public.organizations (
    id         uuid primary key default gen_random_uuid(),
    name       text not null,
    slug       text not null unique,
    created_by uuid not null references public.profiles (id) on delete restrict,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

-- =============================================================================
-- PART 2: Create organization_members table
-- =============================================================================

create table public.organization_members (
    id          uuid primary key default gen_random_uuid(),
    org_id      uuid not null references public.organizations (id) on delete restrict,
    profile_id  uuid not null references public.profiles (id) on delete restrict,
    role_in_org text not null default 'member'
                check (role_in_org in ('admin', 'investigator', 'member')),
    added_by    uuid not null references public.profiles (id) on delete restrict,
    added_at    timestamptz not null default now(),
    unique (org_id, profile_id)
);

-- =============================================================================
-- PART 3: Add organization FK to cases (initially nullable for backfill)
-- =============================================================================

alter table public.cases
    add column org_id uuid references public.organizations (id) on delete restrict;

-- =============================================================================
-- PART 4: Add organization FK to audit_logs (nullable for system events)
-- =============================================================================

alter table public.audit_logs
    add column org_id uuid references public.organizations (id) on delete restrict;

-- =============================================================================
-- PART 5: Indexes
-- =============================================================================

-- organizations: slug is already indexed by the UNIQUE constraint.
create index organizations_created_by_idx on public.organizations (created_by);

-- organization_members: composite for membership lookups; profile_id for
-- "which orgs does this user belong to?" queries.
create index organization_members_org_profile_idx
    on public.organization_members (org_id, profile_id);
create index organization_members_profile_id_idx
    on public.organization_members (profile_id);

-- cases: org_id for org-scoped case queries.
create index cases_org_id_idx on public.cases (org_id);

-- audit_logs: org_id for org-scoped audit queries.
create index audit_logs_org_id_created_idx
    on public.audit_logs (org_id, created_at desc);

-- =============================================================================
-- PART 6: SECURITY DEFINER authorization helpers
--
-- Follow the exact pattern of is_case_member() / case_role() / global_role():
--   * SECURITY DEFINER runs as owner (postgres), bypasses RLS.
--   * set search_path = '' prevents search_path hijacking.
--   * Identity derived from auth.uid(), never from parameters.
--   * EXECUTE revoked from public/anon, granted to authenticated only.
-- =============================================================================

create or replace function public.is_org_member(org_uuid uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $function$
    select exists (
        select 1
        from public.organization_members m
        where m.org_id = is_org_member.org_uuid
          and m.profile_id = auth.uid()
    );
$function$;

create or replace function public.org_role(org_uuid uuid)
returns text
language sql
stable
security definer
set search_path = ''
as $function$
    select m.role_in_org
    from public.organization_members m
    where m.org_id = org_role.org_uuid
      and m.profile_id = auth.uid();
$function$;

alter function public.is_org_member(uuid) owner to postgres;
alter function public.org_role(uuid) owner to postgres;

revoke execute on function public.is_org_member(uuid) from public, anon;
revoke execute on function public.org_role(uuid) from public, anon;

grant execute on function public.is_org_member(uuid) to authenticated;
grant execute on function public.org_role(uuid) to authenticated;

-- =============================================================================
-- PART 7: Enable RLS and create policies
-- =============================================================================

alter table public.organizations enable row level security;
alter table public.organization_members enable row level security;

-- ---------- organizations ----------------------------------------------------

-- SELECT: authenticated users see only organizations they belong to.
drop policy if exists "organizations_select_members" on public.organizations;
create policy "organizations_select_members"
on public.organizations
for select
to authenticated
using (public.is_org_member(id));

-- INSERT: any authenticated user may create an organization.
-- The creator becoming admin will be handled atomically by a future
-- create_organization() SECURITY DEFINER RPC. For this migration,
-- the INSERT policy is intentionally permissive: it prevents non-members
-- from creating orgs in the name of other users (created_by = auth.uid()),
-- but does not yet handle atomic membership creation.
drop policy if exists "organizations_insert_authenticated" on public.organizations;
create policy "organizations_insert_authenticated"
on public.organizations
for insert
to authenticated
with check (created_by = auth.uid());

-- UPDATE: organization admin only.
drop policy if exists "organizations_update_admin_only" on public.organizations;
create policy "organizations_update_admin_only"
on public.organizations
for update
to authenticated
using (public.org_role(id) = 'admin')
with check (public.org_role(id) = 'admin');

-- DELETE: no policy -> denied

-- ---------- organization_members ---------------------------------------------

-- SELECT: only members of that organization can see membership rows.
drop policy if exists "organization_members_select_org_members" on public.organization_members;
create policy "organization_members_select_org_members"
on public.organization_members
for select
to authenticated
using (public.is_org_member(org_id));

-- INSERT: organization admin only. added_by must be auth.uid().
-- Self-insert is blocked by the RLS check: a user who is not already an
-- admin of the org cannot insert any membership rows (including their own).
drop policy if exists "organization_members_insert_admin_only" on public.organization_members;
create policy "organization_members_insert_admin_only"
on public.organization_members
for insert
to authenticated
with check (
    added_by = auth.uid()
    and public.org_role(org_id) = 'admin'
);

-- UPDATE: organization admin only.
drop policy if exists "organization_members_update_admin_only" on public.organization_members;
create policy "organization_members_update_admin_only"
on public.organization_members
for update
to authenticated
using (public.org_role(org_id) = 'admin')
with check (public.org_role(org_id) = 'admin');

-- DELETE: organization admin only. Cannot remove yourself through this policy
-- (an admin must remain to prevent org-lockout; self-removal will be handled
-- by a dedicated RPC with safeguards).
drop policy if exists "organization_members_delete_admin_only" on public.organization_members;
create policy "organization_members_delete_admin_only"
on public.organization_members
for delete
to authenticated
using (
    public.org_role(org_id) = 'admin'
    and profile_id <> auth.uid()
);

-- =============================================================================
-- PART 8: Privileges
--
-- Revoke anon from new tables; grant authenticated only the operations
-- the RLS policies permit. Column-level UPDATE grants make identity columns
-- (created_by / added_by / id / org_id) unmodifiable even through an
-- allowed row UPDATE.
-- =============================================================================

revoke all on public.organizations from anon;
grant select, insert on public.organizations to authenticated;
grant update (name, slug, updated_at) on public.organizations to authenticated;

revoke all on public.organization_members from anon;
grant select, insert, delete on public.organization_members to authenticated;
grant update (role_in_org) on public.organization_members to authenticated;

-- =============================================================================
-- PART 9: Table and column comments
-- =============================================================================

comment on table public.organizations is
  'Multi-agency organization boundary. Cases belong to an organization; users access cases through organization membership.';
comment on column public.organizations.name is
  'Human-readable organization name.';
comment on column public.organizations.slug is
  'URL-safe unique identifier for the organization.';
comment on column public.organizations.created_by is
  'Profile that created the organization.';
comment on column public.organizations.updated_at is
  'Last modification timestamp; managed by the application layer.';

comment on table public.organization_members is
  'Many-to-many link between organizations and profiles; carries the org-scoped role used for organization-level authorization.';
comment on column public.organization_members.role_in_org is
  'Organization-scoped role: admin (manage org and members), investigator (full case access), member (basic access). Vocabulary enforced by CHECK constraint.';
comment on column public.organization_members.added_by is
  'Profile that added this member; must be an org admin.';

comment on column public.cases.org_id is
  'Organization this case belongs to. NOT NULL after backfill; enforced by constraint added at the end of this migration.';

comment on column public.audit_logs.org_id is
  'Organization this audit event is associated with. Nullable for system events or events without a clear org scope.';

-- =============================================================================
-- PART 10: Backfill existing data (profile-guarded)
--
-- Two distinct databases must migrate correctly:
--
--   a) Existing database (development / seeded): profiles exist, and cases /
--      audit_logs reference them. A deterministic default organization is
--      created, every existing profile is added to it as admin, and every
--      existing case plus resolvable audit_logs is associated with it. This
--      preserves access for the existing dataset.
--
--   b) Clean database (fresh `supabase db reset`): zero profiles exist. There
--      is nothing to backfill — and because cases / case_members / evidence /
--      document_versions / chain_of_custody / audit_logs actors all FK-close
--      under public.profiles, no case or audit data can exist without a
--      profile either. No default organization is fabricated (there is no
--      real actor to own it): the first users create or join organizations
--      through the application. The entire backfill is skipped so the
--      migration applies cleanly.
--
-- The guard is `exists(select 1 from public.profiles)` — the one condition that
-- distinguishes path (a) from path (b), chosen because organizations.created_by
-- is NOT NULL and must always reference a real profile.
-- =============================================================================

do $$
declare
    v_default_org_id uuid;
begin
    -- Clean database: nothing and nobody to backfill. Skip the whole block so
    -- no NOT NULL violation (and no invented owner) can occur.
    if not exists (select 1 from public.profiles) then
        return;
    end if;

    -- 10a. Create the default organization, owned by the earliest existing
    --      profile. Deterministic: order by created_at, id (id breaks ties
    --      when multiple profiles share the same timestamp).
    insert into public.organizations (name, slug, created_by)
    select
        'Secure Evidence',
        'secure-evidence',
        p.id
    from public.profiles p
    order by p.created_at, p.id
    limit 1
    returning id into v_default_org_id;

    -- 10b. Add every existing profile to the default organization as admin.
    --      ON CONFLICT is defensive: if the migration is re-run partially,
    --      existing memberships are preserved.
    insert into public.organization_members (org_id, profile_id, role_in_org, added_by)
    select
        v_default_org_id,
        p.id,
        'admin',
        p.id
    from public.profiles p
    on conflict (org_id, profile_id) do nothing;

    -- 10c. Set cases.org_id for all existing cases.
    --      Every case belongs to the default organization.
    update public.cases c
    set org_id = v_default_org_id
    where c.org_id is null;

    -- 10d. Propagate org_id to audit_logs through the entity relationship chain.
    --      Verified entity_type vocabulary (from every "insert into
    --      public.audit_logs" site in the codebase):
    --
    --        entity_type        | entity_id =              | org derived via
    --        -------------------+--------------------------+---------------------------
    --        case               | cases.id                 | cases.org_id
    --        case_member        | case_members.id          | meta->>'case_id' -> cases.org_id
    --        evidence           | evidence.id              | evidence.case_id -> cases.org_id
    --        document_version   | document_versions.id     | dv.evidence_id -> evidence.case_id
    --        blockchain_anchor  | blockchain_anchors.id    | ba.evidence_id -> evidence.case_id
    --
    --      Any other entity_type (profile/system events) resolves to NULL and is
    --      excluded by the WHERE clause. A single CASE on entity_type ensures only
    --      the matching branch's correlated subquery runs per row (all are PK
    --      lookups returning 0 or 1 rows).
    update public.audit_logs al
    set org_id = sub.org_id
    from (
        select
            al_inner.id as audit_id,
            case al_inner.entity_type
                when 'case' then
                    (select c.org_id
                     from public.cases c
                     where c.id = al_inner.entity_id)
                when 'case_member' then
                    (select c.org_id
                     from public.cases c
                     where (al_inner.meta ->> 'case_id') is not null
                       and c.id = (al_inner.meta ->> 'case_id')::uuid)
                when 'evidence' then
                    (select c.org_id
                     from public.evidence e
                     join public.cases c on c.id = e.case_id
                     where e.id = al_inner.entity_id)
                when 'document_version' then
                    (select c.org_id
                     from public.document_versions dv
                     join public.evidence e on e.id = dv.evidence_id
                     join public.cases c on c.id = e.case_id
                     where dv.id = al_inner.entity_id)
                when 'blockchain_anchor' then
                    (select c.org_id
                     from public.blockchain_anchors ba
                     join public.evidence e on e.id = ba.evidence_id
                     join public.cases c on c.id = e.case_id
                     where ba.id = al_inner.entity_id)
            end as org_id
        from public.audit_logs al_inner
    ) sub
    where al.id = sub.audit_id
      and sub.org_id is not null
      and al.org_id is null;
end;
$$;

-- =============================================================================
-- PART 11: Finalize constraints after backfill
-- =============================================================================

-- 11a. cases.org_id must be NOT NULL after backfill.
--      If any case somehow lacks an org_id, this will fail and the migration
--      will roll back, preventing orphaned cases.
alter table public.cases
    alter column org_id set not null;

-- =============================================================================
-- PART 12: Verification assertions
--
-- These SELECT queries are intentionally left as comments. When run manually
-- against the migrated database, they confirm data integrity. They do NOT
-- modify data and will NOT cause the migration to fail if omitted.
--
-- To verify after migration:
--   -- Every case has an org_id:
--   SELECT count(*) FROM public.cases WHERE org_id IS NULL;  -- must be 0
--
--   -- Profiles are members of the default org. Only meaningful when the
--   -- default org exists (i.e. profiles existed at migration time); on a
--   -- clean database the backfill was skipped and the org is absent by design:
--   SELECT count(*) FROM public.profiles p
--   WHERE p.id <> ALL (
--       SELECT created_by FROM public.organizations
--   ) AND NOT EXISTS (
--       SELECT 1 FROM public.organization_members om
--       WHERE om.profile_id = p.id
--   );  -- profiles with no membership are expected pre-onboarding
--
--   -- Default org exists exactly when existing data was backfilled:
--   SELECT id, name, slug FROM public.organizations WHERE slug = 'secure-evidence';
--   -- exactly 1 row on an existing-data database; 0 rows on a clean database.
--
--   -- No existing case_members lost:
--   SELECT count(*) FROM public.case_members;  -- unchanged from pre-migration count
--
--   -- No existing evidence lost:
--   SELECT count(*) FROM public.evidence;  -- unchanged from pre-migration count
--
--   -- No existing document_versions lost:
--   SELECT count(*) FROM public.document_versions;  -- unchanged from pre-migration count
--
--   -- No existing blockchain_anchors lost:
--   SELECT count(*) FROM public.blockchain_anchors;  -- unchanged from pre-migration count
--
--   -- No existing audit_logs lost:
--   SELECT count(*) FROM public.audit_logs;  -- unchanged from pre-migration count
--
--   -- (Existing-data path only — skipped on a clean database:)
--   -- All profiles are admin of default org:
--   SELECT count(*) FROM public.organization_members
--   WHERE org_id = (SELECT id FROM public.organizations WHERE slug = 'secure-evidence')
--     AND role_in_org = 'admin';  -- must equal (SELECT count(*) FROM public.profiles)
