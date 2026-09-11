-- =============================================================================
-- SIH26190 Secure Evidence — organization foundation hardening
--
-- Closes the gaps left open by 20260912000000_organization_foundation:
--
--   1. Organization creation moves behind the atomic create_organization()
--      SECURITY DEFINER RPC. Direct INSERT on public.organizations is revoked
--      from authenticated, so the only creation path is the RPC, which always
--      creates the creator's own 'admin' membership in the same transaction.
--      No caller may supply created_by / added_by / role.
--
--   2. Organization-membership management moves behind SECURITY DEFINER RPCs
--      (add_organization_member, change_organization_member_role,
--      remove_organization_member) that enforce the "every org has at least
--      one admin" invariant. Direct INSERT/UPDATE/DELETE on
--      public.organization_members is revoked from authenticated; the direct
--      policies from the foundation migration are dropped so they can never
--      bypass the invariant.
--
--   3. The audit backfill (Part 10d of the foundation migration) is re-run
--      defensively with the correct entity_type mapping so any row left with a
--      NULL org_id still gets one where determinable. The foundation version
--      referenced a nonexistent evidence.org_id column and the fabricated
--      entity_type 'evidence.status_changed'; those are corrected here and in
--      the foundation migration itself.
--
-- Security decisions (unchanged from foundation): helpers and RPCs are
-- SECURITY DEFINER owned by postgres, set search_path = '', identity always
-- from auth.uid() (never from parameters), EXECUTE revoked from public/anon
-- and granted to authenticated. RLS is unchanged for reads (member-scoped) and
-- organization settings updates (admin-only); DELETE on organizations remains
-- impossible (no policy).
-- =============================================================================

-- =============================================================================
-- PART 1: create_organization() — the single, atomic org-creation path
-- =============================================================================

create or replace function public.create_organization(p_name text, p_slug text)
returns uuid
language plpgsql
security definer
set search_path = ''
as $function$
declare
    v_actor  uuid := auth.uid();
    v_name   text := btrim(coalesce(p_name, ''));
    v_slug   text := lower(btrim(coalesce(p_slug, '')));
    v_org_id uuid;
begin
    -- 1) authenticate
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;

    -- 2) authorize: any authenticated profile may create an organization;
    --    the profile must exist (identity is never caller-supplied).
    if not exists (select 1 from public.profiles p where p.id = v_actor) then
        raise exception 'profile_not_found';
    end if;

    -- 3) validate
    if v_name = '' then
        raise exception 'organization_name_required';
    end if;
    if v_slug = '' then
        raise exception 'organization_slug_required';
    end if;
    if length(v_slug) > 63 then
        raise exception 'invalid_slug';
    end if;
    -- URL-safe slug: lowercase letters/digits, single hyphens between segments.
    if not v_slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$' then
        raise exception 'invalid_slug';
    end if;
    if exists (select 1 from public.organizations o where o.slug = v_slug) then
        raise exception 'slug_taken';
    end if;

    -- 4) business logic: create the org and the creator's admin membership in
    --    one transaction. created_by / added_by / role come ONLY from auth.uid().
    insert into public.organizations (name, slug, created_by)
    values (v_name, v_slug, v_actor)
    returning id into v_org_id;

    insert into public.organization_members (org_id, profile_id, role_in_org, added_by)
    values (v_org_id, v_actor, 'admin', v_actor);

    -- 5) audit (same transaction). 'organization' is outside the
    --    case/evidence vocabulary used by the audit read RPCs, so organization
    --    events never pollute case trails.
    insert into public.audit_logs (actor_id, action, entity_type, entity_id, after, meta)
    values (
        v_actor,
        'organization.created',
        'organization',
        v_org_id,
        jsonb_build_object('name', v_name, 'slug', v_slug),
        jsonb_build_object('name', v_name, 'slug', v_slug)
    );

    return v_org_id;
end;
$function$;

alter function public.create_organization(text, text) owner to postgres;
revoke execute on function public.create_organization(text, text) from public, anon;
grant execute on function public.create_organization(text, text) to authenticated;

-- -----------------------------------------------------------------------------
-- Organization creation is RPC-only from now on. The direct INSERT policy from
-- the foundation migration is dropped and the table-level grant revoked so the
-- RPC (which runs as postgres and bypasses RLS) is the only INSERT path.
-- -----------------------------------------------------------------------------
drop policy if exists "organizations_insert_authenticated" on public.organizations;
revoke insert on public.organizations from authenticated;

-- =============================================================================
-- PART 2: Organization membership management RPCs (last-admin invariant)
--
-- Invariant: an organization must always have at least one 'admin' member.
-- Enforced inside these SECURITY DEFINER RPCs (the only permitted writers of
-- organization_members):
--   * add_organization_member: caller must be an existing admin of the org.
--   * change_organization_member_role: caller must be admin; a member with role
--     'admin' cannot be demoted if they are the last admin (including self).
--   * remove_organization_member: caller must be admin; the last admin cannot
--     be removed (including self).
-- Identity is always auth.uid(); target profile_id and role are the only
-- caller-controlled inputs. Every operation is audited in the same
-- transaction. entity_type 'organization_member' (org_id set directly).
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 2a. add_organization_member
-- -----------------------------------------------------------------------------
create or replace function public.add_organization_member(
    p_org_id uuid,
    p_profile_id uuid,
    p_role text
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $function$
declare
    v_actor    uuid := auth.uid();
    v_member   uuid;
    v_norm_role text := lower(btrim(p_role));
begin
    -- 1) authenticate
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;

    -- 2) authorize: actor must be an existing admin of the org.
    if not exists (
        select 1 from public.organization_members m
        where m.org_id = p_org_id
          and m.profile_id = v_actor
          and m.role_in_org = 'admin'
    ) then
        raise exception 'not_org_admin';
    end if;

    -- 3) validate
    if not exists (select 1 from public.organizations o where o.id = p_org_id) then
        raise exception 'organization_not_found';
    end if;
    if not exists (select 1 from public.profiles p where p.id = p_profile_id) then
        raise exception 'profile_not_found';
    end if;
    -- NULL must be rejected explicitly: `x not in (...)` is NULL for NULL x,
    -- and a CHECK constraint is satisfied by a NULL value too.
    if v_norm_role is null or v_norm_role not in ('admin', 'investigator', 'member') then
        raise exception 'role_not_allowed';
    end if;
    if v_norm_role = 'admin' and p_profile_id = v_actor then
        -- redundant (the actor is already an admin), but keep the guard cheap.
        raise exception 'already_org_member';
    end if;
    if exists (
        select 1 from public.organization_members m
        where m.org_id = p_org_id and m.profile_id = p_profile_id
    ) then
        raise exception 'already_org_member';
    end if;

    -- 4) business logic
    insert into public.organization_members (org_id, profile_id, role_in_org, added_by)
    values (p_org_id, p_profile_id, v_norm_role, v_actor)
    returning id into v_member;

    -- 5) audit
    insert into public.audit_logs (actor_id, action, entity_type, entity_id, after, meta)
    values (
        v_actor,
        'organization.member_added',
        'organization_member',
        v_member,
        jsonb_build_object(
            'org_id', p_org_id,
            'profile_id', p_profile_id,
            'role_in_org', v_norm_role
        ),
        jsonb_build_object(
            'org_id', p_org_id,
            'profile_id', p_profile_id,
            'role_in_org', v_norm_role
        )
    );

    return v_member;
end;
$function$;

alter function public.add_organization_member(uuid, uuid, text) owner to postgres;
revoke execute on function public.add_organization_member(uuid, uuid, text) from public, anon;
grant execute on function public.add_organization_member(uuid, uuid, text) to authenticated;

-- -----------------------------------------------------------------------------
-- 2b. change_organization_member_role
-- -----------------------------------------------------------------------------
create or replace function public.change_organization_member_role(
    p_org_id uuid,
    p_profile_id uuid,
    p_new_role text
)
returns text
language plpgsql
security definer
set search_path = ''
as $function$
declare
    v_actor     uuid := auth.uid();
    v_old_role  text;
    v_new_role  text := lower(btrim(p_new_role));
    v_is_last_admin boolean;
begin
    -- 1) authenticate
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;

    -- 2) validate org exists AND lock the organization row to serialize
    --    concurrent last-admin mutations. Two concurrent demotions of the same
    --    org's last admin cannot both pass the count check because the second
    --    transaction blocks here until the first commits or rolls back, then
    --    re-evaluates the fresh admin count in step 5.
    perform 1
    from public.organizations o
    where o.id = p_org_id
    for update;
    if not found then
        raise exception 'organization_not_found';
    end if;

    -- 3) authorize (evaluated after the lock, against fresh state)
    if not exists (
        select 1 from public.organization_members m
        where m.org_id = p_org_id
          and m.profile_id = v_actor
          and m.role_in_org = 'admin'
    ) then
        raise exception 'not_org_admin';
    end if;

    -- 4) validate inputs
    -- NULL must be rejected explicitly (see add_organization_member).
    if v_new_role is null or v_new_role not in ('admin', 'investigator', 'member') then
        raise exception 'role_not_allowed';
    end if;

    select m.role_in_org into v_old_role
    from public.organization_members m
    where m.org_id = p_org_id and m.profile_id = p_profile_id;
    if v_old_role is null then
        raise exception 'member_not_found';
    end if;

    -- 5) business logic: a demotion of an admin is blocked when that admin is
    --    the org's last admin (covers both self-demotion and demoting another).
    if v_old_role = 'admin' and v_new_role <> 'admin' then
        select not exists (
            select 1 from public.organization_members m
            where m.org_id = p_org_id
              and m.role_in_org = 'admin'
              and m.profile_id <> p_profile_id
        ) into v_is_last_admin;
        if v_is_last_admin then
            raise exception 'last_org_admin_cannot_be_demoted';
        end if;
    end if;

    update public.organization_members m
    set role_in_org = v_new_role
    where m.org_id = p_org_id and m.profile_id = p_profile_id;

    -- 6) audit
    insert into public.audit_logs (actor_id, action, entity_type, entity_id, before, after, meta)
    values (
        v_actor,
        'organization.member_role_changed',
        'organization_member',
        (select m.id from public.organization_members m
         where m.org_id = p_org_id and m.profile_id = p_profile_id),
        jsonb_build_object('org_id', p_org_id, 'profile_id', p_profile_id, 'old_role_in_org', v_old_role),
        jsonb_build_object('org_id', p_org_id, 'profile_id', p_profile_id, 'new_role_in_org', v_new_role),
        jsonb_build_object('org_id', p_org_id, 'profile_id', p_profile_id,
            'old_role_in_org', v_old_role, 'new_role_in_org', v_new_role)
    );

    return v_new_role;
end;
$function$;

alter function public.change_organization_member_role(uuid, uuid, text) owner to postgres;
revoke execute on function public.change_organization_member_role(uuid, uuid, text) from public, anon;
grant execute on function public.change_organization_member_role(uuid, uuid, text) to authenticated;

-- -----------------------------------------------------------------------------
-- 2c. remove_organization_member
-- -----------------------------------------------------------------------------
create or replace function public.remove_organization_member(
    p_org_id uuid,
    p_profile_id uuid
)
returns void
language plpgsql
security definer
set search_path = ''
as $function$
declare
    v_actor    uuid := auth.uid();
    v_member   uuid;
    v_role     text;
    v_is_last_admin boolean;
begin
    -- 1) authenticate
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;

    -- 2) validate org exists AND lock the organization row (same serialization
    --    rationale as change_organization_member_role).
    perform 1
    from public.organizations o
    where o.id = p_org_id
    for update;
    if not found then
        raise exception 'organization_not_found';
    end if;

    -- 3) authorize (evaluated after the lock, against fresh state)
    if not exists (
        select 1 from public.organization_members m
        where m.org_id = p_org_id
          and m.profile_id = v_actor
          and m.role_in_org = 'admin'
    ) then
        raise exception 'not_org_admin';
    end if;

    -- 4) validate
    select m.id, m.role_in_org into v_member, v_role
    from public.organization_members m
    where m.org_id = p_org_id and m.profile_id = p_profile_id;
    if v_member is null then
        raise exception 'member_not_found';
    end if;

    -- 5) business logic: the last admin can never be removed (covers self too).
    if v_role = 'admin' then
        select not exists (
            select 1 from public.organization_members m
            where m.org_id = p_org_id
              and m.role_in_org = 'admin'
              and m.profile_id <> p_profile_id
        ) into v_is_last_admin;
        if v_is_last_admin then
            raise exception 'last_org_admin_cannot_be_removed';
        end if;
    end if;

    delete from public.organization_members m
    where m.id = v_member;

    -- 6) audit
    insert into public.audit_logs (actor_id, action, entity_type, entity_id, before, meta)
    values (
        v_actor,
        'organization.member_removed',
        'organization_member',
        v_member,
        jsonb_build_object('org_id', p_org_id, 'profile_id', p_profile_id, 'role_in_org', v_role),
        jsonb_build_object('org_id', p_org_id, 'profile_id', p_profile_id,
            'removed_role_in_org', v_role)
    );
end;
$function$;

alter function public.remove_organization_member(uuid, uuid) owner to postgres;
revoke execute on function public.remove_organization_member(uuid, uuid) from public, anon;
grant execute on function public.remove_organization_member(uuid, uuid) to authenticated;

-- -----------------------------------------------------------------------------
-- Membership DML is RPC-only. The direct policies from the foundation migration
-- cannot bypass the last-admin invariant, so they are dropped and the table
-- grants revoked. SELECT stays as-is (member-scoped).
-- -----------------------------------------------------------------------------
drop policy if exists "organization_members_insert_admin_only" on public.organization_members;
drop policy if exists "organization_members_update_admin_only" on public.organization_members;
drop policy if exists "organization_members_delete_admin_only" on public.organization_members;
revoke insert, update, delete on public.organization_members from authenticated;

-- =============================================================================
-- PART 3: RLS review after the RPC-only changes
--
-- The resulting policy surface is:
--   organizations
--     SELECT  -> is_org_member(id)                      [member-scoped]
--     INSERT  -> revoked (only create_organization())   [RPC-only]
--     UPDATE  -> org_role(id) = 'admin'                 [unchanged]
--     DELETE  -> no policy, denied                      [unchanged]
--   organization_members
--     SELECT  -> is_org_member(org_id)                  [unchanged]
--     INSERT/UPDATE/DELETE -> revoked (RPCs only)       [was admin policies]
--
-- No policy references another table's policy (no recursion). The adminship
-- checks inside the RPCs read organization_members as postgres, so they are
-- not subject to RLS.
--
-- Defensive assertion: the permissive INSERT policy must be gone, and the
-- only writers of organization_members are the SECURITY DEFINER RPCs.
-- =============================================================================

-- =============================================================================
-- PART 4: Defensive audit backfill re-run
--
-- Repairs any audit_logs rows still missing org_id, using the corrected
-- entity_type mapping (see Part 10d of the foundation migration). Only rows
-- whose org is currently NULL are touched, so this is idempotent. The
-- 'organization' / 'organization_member' entity types introduced by this
-- migration carry org_id on the row itself and never need this mapping.
-- =============================================================================

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

-- =============================================================================
-- PART 5: Verification queries (intentionally comments — run manually)
--
--   -- create_organization is the only INSERT path:
--   SELECT has_table_privilege('authenticated', 'public.organizations', 'INSERT');    -- false
--   SELECT has_table_privilege('authenticated', 'public.organization_members', 'INSERT'); -- false
--   SELECT has_table_privilege('authenticated', 'public.organization_members', 'UPDATE'); -- false
--   SELECT has_table_privilege('authenticated', 'public.organization_members', 'DELETE'); -- false
--
--   -- No audit_logs row with a determinable org remains unmapped:
--   SELECT count(*) FROM public.audit_logs al
--   WHERE al.entity_type IN ('case','case_member','evidence','document_version','blockchain_anchor')
--     AND al.org_id IS NULL;   -- expected 0 (0 rows where the parent chain no longer resolves)
--
--   -- organization.created events carry the right org:
--   SELECT entity_type, action, entity_id, org_id FROM public.audit_logs
--   WHERE entity_type = 'organization';   -- org_id = entity_id
--
--   -- Every org still has exactly >= 1 admin:
--   SELECT o.id FROM public.organizations o
--   WHERE NOT EXISTS (
--       SELECT 1 FROM public.organization_members m
--       WHERE m.org_id = o.id AND m.role_in_org = 'admin'
--   );  -- empty
-- =============================================================================