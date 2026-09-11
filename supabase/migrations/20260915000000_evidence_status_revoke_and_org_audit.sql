-- =============================================================================
-- SIH26190 Secure Evidence — production hardening gaps closed
--
-- Two gaps were proven by the real SQL test suite on a fresh `supabase db
-- reset` (T10 in audit_read_path_and_hardening, T30 in
-- organization_foundation). This migration closes BOTH in production. The
-- tests are left intact and now pass against the corrected model.
--
--   GAP 1 — Direct UPDATE of public.evidence.status by authenticated is NOT
--           actually revoked.
--     Root cause: Supabase local default privileges (`pg_default_acl`) give
--     authenticated a TABLE-LEVEL UPDATE grant on every relation created in
--     the public schema. 20260910000000 tried to lock `status` down with only
--     a subset COLUMN-level `grant update (title, description, type,
--     updated_at)`, but a column grant does not revoke the table-level grant,
--     nor the original `status` column grant left by 20260830000000.
--     Verified before this migration:
--       has_table_privilege('authenticated','evidence','UPDATE')         = true
--       has_column_privilege('authenticated','evidence','status','UPDATE') = true
--     Fix: explicitly revoke the table-level UPDATE and the leftover `status`
--     column grant. Metadata column grants (title, description, type,
--     updated_at) are unchanged and remain updatable by lead/investigator
--     under the existing RLS policy. `status` becomes writable ONLY through
--     the SECURITY DEFINER update_evidence_status() RPC (which enforces case
--     role and the on-chain verification gate).
--     Unaffected paths: update_evidence_status / create_evidence /
--     record_verification_event run SECURITY DEFINER as the table owner
--     (postgres) and need none of the revoked privileges; service_role keeps
--     its table-level grants; RLS policies are not modified.
--
--   GAP 2 — Organization audit events do not populate audit_logs.org_id.
--     Root cause: 20260913000000 documents "org_id set directly" for
--     create_organization ('organization' rows, org_id = entity_id) and the
--     three membership RPCs ('organization_member' rows, org_id = the event's
--     org_id) and asserts it in Part 5's verification checklist — but none of
--     the four functions passed org_id into the audit insert, so org_id stayed
--     NULL. Fix: each function now writes the org scope in the same audit
--     insert. No audit fields are removed or reshaped; RLS / direct access to
--     audit_logs is untouched.
--
-- Requires: 20260910000000_audit_read_path_and_hardening.sql and
--           20260913000000_organization_foundation_hardening.sql applied.
-- =============================================================================

-- =============================================================================
-- PART 1 — Evidence: direct status UPDATE is denied for authenticated
-- =============================================================================

-- 1. Explicitly revoke the Supabase-default table-level UPDATE so direct
--    authenticated UPDATE on evidence is rejected.
revoke update on table public.evidence from authenticated;

-- 2. Revoke the `status` column UPDATE grant left over from
--    20260830000000_rls_policies.sql. Without this, the column grant alone
--    would still allow `update evidence set status = ...`.
revoke update (status) on table public.evidence from authenticated;

-- 3. Re-assert the metadata column grants exactly as 20260910000000 left
--    them. Revoking the table-level UPDATE keeps these effective; status stays
--    absent from the updatable column set.
grant update (title, description, type, updated_at) on public.evidence to authenticated;

-- =============================================================================
-- PART 2 — Organization audit events carry their org_id
-- =============================================================================

-- 2a. create_organization — org_id = entity_id for organization.created.
--     Only the audit insert changes; security model, authorization order,
--     validation and atomicity are byte-for-byte the original.
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

    -- 5) audit (same transaction). org_id is set to the new organization's id
    --    so organization.created events satisfy org_id = entity_id.
    insert into public.audit_logs (actor_id, action, entity_type, entity_id, org_id, after, meta)
    values (
        v_actor,
        'organization.created',
        'organization',
        v_org_id,
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

-- 2b. add_organization_member — org_id = the event's organization.
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
    v_actor     uuid := auth.uid();
    v_member    uuid;
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

    -- 5) audit. org_id carries the event's organization scope.
    insert into public.audit_logs (actor_id, action, entity_type, entity_id, org_id, after, meta)
    values (
        v_actor,
        'organization.member_added',
        'organization_member',
        v_member,
        p_org_id,
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

-- 2c. change_organization_member_role — org_id = the event's organization.
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

    -- 6) audit. org_id carries the event's organization scope.
    insert into public.audit_logs (actor_id, action, entity_type, entity_id, org_id, before, after, meta)
    values (
        v_actor,
        'organization.member_role_changed',
        'organization_member',
        (select m.id from public.organization_members m
         where m.org_id = p_org_id and m.profile_id = p_profile_id),
        p_org_id,
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

-- 2d. remove_organization_member — org_id = the event's organization.
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

    -- 6) audit. org_id carries the event's organization scope.
    insert into public.audit_logs (actor_id, action, entity_type, entity_id, org_id, before, meta)
    values (
        v_actor,
        'organization.member_removed',
        'organization_member',
        v_member,
        p_org_id,
        jsonb_build_object('org_id', p_org_id, 'profile_id', p_profile_id, 'role_in_org', v_role),
        jsonb_build_object('org_id', p_org_id, 'profile_id', p_profile_id,
            'removed_role_in_org', v_role)
    );
end;
$function$;

alter function public.remove_organization_member(uuid, uuid) owner to postgres;
revoke execute on function public.remove_organization_member(uuid, uuid) from public, anon;
grant execute on function public.remove_organization_member(uuid, uuid) to authenticated;

-- =============================================================================
-- PART 3 — Defensive backfill for rows written before this fix
--
-- Mirrors the backfill pattern already used in 20260913000000 Part 10d: if
-- these migrations are applied against a database that already contains
-- organization / organization_member audit rows with a NULL org_id (written by
-- the pre-fix functions), scope them now.
-- =============================================================================

do $do$
begin
    -- organization.created events: the entity IS the organization.
    update public.audit_logs al
    set org_id = al.entity_id
    where al.entity_type = 'organization'
      and al.org_id is null;

    -- organization_member events: derive from the event's own metadata. A
    -- malformed org_id in meta (legacy/foreign data) is left untouched.
    begin
        update public.audit_logs al
        set org_id = (al.meta ->> 'org_id')::uuid
        where al.entity_type = 'organization_member'
          and al.org_id is null
          and al.meta ? 'org_id';
    exception when invalid_text_representation then
        null;
    end;
end
$do$;