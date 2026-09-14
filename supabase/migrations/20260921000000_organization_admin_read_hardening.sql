-- =============================================================================
-- SIH26190 Secure Evidence — M1: organization administrative read hardening
--
-- Audit finding (MEDIUM): the SECURITY DEFINER organization read RPCs
--
--   * list_organization_members(uuid)
--   * list_organization_audit_events(uuid)
--   * lookup_profiles_for_organization(uuid, text)
--
-- authorized with GENERAL membership (is_org_member), so any organization
-- member could retrieve the full roster, the organization audit trail, and
-- candidate profile searches (including badge numbers) — administrative
-- surface that belongs to organization admins alone.
--
-- Fix: every one of these RPCs now requires the caller's CURRENT membership in
-- the target org with role_in_org = 'admin'. The check reuses the existing
-- hardened helper org_role() (20260912000000, SECURITY DEFINER, search_path
-- = '', identity from auth.uid()) — the same predicate the organizations
-- UPDATE/DELETE policies and the add/change/remove member RPCs already use. No
-- new authorization logic is invented here.
--
--   * system roles (profiles.role: admin/supervisor/officer) grant NOTHING.
--   * case roles (case_members.role_in_case) grant NOTHING.
--   * stale membership (a removed organization_members row) grants NOTHING,
--     because org_role() reads the CURRENT organization_members table only.
--   * a caller that is not an admin of the target org — non-member, org member,
--     org investigator, or stale former member — is rejected identically with
--     'org_not_found', the established "inaccessible org" sentinel used by
--     these read RPCs. Existence of an organization is never leaked to callers
--     that cannot administer it, and the existing API routes (which map
--     org_not_found to 404) need no changes.
--
-- The queries themselves are UNCHANGED (same column surface, same org-scoping,
-- same entity-chain resolution, same storage_key scrubbing, same 10-result cap
-- for lookup). Only the authorization gate differs from 20260917000000.
--
-- SECURITY DEFINER, search_path = '', owner postgres, EXECUTE revoked from
-- public/anon and granted to authenticated only: unchanged from the originals.
-- =============================================================================

-- =============================================================================
-- 1) list_organization_members — admin-only roster
-- =============================================================================

create or replace function public.list_organization_members(
    p_org_id uuid
)
returns table (
    id              uuid,
    profile_id      uuid,
    full_name       text,
    badge_number    text,
    role_in_org     text,
    added_by_name   text,
    added_by        uuid,
    added_at        timestamptz
)
language plpgsql
security definer
set search_path = ''
as $function$
declare
    v_actor uuid := auth.uid();
begin
    -- authenticate / authorize: an authenticated session with a profile.
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;
    if not exists (select 1 from public.profiles p where p.id = v_actor) then
        raise exception 'profile_not_found';
    end if;

    -- authorize (M1): only the org's CURRENT admins may read the roster. The
    -- helper resolves the actor's CURRENT organization_members role; stale
    -- membership, case roles and system roles are all irrelevant here. A
    -- non-admin is reported identically to a nonexistent org.
    if coalesce(public.org_role(p_org_id), '') <> 'admin' then
        raise exception 'org_not_found';
    end if;

    return query
    select
        m.id,
        m.profile_id,
        p.full_name,
        p.badge_number,
        m.role_in_org,
        ap.full_name as added_by_name,
        m.added_by,
        m.added_at
    from public.organization_members m
    join public.profiles p on p.id = m.profile_id
    left join public.profiles ap on ap.id = m.added_by
    where m.org_id = p_org_id
    order by m.added_at, m.id;
end;
$function$;

alter function public.list_organization_members(uuid) owner to postgres;
revoke execute on function public.list_organization_members(uuid) from public, anon;
grant execute on function public.list_organization_members(uuid) to authenticated;

-- =============================================================================
-- 2) list_organization_audit_events — admin-only org trail
-- =============================================================================

create or replace function public.list_organization_audit_events(
    p_org_id uuid
)
returns table (
    id           uuid,
    action       text,
    entity_type  text,
    entity_id    uuid,
    actor_id     uuid,
    actor_name   text,
    entity_label text,
    created_at   timestamptz,
    meta         jsonb
)
language plpgsql
security definer
set search_path = ''
as $function$
declare
    v_actor uuid := auth.uid();
begin
    -- authenticate / authorize: an authenticated session with a profile.
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;
    if not exists (select 1 from public.profiles p where p.id = v_actor) then
        raise exception 'profile_not_found';
    end if;

    -- authorize (M1): only the org's CURRENT admins may read its audit trail.
    if coalesce(public.org_role(p_org_id), '') <> 'admin' then
        raise exception 'org_not_found';
    end if;

    -- resolve the owning organization for every entity type (unchanged query:
    -- writers populate audit_logs.org_id for organization / organization_member
    -- / custody events; case-scoped events store the org only in their JSON).
    return query
    with resolved as (
        select
            r0.id,
            r0.action,
            r0.entity_type,
            r0.entity_id,
            r0.actor_id,
            r0.created_at,
            r0.meta_scrubbed as meta,
            r0.org_id
                as org_id,
            case r0.entity_type
                when 'case' then
                    (select c.org_id from public.cases c where c.id = r0.entity_id)
                when 'case_member' then (
                    select c.org_id
                    from public.cases c
                    where c.id = coalesce(
                        (r0.after ->> 'case_id')::uuid,
                        (r0.meta ->> 'case_id')::uuid,
                        (r0.before ->> 'case_id')::uuid
                    )
                )
                when 'evidence' then (
                    select c.org_id
                    from public.evidence e
                    join public.cases c on c.id = e.case_id
                    where e.id = r0.entity_id
                )
                when 'document_version' then (
                    select c.org_id
                    from public.document_versions dv
                    join public.evidence e on e.id = dv.evidence_id
                    join public.cases c on c.id = e.case_id
                    where dv.id = r0.entity_id
                )
                when 'blockchain_anchor' then (
                    select c.org_id
                    from public.blockchain_anchors ba
                    join public.evidence e on e.id = ba.evidence_id
                    join public.cases c on c.id = e.case_id
                    where ba.id = r0.entity_id
                )
                when 'organization' then r0.entity_id
                when 'organization_member' then (r0.meta ->> 'org_id')::uuid
                else null::uuid
            end as resolved_org,
            r0.profile_ref
        from (
            select
                a.*,
                (a.meta - 'storage_key')::jsonb as meta_scrubbed,
                coalesce(
                    (a.after ->> 'profile_id')::uuid,
                    (a.before ->> 'profile_id')::uuid,
                    (a.meta ->> 'to_profile_id')::uuid,
                    (a.meta ->> 'removed_profile_id')::uuid,
                    (a.meta ->> 'profile_id')::uuid
                ) as profile_ref
            from public.audit_logs a
        ) r0
    )
    select
        r.id,
        r.action,
        r.entity_type,
        r.entity_id,
        r.actor_id,
        ap.full_name as actor_name,
        case r.entity_type
            when 'case' then
                (select c.title from public.cases c where c.id = r.entity_id)
            when 'evidence' then
                (select e.title from public.evidence e where e.id = r.entity_id)
            when 'document_version' then
                (select dv.file_name from public.document_versions dv where dv.id = r.entity_id)
            when 'blockchain_anchor' then (
                select e.title
                from public.blockchain_anchors ba
                join public.evidence e on e.id = ba.evidence_id
                where ba.id = r.entity_id
            )
            when 'organization' then
                (select o.name from public.organizations o where o.id = r.entity_id)
            when 'case_member' then
                (select p.full_name from public.profiles p where p.id = r.profile_ref)
            when 'organization_member' then
                (select p.full_name from public.profiles p where p.id = r.profile_ref)
            else null::text
        end as entity_label,
        r.created_at,
        r.meta
    from resolved r
    left join public.profiles ap on ap.id = r.actor_id
    where r.org_id = p_org_id
       or r.resolved_org = p_org_id
    order by r.created_at desc, r.id desc;
end;
$function$;

alter function public.list_organization_audit_events(uuid) owner to postgres;
revoke execute on function public.list_organization_audit_events(uuid) from public, anon;
grant execute on function public.list_organization_audit_events(uuid) to authenticated;

-- =============================================================================
-- 3) lookup_profiles_for_organization — admin-only candidate search
--
-- Query semantics are UNCHANGED from 20260917000000 (the M1 fix adds the admin
-- gate only):
--   * candidates = profiles NOT currently members of the target org (NOT
--     EXISTS against organization_members) — a profile in ANOTHER org, or in
--     no org, is a valid candidate; visible membership is per-org.
--   * optional case-insensitive substring filter on full_name / badge_number.
--   * capped at 10 rows, exposing ONLY id / full_name / badge_number.
--   * no role data, no auth internals, no cross-organization roster exposure
--     beyond the candidate set the "add member" flow needs.
-- =============================================================================

create or replace function public.lookup_profiles_for_organization(
    p_org_id  uuid,
    p_query   text default null
)
returns table (
    id           uuid,
    full_name    text,
    badge_number text
)
language plpgsql
security definer
set search_path = ''
as $function$
declare
    v_actor uuid := auth.uid();
begin
    -- authenticate / authorize: an authenticated session with a profile.
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;
    if not exists (select 1 from public.profiles p where p.id = v_actor) then
        raise exception 'profile_not_found';
    end if;

    -- authorize (M1): only the org's CURRENT admins may search candidates on
    -- the org's behalf. Non-admins are reported identically to a nonexistent
    -- org, so profile enumeration by ordinary members is closed.
    if coalesce(public.org_role(p_org_id), '') <> 'admin' then
        raise exception 'org_not_found';
    end if;

    return query
    select
        p.id,
        p.full_name,
        p.badge_number
    from public.profiles p
    where not exists (
        select 1
        from public.organization_members existing
        where existing.org_id = p_org_id
          and existing.profile_id = p.id
    )
      and (
          p_query is null
          or p.full_name ilike '%' || p_query || '%'
          or p.badge_number ilike '%' || p_query || '%'
      )
    order by p.full_name, p.id
    limit 10;
end;
$function$;

alter function public.lookup_profiles_for_organization(uuid, text) owner to postgres;
revoke execute on function public.lookup_profiles_for_organization(uuid, text) from public, anon;
grant execute on function public.lookup_profiles_for_organization(uuid, text) to authenticated;

-- =============================================================================
-- End of migration 20260921000000_organization_admin_read_hardening
-- =============================================================================