-- =============================================================================
-- SIH26190 Secure Evidence — organization-aware case security
--
-- Makes the organization boundary a real security boundary for case access.
--
-- Target authorization model:
--
--   CASE READ ACCESS (RLS + audit visibility):
--     A user can read a case if and only if they are a member of the case's
--     organization AND (
--         (a) they are an organization ADMIN for that organization, OR
--         (b) they are an explicit member of the case (case_members row)
--     ).
--     Non-admin organization members need explicit case membership. A user
--     from another organization can NEVER access a case of this organization,
--     regardless of stale case_members data.
--
--   CASE WRITE ACCESS (member management, evidence, anchoring):
--     Requires explicit case membership with lead / investigator role.
--     Organization admins do NOT automatically gain write authority on cases
--     they created without explicit membership; they gain organization-wide
--     READ and audit visibility only (the access ORG_ADMIN grants in the
--     target model). Writes stay explicit-case-role gated.
--
-- Approved decisions (narrowest defensible behavior):
--   * is_case_member(uuid) is the single access predicate and is extended to
--     enforce org membership AND (org admin OR case member). This single
--     change propagates org isolation to every existing RLS policy that
--     calls it: cases, evidence, document_versions, chain_of_custody,
--     blockchain_anchors, and storage objects. No new access helpers are
--     introduced (has_case_access / effective_case_role / is_visible_to_case
--     are deliberately NOT added to avoid duplicated, divergent predicates).
--   * Organization admins receive organization-wide case READ and audit
--     access via RLS / read RPCs, matching the task T15 requirement. They
--     are not granted lead-equivalent write authority (task T16-17 scope).
--   * Direct case_members DML is revoked: INSERT/UPDATE/DELETE are removed
--     and the table grants are revoked, making the SECURITY DEFINER RPCs
--     (create_case, add/change/remove_case_member) the ONLY mutation path.
--     This closes direct-DML privilege escalation and cross-org membership
--     fabrication, mirroring the organization_members hardening.
--   * Direct cases INSERT is revoked as well; create_case() is the only
--     case-creation path, preventing unvalidated org_id assignment.
--   * create_case() gains p_org_id and validates that the organization
--     exists and the caller is a member. The creator becomes the case lead.
--     Any organization member may create a case (this preserves the original
--     pre-org semantics of "any authenticated user may create a case", now
--     bounded by organization membership; no narrower org-role gate existed
--     in the product model, and inventing one would change existing behavior.
--     Documented as the chosen policy; easily narrowed later if desired.)
--   * Case member management (add / change / remove) stays LEAD-only via
--     explicit case_role() = 'lead' (unchanged), and gains two org-boundary
--     checks: the actor must have org-aware case visibility, and the target
--     profile must belong to the SAME organization as the case.
--   * The 2-argument is_case_member(profile_uuid, case_uuid) is UNCHANGED:
--     it checks explicit case membership for an arbitrary profile and is used
--     by chain_of_custody from_profile_id / to_profile_id validation.
--   * System global roles (profiles admin / supervisor) are unchanged and do
--     NOT grant case access; only organization_members.role_in_org does.
--   * Case number uniqueness remains global (case_number unique). Org-scoped
--     case numbers are a future product decision and are not part of this
--     migration.
--   * Blockchain RPCs are NOT modified. They gate writes on explicit
--     case_role membership. Organization admins can read anchors (via the
--     select policy below) but must be explicit case members to anchor.
--
-- Functions changed:
--   * is_case_member(uuid)        — + org membership AND (org admin OR member)
--   * is_case_member(uuid, uuid)  — unchanged
--   * create_case(...)            — dropped 3-arg; new (uuid, text, text, text)
--   * add_case_member(...)        — + org-aware visibility + target same-org
--   * change_case_member_role(..) — + org-aware visibility + target same-org
--   * remove_case_member(...)     — + org-aware visibility + target same-org
--   * list_case_audit_events(uuid)   — visibility via is_case_member (id only)
--   * list_evidence_audit_events(uuid) — same
--
-- RLS policies changed:
--   * cases SELECT  -> is_case_member(id) (drop creator-only branch)
--   * cases INSERT  -> dropped + grant revoked (RPC-only creation)
--   * cases UPDATE  -> + is_org_member(org_id) on the lead check
--   * case_members  -> INSERT/UPDATE/DELETE policies dropped + grants revoked
--   * evidence INSERT/UPDATE, document_versions INSERT, chain_of_custody
--     INSERT -> actor must be an org member of the case's org (is_case_member)
--
-- NOT changed:
--   * case_role(uuid), global_role(), is_org_member(uuid), org_role(uuid)
--   * blockchain subsystem RPCs
--   * audit_logs, profiles RLS policies
-- =============================================================================

-- =============================================================================
-- PART 1: Access predicate — org-aware is_case_member(uuid)
-- =============================================================================

-- 1a. is_case_member(uuid) — extend to enforce the organization boundary.
--
-- Before: true iff the caller has an explicit case_members row.
-- After:  true iff the caller is a member of the case's organization AND
--         (is an org admin for it OR has an explicit case_members row).
--
-- This single change propagates org isolation to every RLS policy that calls
-- the 1-arg variant (cases, evidence, document_versions, chain_of_custody,
-- blockchain_anchors, storage evidence_files), because those policies express
-- "is the caller allowed to access this case" and the predicate now enforces
-- the org boundary for all of them at once.
create or replace function public.is_case_member(case_uuid uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $function$
    select exists (
        select 1
        from public.cases c
        left join public.case_members cm
            on cm.case_id = c.id
            and cm.profile_id = auth.uid()
        where c.id = is_case_member.case_uuid
          and public.is_org_member(c.org_id)
          and (
              public.org_role(c.org_id) = 'admin'
              or cm.id is not null
          )
    );
$function$;

-- 1b. Two-argument variant — UNCHANGED.
-- It answers "is this arbitrary profile an explicit case member", not "may
-- the caller access the case", and is referenced by chain_of_custody to vet
-- from_profile_id / to_profile_id. Re-asserted below only for owner / EXECUTE.

alter function public.is_case_member(uuid) owner to postgres;
alter function public.is_case_member(uuid, uuid) owner to postgres;

revoke execute on function public.is_case_member(uuid) from public, anon;
revoke execute on function public.is_case_member(uuid, uuid) from public, anon;

grant execute on function public.is_case_member(uuid) to authenticated;
grant execute on function public.is_case_member(uuid, uuid) to authenticated;

-- =============================================================================
-- PART 2: RLS policy updates
--
-- The SELECT-facing policy surface automatically inherits org awareness from
-- the is_case_member change above. The edits below close direct-write and
-- direct-insert gaps only.
-- =============================================================================

-- 2a. cases SELECT — replace creator-or-member with the org-aware predicate.
--
-- The creator is ALWAYS an explicit 'lead' member (create_case guarantees it),
-- so the creator-only branch is redundant, and keeping it would grant a
-- creator continued read access after their organization membership is
-- revoked (stale case_members). Requiring is_case_member(id) makes creator
-- access flow through the same org boundary (task T17).
drop policy if exists "cases_select_creator_or_member" on public.cases;
create policy "cases_select_member_or_org_admin"
on public.cases
for select
to authenticated
using (public.is_case_member(id));

-- 2b. cases INSERT — remove the direct path entirely.
--
-- The old policy let any authenticated user INSERT a case directly, which
-- would let a client choose org_id (validating nothing) and bypass the
-- atomic lead-membership + audit that create_case() performs. Dropping the
-- policy and revoking the grant makes create_case() the ONLY creation path.
drop policy if exists "cases_insert_authenticated_own" on public.cases;
revoke insert on public.cases from authenticated;

-- 2c. cases UPDATE — keep lead-only, and additionally require the lead to be
-- an organization member of the case's organization.
--
-- Defense in depth: eliminates direct UPDATE by an explicit 'lead' whose
-- organization membership was revoked (stale case_members), closing the
-- same hole at the direct-write layer that RPC-level checks close elsewhere.
drop policy if exists "cases_update_lead_only" on public.cases;
create policy "cases_update_lead_only"
on public.cases
for update
to authenticated
using (
    public.case_role(id) = 'lead'
    and public.is_org_member(org_id)
)
with check (
    public.case_role(id) = 'lead'
    and public.is_org_member(org_id)
);

-- 2d. case_members — RPC-only mutations.
--
-- The previous three policies allowed a lead to INSERT/UPDATE/DELETE
-- case_members rows directly, without any target-organization validation.
-- That path could fabricate cross-organization memberships or grant roles
-- beyond the RPC restrictions. As with organization_members, mutations are
-- revoked; add_case_member / change_case_member_role / remove_case_member
-- (hardened in Part 3) are the only writers. SELECT stays member/self-scoped
-- and inherits org awareness through is_case_member.
drop policy if exists "case_members_insert_lead_no_self_no_lead" on public.case_members;
drop policy if exists "case_members_update_lead_others_no_lead" on public.case_members;
drop policy if exists "case_members_delete_lead_others" on public.case_members;
revoke insert, update, delete on public.case_members from authenticated;

-- 2e. Direct evidence / document_versions / chain_of_custody writes — add an
-- organization-membership guard on the acting user.
--
-- These policies already require an explicit lead/investigator case role;
-- adding is_case_member(case_id) additionally requires the actor to be an
-- organization member of the case's organization. Stale explicit members
-- whose org membership was revoked can no longer write, consistent with the
-- org boundary (defense in depth at the direct-write layer).
drop policy if exists "evidence_insert_lead_or_investigator" on public.evidence;
create policy "evidence_insert_lead_or_investigator"
on public.evidence
for insert
to authenticated
with check (
    created_by = auth.uid()
    and public.case_role(case_id) in ('lead', 'investigator')
    and public.is_case_member(case_id)
);

drop policy if exists "evidence_update_lead_or_investigator" on public.evidence;
create policy "evidence_update_lead_or_investigator"
on public.evidence
for update
to authenticated
using (
    public.case_role(case_id) in ('lead', 'investigator')
    and public.is_case_member(case_id)
)
with check (
    public.case_role(case_id) in ('lead', 'investigator')
    and public.is_case_member(case_id)
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
    -- The actor must be lead or investigator for the evidence's case AND an
    -- organization member of that case's organization.
    and exists (
        select 1
        from public.evidence e
        where e.id = evidence_id
          and public.case_role(e.case_id) in ('lead', 'investigator')
          and public.is_case_member(e.case_id)
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

-- =============================================================================
-- PART 3: RPC updates
-- =============================================================================

-- 3a. create_case — add p_org_id and full organization validation.
--
-- The old 3-argument variant is DROPPED (not kept as an overload): it had no
-- organization concept and would insert a NULL org_id, which the NOT NULL
-- constraint on cases.org_id now rejects. Dropping it also guarantees the
-- callers cannot fall back to an unvalidated creation path.
drop function if exists public.create_case(text, text, text);

-- The creator must be a member of the target organization. Identity
-- (created_by / lead / added_by) is derived ONLY from auth.uid(); the client
-- supplies no actor and no role. The creator becomes the lead, mirroring the
-- original single-statement atomic invariant of the old create_case.
create or replace function public.create_case(
    p_org_id        uuid,
    p_case_number   text,
    p_title         text,
    p_description   text default null
)
returns public.cases
language plpgsql
security definer
set search_path = ''
as $function$
declare
    v_actor uuid := auth.uid();
    v_case  public.cases;
begin
    -- authenticate: derive the actor from the session, never from arguments.
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;
    if not exists (select 1 from public.profiles p where p.id = v_actor) then
        raise exception 'profile_not_found';
    end if;

    -- validate: the target organization must exist and the caller must be a
    -- member of it. Membership is checked BEFORE any case row is written.
    if p_org_id is null then
        raise exception 'org_required';
    end if;
    if not exists (select 1 from public.organizations o where o.id = p_org_id) then
        raise exception 'org_not_found';
    end if;
    if not public.is_org_member(p_org_id) then
        raise exception 'not_org_member';
    end if;

    -- validate (minimum integrity; the route handler performs detailed checks).
    if p_case_number is null or btrim(p_case_number) = '' then
        raise exception 'case_number_required';
    end if;
    if p_title is null or btrim(p_title) = '' then
        raise exception 'title_required';
    end if;

    -- business operation: create the case in the validated organization,
    -- then the creator's lead membership. Atomic (one implicit transaction).
    insert into public.cases (org_id, case_number, title, description, created_by)
    values (p_org_id, p_case_number, btrim(p_title), p_description, v_actor)
    returning * into v_case;

    insert into public.case_members (case_id, profile_id, role_in_case, added_by)
    values (v_case.id, v_actor, 'lead', v_actor);

    -- audit: record the case-creation event. audit_logs has no direct INSERT
    -- policy; only SECURITY DEFINER system paths may write it.
    insert into public.audit_logs (actor_id, action, entity_type, entity_id, after, meta)
    values (
        v_actor,
        'case.created',
        'case',
        v_case.id,
        to_jsonb(v_case),
        jsonb_build_object('case_number', v_case.case_number, 'org_id', p_org_id)
    );

    return v_case;
end;
$function$;

alter function public.create_case(uuid, text, text, text) owner to postgres;
revoke execute on function public.create_case(uuid, text, text, text) from public, anon;
grant execute on function public.create_case(uuid, text, text, text) to authenticated;

-- 3b. add_case_member — enforce the organization boundary.
--
-- Two changes vs. the original:
--   1. Visibility now requires org-aware case access (is_case_member), so a
--      caller from another organization (or with revoked org membership)
--      cannot resolve the case (no existence leak) and cannot add members.
--   2. The TARGET profile must belong to the SAME organization as the case.
--      A cross-organization membership can never be created. NOTE: this
--      checks p_profile_id, not auth.uid().
-- Authorization stays: only an explicit case lead may add members.
create or replace function public.add_case_member(
    p_case_id uuid,
    p_profile_id uuid,
    p_role_in_case text
)
returns public.case_members
language plpgsql
security definer
set search_path = ''
as $function$
declare
    v_actor  uuid := auth.uid();
    v_case   public.cases;
    v_member public.case_members;
begin
    -- authenticate: derive the actor from the session, never from arguments.
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;

    -- authorize: the actor must have an application profile.
    if not exists (select 1 from public.profiles p where p.id = v_actor) then
        raise exception 'profile_not_found';
    end if;

    -- authorize (visibility): the case must exist AND be visible to the actor
    -- (org-aware access), matching cases_select_member_or_org_admin RLS, so an
    -- inaccessible case is reported identically to a nonexistent one.
    select c.*
    into v_case
    from public.cases c
    where c.id = p_case_id
      and public.is_case_member(c.id);
    if not found then
        raise exception 'case_not_found';
    end if;

    -- authorize: only the case lead may add members.
    if not exists (
        select 1
        from public.case_members m
        where m.case_id = p_case_id
          and m.profile_id = v_actor
          and m.role_in_case = 'lead'
    ) then
        raise exception 'not_lead';
    end if;

    -- business rule: only open cases accept members.
    if v_case.status not in ('draft', 'active') then
        raise exception 'case_not_open';
    end if;

    -- validate: the target must be an existing profile.
    if p_profile_id is null
       or not exists (select 1 from public.profiles p where p.id = p_profile_id)
    then
        raise exception 'target_profile_not_found';
    end if;

    -- validate: no self-addition (mirrors the old RLS insert policy).
    if p_profile_id = v_actor then
        raise exception 'self_add_not_allowed';
    end if;

    -- authorize (org boundary): the target must already be a member of THIS
    -- case's organization. Checks p_profile_id — never auth.uid().
    if not exists (
        select 1
        from public.organization_members om
        where om.org_id = v_case.org_id
          and om.profile_id = p_profile_id
    ) then
        raise exception 'target_not_in_org';
    end if;

    -- validate: only assignable roles; never another lead.
    if p_role_in_case not in ('member', 'investigator', 'viewer') then
        raise exception 'role_not_allowed';
    end if;

    -- business operation: insert the membership. The unique
    -- (case_id, profile_id) constraint rejects duplicate membership.
    insert into public.case_members (case_id, profile_id, role_in_case, added_by)
    values (p_case_id, p_profile_id, p_role_in_case, v_actor)
    returning * into v_member;

    -- audit: record the event in the same transaction as the membership
    -- insert. audit_logs has no direct INSERT policy; only SECURITY DEFINER
    -- system paths may write it.
    insert into public.audit_logs (actor_id, action, entity_type, entity_id, after, meta)
    values (
        v_actor,
        'case.member_added',
        'case_member',
        v_member.id,
        to_jsonb(v_member),
        jsonb_build_object(
            'case_id', v_case.id,
            'case_number', v_case.case_number,
            'role_in_case', p_role_in_case
        )
    );

    return v_member;
end;
$function$;

-- 3c. change_case_member_role — enforce the organization boundary.
--
-- Visibility now requires org-aware case access; the target must belong to
-- the same organization as the case. Authorization stays lead-only.
create or replace function public.change_case_member_role(
    p_case_id uuid,
    p_profile_id uuid,
    p_role_in_case text
)
returns public.case_members
language plpgsql
security definer
set search_path = ''
as $function$
declare
    v_actor     uuid := auth.uid();
    v_case      public.cases;
    v_member    public.case_members;
    v_old_member public.case_members;
begin
    -- authenticate: derive the actor from the session, never from arguments.
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;

    -- authorize: the actor must have an application profile.
    if not exists (select 1 from public.profiles p where p.id = v_actor) then
        raise exception 'profile_not_found';
    end if;

    -- authorize (visibility): org-aware case access; an inaccessible case is
    -- reported identically to a nonexistent one (no existence leak).
    select c.*
    into v_case
    from public.cases c
    where c.id = p_case_id
      and public.is_case_member(c.id);
    if not found then
        raise exception 'case_not_found';
    end if;

    -- authorize: only the case lead may change a member's role.
    if not exists (
        select 1
        from public.case_members m
        where m.case_id = p_case_id
          and m.profile_id = v_actor
          and m.role_in_case = 'lead'
    ) then
        raise exception 'not_lead';
    end if;

    -- business rule: role changes are allowed only on open cases.
    if v_case.status not in ('draft', 'active') then
        raise exception 'case_not_open';
    end if;

    -- validate: the target must be an existing member of THIS case. An
    -- inaccessible or nonexistent member is reported identically (no leak).
    if p_profile_id is null then
        raise exception 'target_not_in_case';
    end if;
    select m.*
    into v_old_member
    from public.case_members m
    where m.case_id = p_case_id
      and m.profile_id = p_profile_id;
    if not found then
        raise exception 'target_not_in_case';
    end if;

    -- authorize (org boundary): the target must belong to the SAME
    -- organization as the case. Defense against any stale cross-org rows.
    if not exists (
        select 1
        from public.organization_members om
        where om.org_id = v_case.org_id
          and om.profile_id = p_profile_id
    ) then
        raise exception 'target_not_in_org';
    end if;

    -- validate: the case lead's role can never be changed through this path.
    -- (The actor is the lead, so this also rejects self-change.)
    if v_old_member.role_in_case = 'lead' then
        raise exception 'target_is_lead';
    end if;

    -- validate: only assignable roles; 'lead' can never be granted here.
    if p_role_in_case not in ('member', 'investigator', 'viewer') then
        raise exception 'role_not_allowed';
    end if;

    -- business operation: update the role. RLS is bypassed by SECURITY
    -- DEFINER, but the update is bounded to this one membership row.
    update public.case_members
    set role_in_case = p_role_in_case
    where id = v_old_member.id
    returning * into v_member;

    -- audit: record the event in the same transaction as the role update.
    insert into public.audit_logs (actor_id, action, entity_type, entity_id, before, after, meta)
    values (
        v_actor,
        'case.member_role_changed',
        'case_member',
        v_member.id,
        to_jsonb(v_old_member),
        to_jsonb(v_member),
        jsonb_build_object(
            'case_id', v_case.id,
            'case_number', v_case.case_number,
            'previous_role_in_case', v_old_member.role_in_case,
            'new_role_in_case', v_member.role_in_case
        )
    );

    return v_member;
end;
$function$;

-- 3d. remove_case_member — enforce the organization boundary.
--
-- Same visibility and target-organization checks as change_case_member_role.
create or replace function public.remove_case_member(
    p_case_id uuid,
    p_profile_id uuid
)
returns public.case_members
language plpgsql
security definer
set search_path = ''
as $function$
declare
    v_actor uuid := auth.uid();
    v_case  public.cases;
    v_old_member public.case_members;
begin
    -- authenticate: derive the actor from the session, never from arguments.
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;

    -- authorize: the actor must have an application profile.
    if not exists (select 1 from public.profiles p where p.id = v_actor) then
        raise exception 'profile_not_found';
    end if;

    -- authorize (visibility): org-aware case access; no existence leak.
    select c.*
    into v_case
    from public.cases c
    where c.id = p_case_id
      and public.is_case_member(c.id);
    if not found then
        raise exception 'case_not_found';
    end if;

    -- authorize: only the case lead may remove members.
    if not exists (
        select 1
        from public.case_members m
        where m.case_id = p_case_id
          and m.profile_id = v_actor
          and m.role_in_case = 'lead'
    ) then
        raise exception 'not_lead';
    end if;

    -- business rule: members may only be removed from open cases.
    if v_case.status not in ('draft', 'active') then
        raise exception 'case_not_open';
    end if;

    -- validate: the target must be an existing member of THIS case. An
    -- inaccessible or nonexistent member is reported identically (no leak).
    if p_profile_id is null then
        raise exception 'target_not_in_case';
    end if;
    select m.*
    into v_old_member
    from public.case_members m
    where m.case_id = p_case_id
      and m.profile_id = p_profile_id;
    if not found then
        raise exception 'target_not_in_case';
    end if;

    -- authorize (org boundary): the target must belong to the SAME
    -- organization as the case. Defense against any stale cross-org rows.
    if not exists (
        select 1
        from public.organization_members om
        where om.org_id = v_case.org_id
          and om.profile_id = p_profile_id
    ) then
        raise exception 'target_not_in_org';
    end if;

    -- validate: the case lead can never be removed through this path. The
    -- actor is the lead, so this also rejects self-removal and the removal
    -- of any other lead.
    if v_old_member.role_in_case = 'lead' then
        raise exception 'target_is_lead';
    end if;

    -- business operation: delete exactly this membership row, capturing the
    -- removed row for the audit trail.
    delete from public.case_members
    where id = v_old_member.id
    returning * into v_old_member;

    -- audit: record the event in the same transaction as the delete.
    insert into public.audit_logs (actor_id, action, entity_type, entity_id, before, meta)
    values (
        v_actor,
        'case.member_removed',
        'case_member',
        v_old_member.id,
        to_jsonb(v_old_member),
        jsonb_build_object(
            'case_id', v_case.id,
            'case_number', v_case.case_number,
            'removed_profile_id', v_old_member.profile_id,
            'removed_role_in_case', v_old_member.role_in_case
        )
    );

    return v_old_member;
end;
$function$;

-- 3e. list_case_audit_events — visibility via the org-aware predicate only.
--
-- The old visibility check was "created_by = v_actor OR is_case_member". The
-- creator is always an explicit lead, so the extra branch only served to
-- grant a creator continued read access after org revocation (T17). Replacing
-- it with is_case_member(c.id) makes audit visibility follow exactly the RLS
-- read model — organization admins included. Only the visibility subquery
-- changes; the rest of the body is byte-for-byte the original.
create or replace function public.list_case_audit_events(p_case_id uuid)
returns table (
    id           uuid,
    action       text,
    entity_type  text,
    entity_id    uuid,
    actor_id     uuid,
    actor_name   text,
    case_id      uuid,
    evidence_id  uuid,
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
    v_case  uuid;
begin
    -- authenticate / authorize: an authenticated session with a profile.
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;
    if not exists (select 1 from public.profiles p where p.id = v_actor) then
        raise exception 'profile_not_found';
    end if;

    -- authorize (visibility): the case must exist AND be visible to the actor
    -- (org-aware access), matching cases_select_member_or_org_admin RLS, so an
    -- inaccessible case is reported identically to a nonexistent one.
    select c.id into v_case
    from public.cases c
    where c.id = p_case_id
      and public.is_case_member(c.id);
    if v_case is null then
        raise exception 'case_not_found';
    end if;

    -- build the trail: resolve every polymorphic entity to its owning case /
    -- evidence / label, then return only rows that belong to THIS case. 'meta'
    -- is scrubbed of storage keys and other internals the UI should never see.
    return query
    with resolved as (
        select
            a.id,
            a.action,
            a.entity_type,
            a.entity_id,
            a.actor_id,
            a.created_at,
            (a.meta - 'storage_key') as meta,
            cid.case_id,
            cid.evidence_id,
            cid.entity_label
        from public.audit_logs a
        cross join lateral (
            select
                case a.entity_type
                    when 'case' then a.entity_id
                    when 'case_member' then (a.meta ->> 'case_id')::uuid
                    when 'evidence' then (select e.case_id from public.evidence e where e.id = a.entity_id)
                    when 'document_version' then (
                        select e.case_id
                        from public.document_versions dv
                        join public.evidence e on e.id = dv.evidence_id
                        where dv.id = a.entity_id
                    )
                    when 'blockchain_anchor' then (
                        select e.case_id
                        from public.blockchain_anchors ba
                        join public.evidence e on e.id = ba.evidence_id
                        where ba.id = a.entity_id
                    )
                    else null::uuid
                end as case_id,
                case a.entity_type
                    when 'evidence' then a.entity_id
                    when 'document_version' then (
                        select dv.evidence_id
                        from public.document_versions dv
                        where dv.id = a.entity_id
                    )
                    when 'blockchain_anchor' then (
                        select ba.evidence_id
                        from public.blockchain_anchors ba
                        where ba.id = a.entity_id
                    )
                    else null::uuid
                end as evidence_id,
                case a.entity_type
                    when 'case' then (select c.case_number from public.cases c where c.id = a.entity_id)
                    when 'evidence' then (select e.title from public.evidence e where e.id = a.entity_id)
                    when 'document_version' then (select dv.file_name from public.document_versions dv where dv.id = a.entity_id)
                    when 'blockchain_anchor' then (
                        select e.title
                        from public.blockchain_anchors ba
                        join public.evidence e on e.id = ba.evidence_id
                        where ba.id = a.entity_id
                    )
                    when 'case_member' then (
                        select p.full_name
                        from public.profiles p
                        where p.id = coalesce(
                            (a.meta ->> 'to_profile_id')::uuid,
                            (a.meta ->> 'removed_profile_id')::uuid
                        )
                    )
                    else null::text
                end as entity_label
        ) cid
        where cid.case_id = p_case_id
    )
    select
        r.id,
        r.action,
        r.entity_type,
        r.entity_id,
        r.actor_id,
        (select p.full_name from public.profiles p where p.id = r.actor_id) as actor_name,
        r.case_id,
        r.evidence_id,
        r.entity_label,
        r.created_at,
        r.meta
    from resolved r
    order by r.created_at desc, r.id desc;
end;
$function$;

-- 3f. list_evidence_audit_events — visibility via the org-aware predicate.
--
-- Same rationale as 3e: only the visibility subquery changes.
create or replace function public.list_evidence_audit_events(p_evidence_id uuid)
returns table (
    id           uuid,
    action       text,
    entity_type  text,
    entity_id    uuid,
    actor_id     uuid,
    actor_name   text,
    case_id      uuid,
    evidence_id  uuid,
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
    v_case  uuid;
begin
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;
    if not exists (select 1 from public.profiles p where p.id = v_actor) then
        raise exception 'profile_not_found';
    end if;

    -- authorize (visibility): the evidence must exist and its case must be
    -- visible to the actor (org-aware access).
    select e.case_id into v_case
    from public.evidence e
    where e.id = p_evidence_id
      and exists (
          select 1
          from public.cases c
          where c.id = e.case_id
            and public.is_case_member(c.id)
      );
    if v_case is null then
        raise exception 'evidence_not_found';
    end if;

    -- the evidence's trail: the evidence row itself, its document versions and
    -- its blockchain anchors. Verdict / result events live on the version row.
    return query
    with resolved as (
        select
            a.id,
            a.action,
            a.entity_type,
            a.entity_id,
            a.actor_id,
            a.created_at,
            (a.meta - 'storage_key') as meta,
            cid.case_id,
            cid.evidence_id,
            cid.entity_label
        from public.audit_logs a
        cross join lateral (
            select
                case a.entity_type
                    when 'evidence' then (select e.case_id from public.evidence e where e.id = a.entity_id)
                    when 'document_version' then (
                        select e.case_id
                        from public.document_versions dv
                        join public.evidence e on e.id = dv.evidence_id
                        where dv.id = a.entity_id
                    )
                    when 'blockchain_anchor' then (
                        select e.case_id
                        from public.blockchain_anchors ba
                        join public.evidence e on e.id = ba.evidence_id
                        where ba.id = a.entity_id
                    )
                    else null::uuid
                end as case_id,
                case a.entity_type
                    when 'evidence' then a.entity_id
                    when 'document_version' then (
                        select dv.evidence_id
                        from public.document_versions dv
                        where dv.id = a.entity_id
                    )
                    when 'blockchain_anchor' then (
                        select ba.evidence_id
                        from public.blockchain_anchors ba
                        where ba.id = a.entity_id
                    )
                    else null::uuid
                end as evidence_id,
                case a.entity_type
                    when 'evidence' then (select e.title from public.evidence e where e.id = a.entity_id)
                    when 'document_version' then (select dv.file_name from public.document_versions dv where dv.id = a.entity_id)
                    when 'blockchain_anchor' then (
                        select e.title
                        from public.blockchain_anchors ba
                        join public.evidence e on e.id = ba.evidence_id
                        where ba.id = a.entity_id
                    )
                    else null::text
                end as entity_label
        ) cid
        where
            (a.entity_type = 'evidence' and a.entity_id = p_evidence_id)
            or (
                a.entity_type = 'document_version'
                and exists (
                    select 1 from public.document_versions dv
                    where dv.id = a.entity_id and dv.evidence_id = p_evidence_id
                )
            )
            or (
                a.entity_type = 'blockchain_anchor'
                and exists (
                    select 1 from public.blockchain_anchors ba
                    where ba.id = a.entity_id and ba.evidence_id = p_evidence_id
                )
            )
    )
    select
        r.id,
        r.action,
        r.entity_type,
        r.entity_id,
        r.actor_id,
        (select p.full_name from public.profiles p where p.id = r.actor_id) as actor_name,
        r.case_id,
        r.evidence_id,
        r.entity_label,
        r.created_at,
        r.meta
    from resolved r
    order by r.created_at desc, r.id desc;
end;
$function$;

-- =============================================================================
-- PART 4: Ownership and EXECUTE for the recreated functions
-- =============================================================================

alter function public.add_case_member(uuid, uuid, text) owner to postgres;
alter function public.change_case_member_role(uuid, uuid, text) owner to postgres;
alter function public.remove_case_member(uuid, uuid) owner to postgres;
alter function public.list_case_audit_events(uuid) owner to postgres;
alter function public.list_evidence_audit_events(uuid) owner to postgres;

revoke execute on function public.add_case_member(uuid, uuid, text) from public, anon;
revoke execute on function public.change_case_member_role(uuid, uuid, text) from public, anon;
revoke execute on function public.remove_case_member(uuid, uuid) from public, anon;
revoke execute on function public.list_case_audit_events(uuid) from public, anon;
revoke execute on function public.list_evidence_audit_events(uuid) from public, anon;

grant execute on function public.add_case_member(uuid, uuid, text) to authenticated;
grant execute on function public.change_case_member_role(uuid, uuid, text) to authenticated;
grant execute on function public.remove_case_member(uuid, uuid) to authenticated;
grant execute on function public.list_case_audit_events(uuid) to authenticated;
grant execute on function public.list_evidence_audit_events(uuid) to authenticated;

-- =============================================================================
-- PART 5: Verification queries (comments only — run manually)
-- =============================================================================
--
--   -- Authenticated can no longer directly INSERT cases / mutate
--   -- case_members (all four should be false):
--   SELECT has_table_privilege('authenticated', 'public.cases', 'INSERT');              -- false
--   SELECT has_table_privilege('authenticated', 'public.case_members', 'INSERT');       -- false
--   SELECT has_table_privilege('authenticated', 'public.case_members', 'UPDATE');       -- false
--   SELECT has_table_privilege('authenticated', 'public.case_members', 'DELETE');       -- false
--
--   -- Every case has a valid org (0 rows):
--   SELECT count(*) FROM public.cases c
--   WHERE NOT EXISTS (SELECT 1 FROM public.organizations o WHERE o.id = c.org_id);
--
--   -- No cross-org case membership can exist (0 rows): any case_members row
--   -- must belong to a member of the same org as its case:
--   SELECT count(*) FROM public.case_members cm
--   JOIN public.cases c ON c.id = cm.case_id
--   WHERE NOT EXISTS (
--       SELECT 1 FROM public.organization_members om
--       WHERE om.org_id = c.org_id AND om.profile_id = cm.profile_id
--   );
--
--   -- org admins see every case in their org through the RLS + is_case_member:
--   SELECT count(*) FROM public.cases c
--   WHERE public.is_org_member(c.org_id) AND public.org_role(c.org_id) = 'admin'
--     AND NOT public.is_case_member(c.id);  -- must be 0
-- =============================================================================