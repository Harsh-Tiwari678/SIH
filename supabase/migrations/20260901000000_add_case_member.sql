-- =============================================================================
-- SIH26190 Secure Evidence — lead-managed case member addition
--
-- Provides a SECURITY DEFINER RPC that atomically adds a member to an existing
-- case and records the matching audit event. Mirrors the trusted-write pattern
-- established by public.create_case.
--
-- Why SECURITY DEFINER (and not a plain client INSERT through RLS):
--   * audit_logs has no INSERT policy by design; only trusted system paths may
--     write it. Membership addition is a sensitive operation that must be
--     audited, and the membership insert and its audit row must be atomic —
--     a failure between two separate client statements would leave an
--     unlogged membership change.
--   * The RPC runs as its owner (postgres) and re-implements every
--     authorization check internally; SECURITY DEFINER bypasses RLS, so no
--     check may be assumed from the policies. The RLS INSERT policy on
--     case_members remains in force for every direct client path.
--
-- Security decisions encoded here:
--   * Identity is derived ONLY from auth.uid(). The RPC accepts no actor and
--     no added_by argument; case_members.added_by and audit_logs.actor_id both
--     equal auth.uid(). A user can never forge these values.
--   * Case visibility is checked the same way the RLS SELECT policy sees it
--     (creator or member). A well-formed uuid for an inaccessible case is
--     therefore indistinguishable from a nonexistent case (no existence leak).
--   * Only the case lead may add members. Only member/investigator/viewer may
--     be assigned; 'lead' can never be created through this path (lead is
--     granted by create_case and a future, separate lead-transfer flow).
--   * Membership changes are permitted only while the case is 'draft' or
--     'active'. Closed and archived cases reject new members.
--   * The target must be an existing profile. Self-addition is rejected
--     (mirrors the RLS insert policy). Duplicate membership is rejected by the
--     unique (case_id, profile_id) constraint.
--   * Bounded privilege: the RPC can only insert one case_members row and one
--     audit_logs row. It writes nothing else.
--   * search_path is pinned to '' so every identifier must be schema-qualified,
--     eliminating search_path hijacking.
--   * EXECUTE is granted to authenticated only; revoked from PUBLIC and anon.
-- =============================================================================

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
    -- (creator or member), matching cases_select_creator_or_member RLS, so an
    -- inaccessible case is reported identically to a nonexistent one.
    select c.*
    into v_case
    from public.cases c
    where c.id = p_case_id
      and (
          c.created_by = v_actor
          or exists (
              select 1
              from public.case_members m
              where m.case_id = c.id
                and m.profile_id = v_actor
          )
      );
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

    -- validate: no self-addition (mirrors the RLS insert policy).
    if p_profile_id = v_actor then
        raise exception 'self_add_not_allowed';
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

-- Owned by the trusted role; guarantees the RLS bypass runs as postgres, not a
-- lower-privilege owner, matching the pattern of the existing helpers.
alter function public.add_case_member(uuid, uuid, text) owner to postgres;

-- The RPC is callable only by authenticated users, never anon/PUBLIC.
revoke execute on function public.add_case_member(uuid, uuid, text) from public;
revoke execute on function public.add_case_member(uuid, uuid, text) from anon;

grant execute on function public.add_case_member(uuid, uuid, text) to authenticated;
