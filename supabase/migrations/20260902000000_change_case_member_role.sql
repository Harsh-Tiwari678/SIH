-- =============================================================================
-- SIH26190 Secure Evidence — lead-managed case member role change
--
-- Provides a SECURITY DEFINER RPC that atomically changes an existing member's
-- role_in_case and records the matching audit event. Mirrors the trusted-write
-- pattern established by public.create_case and public.add_case_member.
--
-- Why SECURITY DEFINER (and not a direct client UPDATE through RLS):
--   * audit_logs has no INSERT policy by design; only trusted system paths may
--     write it. A role change is a sensitive, auditable operation and the
--     membership update and its audit row must be atomic — a failure between
--     two separate client statements would leave an unlogged role change.
--   * The RPC runs as its owner (postgres) and re-implements every
--     authorization check internally; SECURITY DEFINER bypasses RLS, so no
--     check may be assumed from the policies. The RLS UPDATE policy on
--     case_members (case_members_update_lead_others_no_lead) remains in force
--     for every direct client path.
--
-- Security decisions encoded here:
--   * Identity is derived ONLY from auth.uid(). The RPC accepts no actor
--     argument; audit_logs.actor_id equals auth.uid(). A user can never forge
--     these values.
--   * Case visibility is checked the same way the RLS SELECT policy sees it
--     (creator or member). A well-formed uuid for an inaccessible case is
--     therefore indistinguishable from a nonexistent case (no existence leak).
--   * Only the case lead of THIS case may change a member's role.
--   * Membership changes are permitted only while the case is 'draft' or
--     'active'. Closed and archived cases reject role changes.
--   * The target must be an existing member of THIS case. An inaccessible or
--     nonexistent member is reported identically (no existence leak).
--   * The case lead's own role can never be changed through this path — the
--     lead is established only by create_case (and a future lead-transfer
--     flow). Since the actor must be the lead, this also forbids self-change.
--   * Only member/investigator/viewer may be assigned; 'lead' can never be
--     granted through this RPC.
--   * Bounded privilege: the RPC can update one case_members row and insert
--     one audit_logs row. It writes nothing else.
--   * search_path is pinned to '' so every identifier must be schema-qualified,
--     eliminating search_path hijacking.
--   * EXECUTE is granted to authenticated only; revoked from PUBLIC and anon.
-- =============================================================================

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
    -- audit_logs has no direct INSERT policy; only SECURITY DEFINER system
    -- paths may write it.
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

-- Owned by the trusted role; guarantees the RLS bypass runs as postgres, not a
-- lower-privilege owner, matching the pattern of the existing helpers.
alter function public.change_case_member_role(uuid, uuid, text) owner to postgres;

-- The RPC is callable only by authenticated users, never anon/PUBLIC.
revoke execute on function public.change_case_member_role(uuid, uuid, text) from public;
revoke execute on function public.change_case_member_role(uuid, uuid, text) from anon;

grant execute on function public.change_case_member_role(uuid, uuid, text) to authenticated;
