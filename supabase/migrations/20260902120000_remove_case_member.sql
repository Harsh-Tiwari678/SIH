-- =============================================================================
-- SIH26190 Secure Evidence — lead-managed case member removal
--
-- Provides a SECURITY DEFINER RPC that atomically removes a non-lead member
-- from an existing case and records the matching audit event. Mirrors the
-- trusted-write pattern established by public.create_case,
-- public.add_case_member, and public.change_case_member_role.
--
-- Why SECURITY DEFINER (and not a direct client DELETE through RLS):
--   * audit_logs has no INSERT policy by design; only trusted system paths may
--     write it. A removal is a sensitive, auditable operation and the
--     membership delete and its audit row must be atomic — a failure between
--     two separate client statements would delete the row before its audit
--     record could be written (or leave an audit record for a delete that
--     never happened).
--   * The RPC runs as its owner (postgres) and re-implements every
--     authorization check internally; SECURITY DEFINER bypasses RLS, so no
--     check may be assumed from the policies. The RLS DELETE policy on
--     case_members (case_members_delete_lead_others) remains in force for
--     every direct client path.
--
-- Security decisions encoded here:
--   * Identity is derived ONLY from auth.uid(). The RPC accepts no actor
--     argument; audit_logs.actor_id equals auth.uid(). A user can never forge
--     these values.
--   * Case visibility is checked the same way the RLS SELECT policy sees it
--     (creator or member). A well-formed uuid for an inaccessible case is
--     therefore indistinguishable from a nonexistent case (no existence leak).
--   * Only the case lead of THIS case may remove a member. A non-lead member,
--     investigator, or viewer can remove nobody.
--   * Membership removal is permitted only while the case is 'draft' or
--     'active'. Closed and archived cases reject removals.
--   * The target must be an existing member of THIS case. An inaccessible or
--     nonexistent member is reported identically (no existence leak).
--   * The case lead's own membership can never be removed through this path.
--     Because the actor must be the lead, this single check also rejects
--     self-removal and the removal of any other lead; the lead is relinquished
--     only via a future lead-transfer flow.
--   * Bounded privilege: the RPC can delete one case_members row and insert
--     one audit_logs row. It writes nothing else.
--   * search_path is pinned to '' so every identifier must be schema-qualified,
--     eliminating search_path hijacking.
--   * EXECUTE is granted to authenticated only; revoked from PUBLIC and anon.
-- =============================================================================

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

    -- validate: the case lead can never be removed through this path. The
    -- actor is the lead, so this also rejects self-removal and the removal
    -- of any other lead.
    if v_old_member.role_in_case = 'lead' then
        raise exception 'target_is_lead';
    end if;

    -- business operation: delete exactly this membership row, capturing the
    -- removed row for the audit trail. RLS is bypassed by SECURITY DEFINER,
    -- but the delete is bounded to this one membership row.
    delete from public.case_members
    where id = v_old_member.id
    returning * into v_old_member;

    -- audit: record the event in the same transaction as the delete.
    -- audit_logs has no direct INSERT policy; only SECURITY DEFINER system
    -- paths may write it. before = prior row, after = null (deletion).
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

-- Owned by the trusted role; guarantees the RLS bypass runs as postgres, not a
-- lower-privilege owner, matching the pattern of the existing helpers.
alter function public.remove_case_member(uuid, uuid) owner to postgres;

-- The RPC is callable only by authenticated users, never anon/PUBLIC.
revoke execute on function public.remove_case_member(uuid, uuid) from public;
revoke execute on function public.remove_case_member(uuid, uuid) from anon;

grant execute on function public.remove_case_member(uuid, uuid) to authenticated;
