-- =============================================================================
-- SIH26190 Secure Evidence — secure atomic case creation
--
-- Provides a single SECURITY DEFINER RPC that atomically creates a case AND the
-- creator's lead membership. This is the only safe way to satisfy the invariant
-- "a case never exists without its creator's lead membership."
--
-- Why SECURITY DEFINER (and why the normal RLS path cannot do this):
--   * The existing RLS policy case_members_insert_lead_no_self_no_lead requires
--     profile_id <> auth.uid() and role_in_case in ('member','investigator',
--     'viewer'). It is therefore IMPOSSIBLE for a creator to insert their own
--     'lead' membership through the normal client/RLS path — by design that
--     policy governs subsequent lead-managed additions, not self-bootstrap.
--   * Two separate client statements ("insert case", then "insert membership")
--     cannot be atomic: they are independent PostgREST requests with no shared
--     database transaction. A failure between them would leave a case with no
--     lead member — exactly the invariant we must never violate.
--
-- The RPC therefore runs as its owner (postgres):
--   * security definer: runs with owner privileges, so the two writes succeed
--     even where RLS restricts direct self-lead inserts. This is a narrow,
--     sanctioned write path, not a general bypass.
--   * set search_path = '': forces every identifier to be schema-qualified so a
--     malicious object in an attacker-controlled search_path cannot shadow
--     pg_catalog / public / auth.
--   * Identity is derived ONLY from auth.uid(). The RPC accepts NO creator id and
--     NO role argument. cases.created_by, case_members.profile_id and
--     case_members.added_by all equal auth.uid(); role_in_case is hardcoded to
--     'lead'. A user can never choose or forge these values.
--   * Atomic: both inserts share one implicit transaction; if either fails the
--     whole statement rolls back, so a case can never exist without its lead row
--     (and vice versa).
--   * Bounded privilege: the RPC can only create a case, its own lead member
--     row, and one audit row. It writes nothing else.
--   * EXECUTE is granted to authenticated only; revoked from PUBLIC and anon.
--
-- The existing RLS INSERT policies on cases and case_members are NOT weakened;
-- they remain in force for every direct client path. RLS still guards SELECTs
-- and all subsequent membership / evidence / audit / custody operations. This
-- RPC (plus the future audit write RPC) is the only trusted write path.
-- =============================================================================

create or replace function public.create_case(
    p_case_number text,
    p_title text,
    p_description text default null
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
    -- authenticate / authorize: must be an authenticated session with a profile.
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;
    if not exists (select 1 from public.profiles p where p.id = v_actor) then
        raise exception 'profile_not_found';
    end if;

    -- validate (minimum integrity; the route handler performs detailed checks).
    if p_case_number is null or btrim(p_case_number) = '' then
        raise exception 'case_number_required';
    end if;
    if p_title is null or btrim(p_title) = '' then
        raise exception 'title_required';
    end if;

    -- business operation: create the case, then the creator's lead membership.
    insert into public.cases (case_number, title, description, created_by)
    values (p_case_number, btrim(p_title), p_description, v_actor)
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
        jsonb_build_object('case_number', v_case.case_number)
    );

    return v_case;
end;
$function$;

-- Owned by the trusted role; guarantees RLS bypass is via postgres, not a
-- lower-privilege owner, and matches the pattern of the existing helpers.
alter function public.create_case(text, text, text) owner to postgres;

-- The RPC is callable only by authenticated users, never anon/PUBLIC.
revoke execute on function public.create_case(text, text, text) from public;
revoke execute on function public.create_case(text, text, text) from anon;

grant execute on function public.create_case(text, text, text) to authenticated;
