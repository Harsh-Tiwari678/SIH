-- =============================================================================
-- SIH26190 Secure Evidence — secure case metadata update / status transition
--
-- Provides a single SECURITY DEFINER RPC that updates case metadata
-- (title, description) and/or performs a case status transition, atomically,
-- with identity derived ONLY from auth.uid().
--
-- Design (mirrors create_case / add_case_member):
--   * Authorization is enforced INSIDE the RPC: the caller must be the case
--     lead. The existing RLS policy `cases_update_lead_only` remains in force
--     for every direct client write; this RPC is the trusted workflow path and
--     re-checks lead membership itself rather than relying on execution flags.
--   * Identity is never taken from the request. closed_by / audit actor always
--     equal auth.uid(); a client can never forge who closed a case.
--   * The status vocabulary is the existing CHECK constraint's vocabulary:
--     ('draft', 'active', 'closed', 'archived'). No transition matrix is
--     invented here — a lead may move the case to any valid status. The
--     closed_at / closed_by pair is maintained to satisfy the schema invariant
--     ((closed_at is null) = (closed_by is null)): entering 'closed' or
--     'archived' records the actor and timestamp; leaving them clears the pair.
--   * Metadata updates: case_number is intentionally NOT updatable (it is
--     absent from the cases UPDATE grant) and is not a parameter here.
--   * updated_at is app-managed (no trigger exists); it is bumped only when a
--     managed column actually changes, so read-only status "updates" produce
--     no noise.
--   * audit_logs has no direct INSERT policy; the RPC appends an
--     'case.updated' entry with before/after JSON, exactly as create_case does.
--   * Atomic: single statement set; if any part fails the whole call rolls
--     back. SECURITY DEFINER + search_path = '' matches the existing helpers;
--     EXECUTE is limited to authenticated.
-- =============================================================================

create or replace function public.update_case(
    p_case_id uuid,
    p_title text default null,
    p_description text default null,
    p_set_description_null boolean default false,
    p_status text default null
)
returns public.cases
language plpgsql
security definer
set search_path = ''
as $function$
declare
    v_actor  uuid := auth.uid();
    v_row    public.cases;
    v_before jsonb;
    v_changed boolean := false;
    v_new_title text;
    v_new_description text;
    v_new_status text;
    v_new_closed_at timestamptz;
    v_new_closed_by uuid;
begin
    -- authenticate / authorize: must be an authenticated session with a profile.
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;
    if not exists (select 1 from public.profiles p where p.id = v_actor) then
        raise exception 'profile_not_found';
    end if;

    -- validate: the case must exist and the caller must be its lead.
    select c.* into v_row
    from public.cases c
    where c.id = p_case_id;
    if not found then
        raise exception 'case_not_found';
    end if;

    if public.case_role(p_case_id) <> 'lead' then
        raise exception 'not_lead';
    end if;

    -- validate: every supplied value must satisfy the existing constraints.
    if p_status is not null and p_status not in ('draft', 'active', 'closed', 'archived') then
        raise exception 'status_not_allowed';
    end if;
    if p_title is not null and btrim(p_title) = '' then
        raise exception 'title_required';
    end if;
    if p_title is not null and length(btrim(p_title)) > 500 then
        raise exception 'title_too_long';
    end if;
    if p_description is not null and length(p_description) > 5000 then
        raise exception 'description_too_long';
    end if;

    -- business operation: compute the candidate values, detect real changes.
    v_new_title := case when p_title is not null then btrim(p_title) else v_row.title end;
    v_new_description := case
        when p_set_description_null then null
        when p_description is not null then p_description
        else v_row.description
    end;
    v_new_status := case when p_status is not null then p_status else v_row.status end;

    v_changed := (v_new_title is distinct from v_row.title)
        or (v_new_description is distinct from v_row.description)
        or (v_new_status is distinct from v_row.status);

    if not v_changed then
        return v_row;
    end if;

    v_before := to_jsonb(v_row);

    v_new_closed_at := case
        when p_status is not null and p_status in ('closed', 'archived') then now()
        when p_status is not null then null
        else v_row.closed_at
    end;
    v_new_closed_by := case
        when p_status is not null and p_status in ('closed', 'archived') then v_actor
        when p_status is not null then null
        else v_row.closed_by
    end;

    update public.cases c0
    set title       = v_new_title,
        description = v_new_description,
        status      = v_new_status,
        closed_at   = v_new_closed_at,
        closed_by   = v_new_closed_by,
        updated_at  = now()
    where c0.id = p_case_id
    returning * into v_row;

    -- audit: record the update. audit_logs has no direct INSERT policy; only
    -- SECURITY DEFINER system paths may write it.
    insert into public.audit_logs (actor_id, action, entity_type, entity_id, before, after, meta)
    values (
        v_actor,
        'case.updated',
        'case',
        p_case_id,
        v_before,
        to_jsonb(v_row),
        jsonb_build_object('case_number', v_row.case_number)
    );

    return v_row;
end;
$function$;

-- Owned by the trusted role; guarantees privilege is via postgres, not a
-- lower-privilege owner, matching the existing SECURITY DEFINER helpers.
alter function public.update_case(uuid, text, text, boolean, text) owner to postgres;

-- Callable only by authenticated users, never anon/PUBLIC.
revoke execute on function public.update_case(uuid, text, text, boolean, text) from public;
revoke execute on function public.update_case(uuid, text, text, boolean, text) from anon;

grant execute on function public.update_case(uuid, text, text, boolean, text) to authenticated;