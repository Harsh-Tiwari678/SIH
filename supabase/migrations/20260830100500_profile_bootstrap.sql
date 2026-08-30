-- =============================================================================
-- SIH26190 Secure Evidence — authentication-to-profile bootstrap
--
-- Automatically creates a public.profiles row when a new Supabase Auth user is
-- created in auth.users. Fixes the bootstrap gap identified during RLS-test
-- planning: previously no code path created a profile row, so a newly
-- signed-up user had no profile and therefore could not become a case member,
-- read cases, or take part in any RLS-gated workflow.
--
-- Security decisions:
--   * SECURITY DEFINER: runs as its owner (postgres) with the privileges to
--     insert into public.profiles independent of the calling (possibly
--     anonymous) session. This is a trusted system path, never a user request
--     path.
--   * set search_path = '': forces every identifier to be schema-qualified so a
--     malicious object placed earlier in an attacker-controlled search_path
--     cannot shadow pg_catalog or the auth schema. The new user is reached
--     through the trigger's NEW row, not via an unqualified table lookup.
--   * Fully-qualified identifier only: public.profiles.
--   * role is hardcoded to 'officer'. NEW.raw_user_meta_data (user-controllable)
--     is NEVER consulted for the role; a user cannot self-assign admin,
--     supervisor, or any other global role through this trigger. Role changes
--     require a separate, sanctioned path (future admin RPC), never this one.
--   * ON CONFLICT (id) DO NOTHING: idempotent against a duplicate or raced
--     profile insert without masking genuine constraint failures on other
--     columns (e.g. a missing full_name).
--   * No direct EXECUTE: the function is used only as a trigger body. EXECUTE is
--     revoked from PUBLIC/anon/authenticated so a user cannot invoke it by hand
--     to forge profiles.
-- =============================================================================

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $function$
begin
    insert into public.profiles (id, full_name, role)
    values (
        NEW.id,
        coalesce(nullif(NEW.raw_user_meta_data ->> 'full_name', ''), 'New Officer'),
        'officer'
    )
    on conflict (id) do nothing;

    return NEW;
end;
$function$;

-- Owned by the trusted bootstrap role; ensures RLS (owned by postgres) is not a
-- barrier in this trusted path and that the function cannot be re-owned to a
-- lower-privilege role by mistake.
alter function public.handle_new_user() owner to postgres;

-- The function is a trigger body only; deny direct invocation by any client.
revoke execute on function public.handle_new_user() from public;
revoke execute on function public.handle_new_user() from anon;
revoke execute on function public.handle_new_user() from authenticated;

-- AFTER INSERT so the new auth.users row (the parent referenced by the
-- profiles.id -> auth.users.id foreign key) already exists in the same
-- transaction when the FK is validated.
create trigger on_auth_user_created
    after insert on auth.users
    for each row
    execute function public.handle_new_user();
