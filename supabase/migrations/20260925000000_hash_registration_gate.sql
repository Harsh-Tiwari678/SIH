-- =============================================================================
-- SIH26190 Secure Evidence — L3.1: capability-gated hash registration
--
-- AUDIT FINDING (L3 follow-up)
--   create_evidence() accepted caller-supplied p_sha256 without any server
--   capability check.  PostgreSQL cannot re-read the MinIO-stored object
--   bytes, so "did the stored bytes actually hash to p_sha256?" is NOT
--   answerable here.  What IS answerable: WHO may register a hash.
--
--   Before this migration any authenticated user with a valid case role could
--   invoke create_evidence() directly via PostgREST and register an arbitrary
--   64-hex string as the integrity SHA-256, even though the upload route
--   computes it over the exact bytes it uploads.  The RPC's unrestricted
--   grant turned a server-only computation into a client-reachable write.
--
-- FIX
--   The database stores only the SHA-256 digest of a server-only secret
--   (HASH_CONFIRMATION_SECRET) as the expected verifier.  The upload route
--   passes the RAW secret as p_confirmation_token; create_evidence() hashes
--   the supplied token inside PostgreSQL (extensions.digest, the pgcrypto
--   facility) and compares the computed digest to the stored verifier.  The
--   secret never leaves the server process; the stored digest is a verifier,
--   NOT a bearer credential — knowing it does not authenticate (SHA-256
--   preimage resistance), only the raw secret, once hashed, matches.  Rotation
--   requires only a new migration embedding the new digest (see ROTATION).
--
-- WHAT IS PROVED
--   - An un-tokened PostgREST caller cannot register ANY hash through
--     create_evidence(), regardless of their role, org membership, or
--     knowledge of storage keys.  The capability gate fires BEFORE
--     authorization, so no case/storage/oracle information leaks.
--   - Knowledge of the public digest constant alone does NOT authenticate:
--     the gate hashes the supplied token in the DB, so only the raw secret
--     (whose SHA-256 equals the verifier) passes.
--   - The upload route is the only remaining call path that can carry the
--     correct token.  The route computes sha256 over the exact same byte
--     array it uploads to storage (lib/storage.sha256Hex(bytes)), so the
--     registered hash matches the stored object by construction.
--
-- REMAINING LIMITATION (honest)
--   The database does NOT byte-re-verify the hash: PostgreSQL has no access
--   to MinIO object contents.  A valid token authorises the hash the caller
--   supplies — the guarantee is that ONLY the server process (which computes
--   the hash over the same bytes it stores) can reach this code path.  If the
--   HASH_CONFIRMATION_SECRET leaks or the server process is compromised the
--   DB cannot provide an independent fallback.  This is an explicit,
--   documented residual; the bound is the capability, not a DB byte check.
--
-- ROTATION
--   1. Generate a fresh 256-bit random value.
--   2. Put it into .env.local as HASH_CONFIRMATION_SECRET.
--   3. Compute its SHA-256 digest.
--   4. Embed the new digest as v_expected_confirmation in a NEW migration
--      (never editing this migration retroactively).
--   5. Rotate the deployment environment.
--
-- =============================================================================

-- Drop the previous 12-arg signature (from 20260924). It MUST not remain as an
-- overload: it has no capability gate, so leaving it in place (even with
-- EXECUTE revoked from the client roles) would keep an ungated SECURITY
-- DEFINER variant callable by the function owner and any future server-side
-- path, and would make named-arg calls ambiguous.
drop function if exists public.create_evidence(
    uuid, uuid, uuid, text, text, text, text, text, bigint, text, text, text
);

create or replace function public.create_evidence(
    p_case_id              uuid,
    p_evidence_id          uuid,
    p_document_version_id  uuid,
    p_title                text,
    p_description          text,
    p_type                 text,
    p_file_name            text,
    p_mime_type            text,
    p_file_size_bytes      bigint,
    p_sha256               text,
    p_storage_key          text,
    p_notes                text,
    p_confirmation_token   text default null
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $function$
declare
    v_actor   uuid := auth.uid();
    v_case    public.cases;
    v_evidence public.evidence;
    v_version public.document_versions;
    v_seq     integer;
    -- SHA-256 verifier of HASH_CONFIRMATION_SECRET (see .env.local); a public
    -- constant KNOWN IN THIS MIGRATION.  This is a VERIFIER, not a bearer
    -- credential: knowing the digest does not authenticate.  The gate below
    -- hashes the supplied token inside the DB and compares the computed
    -- digest to this value, so only the RAW secret (whose SHA-256 equals
    -- this verifier) passes.  Registry/readers of this constant cannot mint
    -- a valid token (SHA-256 preimage resistance).
    v_expected_confirmation constant text := '0b91ed06536d236e343af0ac61392108fa9f55188baa4a19d90c895b63c30781';
begin
    -- authenticate: derive the actor from the session, never from arguments.
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;

    -- capability gate (L3.1): only server code that holds the RAW
    -- HASH_CONFIRMATION_SECRET passes.  The supplied token is hashed inside
    -- the DB (extensions.digest = the installed pgcrypto facility; no new
    -- dependency) and the computed digest is compared to the stored
    -- verifier.  A direct PostgREST caller who knows the PUBLIC digest
    -- constant cannot authenticate — sha256(public_digest) <> public_digest.
    -- The check is placed BEFORE authorization so un-tokened callers cannot
    -- even probe case or storage existence through error responses — the
    -- RPC stays silent.
    -- If p_confirmation_token is NULL (caller omitted it) the <> comparison
    -- yields NULL which the IF treats as false; guard explicitly for clarity
    -- and a uniform error message.
    if p_confirmation_token is null
       or p_confirmation_token !~ '^[0-9a-f]{64}$'
       or encode(extensions.digest(p_confirmation_token::text, 'sha256'), 'hex')
            <> v_expected_confirmation
    then
        raise exception 'invalid_confirmation';
    end if;

    -- authorize: the actor must have an application profile.
    if not exists (select 1 from public.profiles p where p.id = v_actor) then
        raise exception 'profile_not_found';
    end if;

    -- HARDENING (M1-era): use org-aware case visibility. The old check
    -- (c.created_by = v_actor OR explicit case_members) let stale members
    -- through. is_case_member enforces the org boundary.
    select c.*
    into v_case
    from public.cases c
    where c.id = p_case_id
      and public.is_case_member(c.id);
    if not found then
        raise exception 'case_not_found';
    end if;

    -- authorize: only the case lead or an investigator may upload evidence.
    -- The is_case_member check above ensures the actor is an org member;
    -- this check ensures the actor has the explicit role.
    if not exists (
        select 1
        from public.case_members m
        where m.case_id = p_case_id
          and m.profile_id = v_actor
          and m.role_in_case in ('lead', 'investigator')
    ) then
        raise exception 'not_authorized_to_upload';
    end if;

    -- business rule: evidence may only be added to open cases.
    if v_case.status not in ('draft', 'active') then
        raise exception 'case_not_open';
    end if;

    -- validate: metadata handed over by the route handler (which already
    -- enforced size/MIME/filename rules before uploading the object). The DB
    -- re-asserts the invariants so no write path can bypass them.
    if p_evidence_id is null or p_document_version_id is null then
        raise exception 'invalid_file_metadata';
    end if;
    if p_title is null or btrim(p_title) = '' or char_length(p_title) > 500 then
        raise exception 'invalid_file_metadata';
    end if;
    if p_description is not null and char_length(p_description) > 5000 then
        raise exception 'invalid_file_metadata';
    end if;
    if p_type not in ('document', 'image', 'video', 'audio', 'other') then
        raise exception 'evidence_type_not_allowed';
    end if;
    if p_file_name is null or btrim(p_file_name) = '' or char_length(p_file_name) > 255 then
        raise exception 'invalid_file_metadata';
    end if;
    if p_mime_type is null or btrim(p_mime_type) = '' then
        raise exception 'invalid_file_metadata';
    end if;
    if p_file_size_bytes is null or p_file_size_bytes < 1 then
        raise exception 'invalid_file_metadata';
    end if;
    if p_sha256 !~ '^[0-9a-f]{64}$' then
        raise exception 'invalid_file_metadata';
    end if;

    -- validate: the storage key must be exactly the opaque key for THIS case,
    -- evidence and version. The DB can never point at a foreign object.
    if p_storage_key is distinct from
       p_case_id || '/' || p_evidence_id || '/' || p_document_version_id
    then
        raise exception 'storage_key_mismatch';
    end if;

    -- validate (L3): the opaque key must reference a REAL object under the
    -- evidence bucket whose recorded size matches the declared size. The
    -- storage service writes storage.objects.metadata.size from the actual
    -- uploaded bytes, so this binds the DB row to an object that genuinely
    -- exists under exactly the case/evidence/version key — an arbitrary,
    -- foreign, or unlinked key can no longer be registered. Byte-level
    -- re-hashing of the object is impossible here (the payload lives in
    -- MinIO); the SHA-256 integrity binding rests on the server-only
    -- capability gate above (only the server can mint the token) plus this
    -- existence/size invariant (see migration header).
    if not exists (
        select 1
        from storage.objects o
        where o.bucket_id = 'evidence-files'
          and o.name = p_storage_key
          and (o.metadata ->> 'size')::bigint = p_file_size_bytes
    ) then
        raise exception 'storage_object_not_found';
    end if;

    -- business operation: allocate the per-case sequential evidence number
    -- ATOMICALLY (L2). The transaction-scoped advisory lock serializes
    -- same-case creators before the count is read, so the count always
    -- reflects every committed predecessor and the number is gap-free.
    -- Evidence rows are never deleted, so the count remains a valid base.
    perform pg_advisory_xact_lock(
        (766442187)::int,
        mod(hashtextextended(p_case_id::text, 0), 2147483647)::int
    );
    v_seq := (select count(*) from public.evidence where case_id = p_case_id) + 1;
    insert into public.evidence (
        id, case_id, evidence_number, title, description, type, status, created_by
    ) values (
        p_evidence_id,
        p_case_id,
        'EV-' || lpad(v_seq::text, 3, '0'),
        btrim(p_title),
        p_description,
        p_type,
        'received',
        v_actor
    )
    returning * into v_evidence;

    -- business operation: the immutable first file version.
    insert into public.document_versions (
        id, evidence_id, version, prev_version_id, file_name, mime_type,
        file_size_bytes, sha256, storage_key, uploaded_by, notes
    ) values (
        p_document_version_id,
        v_evidence.id,
        1,
        null,
        p_file_name,
        p_mime_type,
        p_file_size_bytes,
        p_sha256,
        p_storage_key,
        v_actor,
        p_notes
    )
    returning * into v_version;

    -- business operation: initial possession entry. The uploader takes
    -- custody; the origin (from_profile_id) is outside the system.
    insert into public.chain_of_custody (
        evidence_id, document_version_id, action, actor_id,
        from_profile_id, to_profile_id, notes
    ) values (
        v_evidence.id,
        v_version.id,
        'received',
        v_actor,
        null,
        v_actor,
        p_notes
    );

    -- audit: record the events in the same transaction as the inserts.
    -- audit_logs has no direct INSERT policy; only SECURITY DEFINER system
    -- paths may write it. Possession itself is recorded above in
    -- chain_of_custody — the two concepts stay separate.

    -- the SHA-256 fingerprint was just computed and bound to the version.
    insert into public.audit_logs (actor_id, action, entity_type, entity_id, meta)
    values (
        v_actor,
        'evidence.hash_generated',
        'evidence',
        v_evidence.id,
        jsonb_build_object(
            'case_id', v_case.id,
            'case_number', v_case.case_number,
            'document_version_id', v_version.id,
            'sha256', v_version.sha256
        )
    );

    -- custody was taken by the uploader (mirrors chain_of_custody 'received').
    insert into public.audit_logs (actor_id, action, entity_type, entity_id, meta)
    values (
        v_actor,
        'evidence.custody_received',
        'evidence',
        v_evidence.id,
        jsonb_build_object(
            'case_id', v_case.id,
            'case_number', v_case.case_number,
            'evidence_id', v_evidence.id,
            'evidence_number', v_evidence.evidence_number,
            'title', v_evidence.title,
            'document_version_id', v_version.id,
            'file_name', v_version.file_name
        )
    );

    insert into public.audit_logs (actor_id, action, entity_type, entity_id, after, meta)
    values (
        v_actor,
        'evidence.created',
        'evidence',
        v_evidence.id,
        to_jsonb(v_evidence),
        jsonb_build_object(
            'case_id', v_case.id,
            'case_number', v_case.case_number,
            'evidence_id', v_evidence.id,
            'evidence_number', v_evidence.evidence_number,
            'title', v_evidence.title,
            'document_version_id', v_version.id,
            'file_name', v_version.file_name,
            'mime_type', v_version.mime_type,
            'file_size_bytes', v_version.file_size_bytes,
            'sha256', v_version.sha256,
            'storage_key', v_version.storage_key
        )
    );

    return jsonb_build_object(
        'evidence', to_jsonb(v_evidence),
        'document_version', to_jsonb(v_version)
    );
end;
$function$;

-- 13-arg signature (new).  p_confirmation_token defaults to null; callers
-- that omit it get NULL which is rejected by the capability gate before any
-- write is attempted — fail-closed by design.
alter function public.create_evidence(
    uuid, uuid, uuid, text, text, text, text, text, bigint, text, text, text, text
) owner to postgres;
revoke execute on function public.create_evidence(
    uuid, uuid, uuid, text, text, text, text, text, bigint, text, text, text, text
) from public, anon;
grant execute on function public.create_evidence(
    uuid, uuid, uuid, text, text, text, text, text, bigint, text, text, text, text
) to authenticated;
