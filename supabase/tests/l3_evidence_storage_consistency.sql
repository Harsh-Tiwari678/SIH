-- =============================================================================
-- SIH26190 Secure Evidence — L3: evidence hash / storage consistency suite
--
-- AUDIT FINDING
--   create_evidence() accepted caller-supplied sha256 + storage_key and never
--   checked that a real object exists at that key or that the declared size
--   matches the object's metadata. A malicious or buggy direct caller could
--   register metadata for a nonexistent or undersized file.
--
-- FIX (20260924000000_evidence_storage_consistency.sql)
--   Before any rows are written, create_evidence now verifies:
--     1. the opaque key equals {case}/{evidence}/{version} (already existed);
--     2. an object exists in storage.objects under bucket 'evidence-files'
--        with the EXACT name equal to that key;
--     3. the object's metadata.size equals the declared file_size_bytes;
--     4. document_versions.storage_key is already UNIQUE (defense-in-depth).
--   Failing any of these raises 'storage_object_not_found' or
--   'storage_key_mismatch' BEFORE the evidence / document_versions inserts,
--   so no partial rows leak. The SHA-256 cannot be byte-verified inside the DB
--   (the payload lives in MinIO); the suite asserts the honest scope:
--   existence + size binding, NOT a re-hash claim.
--
-- L3.1 SEAL (20260925000000_hash_registration_gate.sql)
--   p_sha256 REGISTRATION is now capability-gated. create_evidence() requires
--   p_confirmation_token to be the RAW server-only HASH_CONFIRMATION_SECRET;
--   the DB hashes the supplied token inside PostgreSQL (extensions.digest) and
--   compares the computed digest to the stored verifier (a public constant in
--   the migration; the raw secret lives only in .env.local and is injected
--   here at runtime — it is never written into this tracked file).  The gate
--   fires BEFORE authorization, so un-tokened callers cannot probe
--   case/storage existence through the RPC at all.  This turns the upload
--   route — which computes sha256 over the EXACT byte array it uploads to
--   storage — into the only registration path that can get past the gate.
--   The public digest constant alone does NOT authenticate (sha256(digest) <>
--   digest); L3-HASH-4 below proves that regression.
--   The DB STILL cannot byte-re-verify a hash it is handed: L3-HASH-3 below
--   demonstrates that an arbitrary p_sha256 is accepted when (and only when) a
--   valid token is supplied, and documents the residual explicitly.
--
-- Fixture key prefix: 41 (users), 42 (org), 43 (case), 44 (evidence), 45 (version)
-- u1 41..0001  lead     | u2 41..0002  investigator
-- org_a 42..a1           | C_A 43..a1  active
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Fixtures
-- -----------------------------------------------------------------------------
-- p_confirmation_token MUST be the raw HASH_CONFIRMATION_SECRET (the DB hashes
-- it and compares the computed digest to its verifier).  The real secret lives
-- only in .env.local and is read at runtime from the HASH_CONFIRMATION_SECRET
-- environment variable into a session GUC (current_setting call sites below) —
-- never embedded in this tracked file.  Run suites with
--   HASH_CONFIRMATION_SECRET=<secret> psql ... -f <suite.sql>
-- L3-HASH-2 exercises the gate with NULL and a wrong token; L3-HASH-4 proves
-- the PUBLIC DIGEST constant no longer authenticates.
\getenv hash_token HASH_CONFIRMATION_SECRET
set app.capability_token = :'hash_token';

insert into auth.users (id, email, encrypted_password, email_confirmed_at, raw_app_meta_data, created_at, updated_at)
values
  ('41000000-0000-0000-0000-000000000001', 'l3.u1@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('41000000-0000-0000-0000-000000000002', 'l3.u2@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now());

insert into public.profiles (id, full_name, badge_number, role)
values
  ('41000000-0000-0000-0000-000000000001', 'L3 Lead',   'L3-01', 'officer'),
  ('41000000-0000-0000-0000-000000000002', 'L3 Inv',    'L3-02', 'officer')
on conflict (id) do nothing;

insert into public.organizations (id, name, slug, created_by)
values ('42000000-0000-0000-0000-0000000000a1', 'org-l3-alpha', 'l3-alpha', '41000000-0000-0000-0000-000000000001');

insert into public.organization_members (org_id, profile_id, role_in_org, added_by)
values
  ('42000000-0000-0000-0000-0000000000a1', '41000000-0000-0000-0000-000000000001', 'admin',        '41000000-0000-0000-0000-000000000001'),
  ('42000000-0000-0000-0000-0000000000a1', '41000000-0000-0000-0000-000000000002', 'investigator', '41000000-0000-0000-0000-000000000001');

insert into public.cases (id, org_id, case_number, title, description, status, created_by)
values ('43000000-0000-0000-0000-0000000000a1', '42000000-0000-0000-0000-0000000000a1', 'L3-CASE', 'l3 case', null, 'active', '41000000-0000-0000-0000-000000000001');

insert into public.case_members (case_id, profile_id, role_in_case, added_by)
values
  ('43000000-0000-0000-0000-0000000000a1', '41000000-0000-0000-0000-000000000001', 'lead',         '41000000-0000-0000-0000-000000000001'),
  ('43000000-0000-0000-0000-0000000000a1', '41000000-0000-0000-0000-000000000002', 'investigator', '41000000-0000-0000-0000-000000000001');

-- storage.objects: real objects that the positive tests rely on.
-- T4 positive: correct key + size 1204  (object genuinely exists).
-- T3 size-mismatch: correct key name but size mismatch (metadata says 99999).
-- T1 storage_key_mismatch: uses a deliberately wrong key shape (not the
--     case/evidence/version format) — no object needed since the mismatch
--     check fires first.
-- L3-HASH-1: server-trusted registration at key5, size 1205.
-- L3-HASH-3: arbitrary-hash residual at key7, size 1207.
insert into storage.objects (bucket_id, name, owner, metadata, created_at, updated_at)
values
  ('evidence-files',
   '43000000-0000-0000-0000-0000000000a1/44000000-0000-0000-0000-000000000004/45000000-0000-0000-0000-000000000004',
   '41000000-0000-0000-0000-000000000001',
   '{"size":1204,"mimetype":"application/pdf"}',
   now(), now()),
  ('evidence-files',
   '43000000-0000-0000-0000-0000000000a1/44000000-0000-0000-0000-000000000003/45000000-0000-0000-0000-000000000003',
   '41000000-0000-0000-0000-000000000001',
   '{"size":99999,"mimetype":"application/pdf"}',
   now(), now()),
  ('evidence-files',
   '43000000-0000-0000-0000-0000000000a1/44000000-0000-0000-0000-000000000005/45000000-0000-0000-0000-000000000005',
   '41000000-0000-0000-0000-000000000001',
   '{"size":1205,"mimetype":"application/pdf"}',
   now(), now()),
  ('evidence-files',
   '43000000-0000-0000-0000-0000000000a1/44000000-0000-0000-0000-000000000007/45000000-0000-0000-0000-000000000007',
   '41000000-0000-0000-0000-000000000001',
   '{"size":1207,"mimetype":"application/pdf"}',
   now(), now());

-- Fixture sanity: no evidence rows pre-seed C_A; the object at key4 exists.
set local role postgres;

do $$
declare
    n integer;
begin
    select count(*) into n from public.evidence where case_id = '43000000-0000-0000-0000-0000000000a1';
    if n <> 0 then
        raise exception 'FAIL L3-fixture: C_A must be empty (count %)', n;
    end if;
    if not exists (
        select 1 from storage.objects
        where bucket_id = 'evidence-files'
          and name = '43000000-0000-0000-0000-0000000000a1/44000000-0000-0000-0000-000000000004/45000000-0000-0000-0000-000000000004'
    ) then
        raise exception 'FAIL L3-fixture: correct-size object missing';
    end if;
    if not exists (
        select 1 from storage.objects
        where bucket_id = 'evidence-files'
          and name = '43000000-0000-0000-0000-0000000000a1/44000000-0000-0000-0000-000000000003/45000000-0000-0000-0000-000000000003'
    ) then
        raise exception 'FAIL L3-fixture: size-mismatch object missing';
    end if;
end $$;

-- =============================================================================
-- L3-T1 — storage_key_mismatch: key does not follow the opaque
--         {case}/{evidence}/{version} shape; the DB rejects it before the
--         storage.objects check can even run.
-- =============================================================================
set local role authenticated;
set local request.jwt.claims = '{"sub":"41000000-0000-0000-0000-000000000001"}';

do $$
begin
    begin
        perform public.create_evidence(
            p_case_id             => '43000000-0000-0000-0000-0000000000a1',
            p_evidence_id         => '44000000-0000-0000-0000-000000000001',
            p_document_version_id => '45000000-0000-0000-0000-000000000001',
            p_title               => 'bad shape',
            p_description         => null,
            p_type                => 'document',
            p_file_name           => 'bad.pdf',
            p_mime_type           => 'application/pdf',
            p_file_size_bytes     => 100,
            p_sha256              => repeat('a', 64),
            p_storage_key         => 'DOES-NOT-MATCH-THE-REQUIRED-FORMAT',
            p_notes               => null,
            p_confirmation_token  => current_setting('app.capability_token', true)
        );
        raise exception 'FAIL L3-T1: bad storage_key_shape accepted';
    exception
        when sqlstate 'P0001' then
            if sqlerrm like '%storage_key_mismatch%' then null;
            else raise exception 'FAIL L3-T1: unexpected sqlerrm %', sqlerrm; end if;
    end;
end $$;

-- =============================================================================
-- L3-T2 — storage_object_not_found: the key is correct in shape, but no
--         object exists at that key. The RPC raises BEFORE inserting any rows.
--         Fail-closed sweep verifies nothing was written.
-- =============================================================================
do $$
begin
    begin
        perform public.create_evidence(
            p_case_id             => '43000000-0000-0000-0000-0000000000a1',
            p_evidence_id         => '44000000-0000-0000-0000-000000000002',
            p_document_version_id => '45000000-0000-0000-0000-000000000002',
            p_title               => 'missing object',
            p_description         => null,
            p_type                => 'document',
            p_file_name           => 'missing.pdf',
            p_mime_type           => 'application/pdf',
            p_file_size_bytes     => 200,
            p_sha256              => repeat('b', 64),
            p_storage_key         => '43000000-0000-0000-0000-0000000000a1/44000000-0000-0000-0000-000000000002/45000000-0000-0000-0000-000000000002',
            p_notes               => null,
            p_confirmation_token  => current_setting('app.capability_token', true)
        );
        raise exception 'FAIL L3-T2: missing object accepted';
    exception
        when sqlstate 'P0001' then
            if sqlerrm like '%storage_object_not_found%' then null;
            else raise exception 'FAIL L3-T2: unexpected sqlerrm %', sqlerrm; end if;
    end;
end $$;

-- L3-T2 fail-closed: no evidence/document_version/audit row for the missing-object ids.
do $$
declare
    n integer;
begin
    select count(*) into n from public.evidence where case_id = '43000000-0000-0000-0000-0000000000a1';
    if n <> 0 then
        raise exception 'FAIL L3-T2-fail-closed: evidence rows exist after storage_object_not_found (%)', n;
    end if;
end $$;
set local role postgres;
do $$
declare
    n integer;
begin
    select count(*) into n
    from public.audit_logs
    where entity_id = '44000000-0000-0000-0000-000000000002';
    if n <> 0 then
        raise exception 'FAIL L3-T2-fail-closed: audit logs present for missing-object evidence (%)', n;
    end if;
end $$;

-- =============================================================================
-- L3-T3 — storage_object_not_found on size mismatch: an object exists at the
--         exact key, but its recorded metadata.size does not match the
--         declared file_size_bytes. The DB still fails closed.
-- =============================================================================
do $$
begin
    begin
        perform public.create_evidence(
            p_case_id             => '43000000-0000-0000-0000-0000000000a1',
            p_evidence_id         => '44000000-0000-0000-0000-000000000003',
            p_document_version_id => '45000000-0000-0000-0000-000000000003',
            p_title               => 'size mismatch',
            p_description         => null,
            p_type                => 'document',
            p_file_name           => 'mismatch.pdf',
            p_mime_type           => 'application/pdf',
            p_file_size_bytes     => 100,
            p_sha256              => repeat('c', 64),
            p_storage_key         => '43000000-0000-0000-0000-0000000000a1/44000000-0000-0000-0000-000000000003/45000000-0000-0000-0000-000000000003',
            p_notes               => null,
            p_confirmation_token  => current_setting('app.capability_token', true)
        );
        raise exception 'FAIL L3-T3: size mismatch accepted';
    exception
        when sqlstate 'P0001' then
            if sqlerrm like '%storage_object_not_found%' then null;
            else raise exception 'FAIL L3-T3: unexpected sqlerrm %', sqlerrm; end if;
    end;
end $$;

do $$
declare
    n integer;
begin
    select count(*) into n from public.evidence where case_id = '43000000-0000-0000-0000-0000000000a1';
    if n <> 0 then
        raise exception 'FAIL L3-T3-fail-closed: evidence rows exist after size mismatch (%)', n;
    end if;
end $$;

-- =============================================================================
-- L3-T4 — positive: correct key + matching storage.objects.size -> succeeds.
--         document_versions records the storage_key and sha256; the
--         chain-of-custody 'received' entry is created; evidence.created
--         audit log exists with the correct key.
-- =============================================================================
do $$
declare
    v_result jsonb;
    v_ev     jsonb;
    v_dv     jsonb;
    v_key    text;
    v_sha    text;
    v_dv_id  text;
    v_n      integer;
begin
    v_result := public.create_evidence(
        p_case_id             => '43000000-0000-0000-0000-0000000000a1',
        p_evidence_id         => '44000000-0000-0000-0000-000000000004',
        p_document_version_id => '45000000-0000-0000-0000-000000000004',
        p_title               => 'l3 positive',
        p_description         => null,
        p_type                => 'document',
        p_file_name           => 'l3-ok.pdf',
        p_mime_type           => 'application/pdf',
        p_file_size_bytes     => 1204,
        p_sha256              => repeat('d', 64),
        p_storage_key         => '43000000-0000-0000-0000-0000000000a1/44000000-0000-0000-0000-000000000004/45000000-0000-0000-0000-000000000004',
        p_notes               => 'l3 note',
        p_confirmation_token  => current_setting('app.capability_token', true)
    );
    v_ev := v_result -> 'evidence';
    v_dv := v_result -> 'document_version';
    if v_ev #>> '{evidence_number}' <> 'EV-001' then
        raise exception 'FAIL L3-T4: evidence_number was %', v_ev #>> '{evidence_number}';
    end if;

    -- storage_key and sha256 are recorded on the document_version, not in
    -- evidence. This is the honest path: the DB stored what the server gave
    -- it, and the server-bound the sha256 of the actual bytes.
    v_key := v_dv ->> 'storage_key';
    v_sha := v_dv ->> 'sha256';
    v_dv_id := v_dv ->> 'id';
    if v_key <> '43000000-0000-0000-0000-0000000000a1/44000000-0000-0000-0000-000000000004/45000000-0000-0000-0000-000000000004' then
        raise exception 'FAIL L3-T4: storage_key on document_version is wrong (%)', v_key;
    end if;
    if v_sha <> repeat('d', 64) then
        raise exception 'FAIL L3-T4: sha256 on document_version is wrong (%)', v_sha;
    end if;

    -- chain_of_custody: the initial 'received' entry exists.
    select count(*) into v_n
    from public.chain_of_custody
    where evidence_id = '44000000-0000-0000-0000-000000000004'
      and document_version_id = v_dv_id::uuid
      and action = 'received'
      and to_profile_id = '41000000-0000-0000-0000-000000000001';
    if v_n <> 1 then
        raise exception 'FAIL L3-T4: custody received missing or extra (%)', v_n;
    end if;
end $$;

-- audit is a privileged channel (only admins/supervisors can read it); switch
-- to postgres for the audit assertion.
set local role postgres;

do $$
declare
    v_n integer;
begin
    select count(*) into v_n
    from public.audit_logs
    where action = 'evidence.created'
      and entity_id = '44000000-0000-0000-0000-000000000004';
    if v_n <> 1 then
        raise exception 'FAIL L3-T4: evidence.created audit row missing (%)', v_n;
    end if;
end $$;

-- =============================================================================
-- L3-T5 — defense-in-depth: document_versions.storage_key UNIQUE constraint.
--         Directly inserting a second row with the same storage_key is
--         rejected (unique_violation). This is NOT reachable through
--         create_evidence (the opaque key is constructed from uuids and
--         cannot collide), but guards out-of-band SQL writes.
-- =============================================================================
do $$
begin
    begin
        insert into public.document_versions (
            id, evidence_id, version, prev_version_id, file_name, mime_type,
            file_size_bytes, sha256, storage_key, uploaded_by, notes
        ) values (
            '45000000-0000-0000-0000-000000000005',
            '44000000-0000-0000-0000-000000000004',
            99, null, 'duplicate.pdf', 'application/pdf',
            100, repeat('e', 64),
            '43000000-0000-0000-0000-0000000000a1/44000000-0000-0000-0000-000000000004/45000000-0000-0000-0000-000000000004',
            '41000000-0000-0000-0000-000000000001', null);
        raise exception 'FAIL L3-T5: duplicate storage_key accepted';
    exception
        when unique_violation then
            null;
    end;
end $$;

-- =============================================================================
-- L3-T6 — ownership proof: sha256 and storage_key live ONLY on
--         document_versions (the DB cannot re-hash, and the binding is the
--         existence + size check above). Assert that the successful create
--         left exactly ONE document_version with the correct sha256.
-- =============================================================================
do $$
declare
    n integer;
begin
    select count(*) into n
    from public.document_versions dv
    where dv.evidence_id = '44000000-0000-0000-0000-000000000004'
      and dv.sha256 = repeat('d', 64);
    if n <> 1 then
        raise exception 'FAIL L3-T6: sha256 on document_versions count % (expected 1)', n;
    end if;
    -- The sha256 is recorded, not verified from bytes here — a honest bound.
    -- This assertion documents the boundary: if you need byte-level proof,
    -- verify at the storage layer (MinIO), not in the DB.
end $$;

-- =============================================================================
-- L3-T7 — overall count: exactly one evidence row created in C_A (T4 only).
--         All prior negative tests (T1-T3) failed closed without residue.
-- =============================================================================
do $$
declare
    n integer;
begin
    select count(*) into n from public.evidence where case_id = '43000000-0000-0000-0000-0000000000a1';
    if n <> 1 then
        raise exception 'FAIL L3-T7: expected 1 evidence row in C_A (got %)', n;
    end if;
end $$;

-- =============================================================================
-- L3-HASH-1 — the legitimate registration path (server capability present).
--   A token-bearing create persists the supplied hash and pins it across the
--   integrity chain (document_versions.sha256 == evidence.hash_generated meta
--   == evidence.created meta), and the version is bound to a REAL storage
--   object of matching size. The hash itself is produced only by the route,
--   which hashes the exact bytes it uploads; this test proves the DB-side
--   half of that trust chain.
-- =============================================================================
set local role authenticated;
set local request.jwt.claims = '{"sub":"41000000-0000-0000-0000-000000000001"}';

do $$
declare
    v_result jsonb;
    v_dv     jsonb;
    v_n      integer;
begin
    v_result := public.create_evidence(
        p_case_id             => '43000000-0000-0000-0000-0000000000a1',
        p_evidence_id         => '44000000-0000-0000-0000-000000000005',
        p_document_version_id => '45000000-0000-0000-0000-000000000005',
        p_title               => 'hash reg via server path',
        p_description         => null,
        p_type                => 'document',
        p_file_name           => 'hash-1.pdf',
        p_mime_type           => 'application/pdf',
        p_file_size_bytes     => 1205,
        p_sha256              => repeat('e', 64),
        p_storage_key         => '43000000-0000-0000-0000-0000000000a1/44000000-0000-0000-0000-000000000005/45000000-0000-0000-0000-000000000005',
        p_notes               => 'server path',
        p_confirmation_token  => current_setting('app.capability_token', true)
    );
    v_dv := v_result -> 'document_version';
    if (v_dv ->> 'sha256') <> repeat('e', 64) then
        raise exception 'FAIL L3-HASH-1: registered sha256 not persisted (%)', v_dv ->> 'sha256';
    end if;
    if (v_dv ->> 'storage_key') <> '43000000-0000-0000-0000-0000000000a1/44000000-0000-0000-0000-000000000005/45000000-0000-0000-0000-000000000005' then
        raise exception 'FAIL L3-HASH-1: storage_key not persisted';
    end if;
    select count(*) into v_n
    from storage.objects
    where bucket_id = 'evidence-files'
      and name = '43000000-0000-0000-0000-0000000000a1/44000000-0000-0000-0000-000000000005/45000000-0000-0000-0000-000000000005'
      and (metadata ->> 'size')::bigint = 1205;
    if v_n <> 1 then
        raise exception 'FAIL L3-HASH-1: version not bound to a real object of matching size (%)', v_n;
    end if;
end $$;

-- audit pin (privileged read) — the same registered hash appears in the
-- evidence.hash_generated and evidence.created audit meta.
set local role postgres;

do $$
declare
    v_n integer;
begin
    select count(*) into v_n
    from public.audit_logs a
    where a.entity_id = '44000000-0000-0000-0000-000000000005'
      and a.action in ('evidence.hash_generated', 'evidence.created')
      and a.meta ->> 'sha256' = repeat('e', 64);
    if v_n <> 2 then
        raise exception 'FAIL L3-HASH-1: hash not pinned in the audit chain (found %)', v_n;
    end if;
end $$;

-- =============================================================================
-- L3-HASH-2 — direct RPC cannot bypass the capability gate.
--   From a legitimate lead's own session, calling create_evidence() without a
--   token (NULL) or with a wrong token is rejected with 'invalid_confirmation'
--   BEFORE authorization runs — raw PostgREST callers cannot register ANY hash.
--   Fail-closed: nothing is written.
-- =============================================================================
set local role authenticated;
set local request.jwt.claims = '{"sub":"41000000-0000-0000-0000-000000000001"}';

do $$
begin
    begin
        perform public.create_evidence(
            p_case_id             => '43000000-0000-0000-0000-0000000000a1',
            p_evidence_id         => '44000000-0000-0000-0000-000000000006',
            p_document_version_id => '45000000-0000-0000-0000-000000000006',
            p_title               => 'tokenless bypass',
            p_description         => null,
            p_type                => 'document',
            p_file_name           => 'no-token.pdf',
            p_mime_type           => 'application/pdf',
            p_file_size_bytes     => 1206,
            p_sha256              => repeat('f', 64),
            p_storage_key         => '43000000-0000-0000-0000-0000000000a1/44000000-0000-0000-0000-000000000006/45000000-0000-0000-0000-000000000006',
            p_notes               => null
        );
        raise exception 'FAIL L3-HASH-2: tokenless registration accepted';
    exception
        when sqlstate 'P0001' then
            if sqlerrm like '%invalid_confirmation%' then null;
            else raise exception 'FAIL L3-HASH-2: unexpected error (expected invalid_confirmation): %', sqlerrm; end if;
    end;
    begin
        perform public.create_evidence(
            p_case_id             => '43000000-0000-0000-0000-0000000000a1',
            p_evidence_id         => '44000000-0000-0000-0000-000000000006',
            p_document_version_id => '45000000-0000-0000-0000-000000000006',
            p_title               => 'wrong-token bypass',
            p_description         => null,
            p_type                => 'document',
            p_file_name           => 'wrong-token.pdf',
            p_mime_type           => 'application/pdf',
            p_file_size_bytes     => 1206,
            p_sha256              => repeat('f', 64),
            p_storage_key         => '43000000-0000-0000-0000-0000000000a1/44000000-0000-0000-0000-000000000006/45000000-0000-0000-0000-000000000006',
            p_notes               => null,
            p_confirmation_token  => repeat('0', 64)
        );
        raise exception 'FAIL L3-HASH-2: wrong-token registration accepted';
    exception
        when sqlstate 'P0001' then
            if sqlerrm like '%invalid_confirmation%' then null;
            else raise exception 'FAIL L3-HASH-2: unexpected error (expected invalid_confirmation): %', sqlerrm; end if;
    end;
end $$;

set local role postgres;

do $$
declare
    n integer;
begin
    select count(*) into n
    from public.evidence
    where id = '44000000-0000-0000-0000-000000000006';
    if n <> 0 then
        raise exception 'FAIL L3-HASH-2-fail-closed: evidence row exists after rejection (%)', n;
    end if;
    select count(*) into n
    from public.audit_logs
    where entity_id = '44000000-0000-0000-0000-000000000006';
    if n <> 0 then
        raise exception 'FAIL L3-HASH-2-fail-closed: audit rows exist after rejection (%)', n;
    end if;
end $$;

-- =============================================================================
-- L3-HASH-3 — documented residual: the DB still cannot byte-verify.
--   WITH a valid token, an arbitrary well-formed p_sha256 is accepted and
--   stored. This is the explicit, honest limitation: the database checks
--   existence + size + key shape + lock + capability, but has no access to the
--   MinIO byte payload, so it CANNOT refute a hash a token-holder supplies.
--   Byte-level integrity therefore rests on the server capability — the route
--   hashes the exact bytes it uploads and is the only path that can mint the
--   token. If HASH_CONFIRMATION_SECRET leaks (or the server process is
--   compromised), the database provides no independent byte-level fallback.
-- =============================================================================
set local role authenticated;
set local request.jwt.claims = '{"sub":"41000000-0000-0000-0000-000000000001"}';

do $$
declare
    v_result jsonb;
    v_sha    text;
begin
    v_result := public.create_evidence(
        p_case_id             => '43000000-0000-0000-0000-0000000000a1',
        p_evidence_id         => '44000000-0000-0000-0000-000000000007',
        p_document_version_id => '45000000-0000-0000-0000-000000000007',
        p_title               => 'arbitrary hash with valid token',
        p_description         => null,
        p_type                => 'document',
        p_file_name           => 'hash-3.pdf',
        p_mime_type           => 'application/pdf',
        p_file_size_bytes     => 1207,
        p_sha256              => repeat('7', 64),
        p_storage_key         => '43000000-0000-0000-0000-0000000000a1/44000000-0000-0000-0000-000000000007/45000000-0000-0000-0000-000000000007',
        p_notes               => 'residual demo',
        p_confirmation_token  => current_setting('app.capability_token', true)
    );
    v_sha := v_result -> 'document_version' ->> 'sha256';
    if v_sha <> repeat('7', 64) then
        raise exception 'FAIL L3-HASH-3: unexpected stored sha (%)', v_sha;
    end if;
end $$;

reset role;

-- =============================================================================
-- L3-HASH-4 — SECURITY REGRESSION: the PUBLIC DIGEST does NOT authenticate.
--   The DB-side verifier constant is public (it is embedded in migration
--   20260925000000).  Under the OLD gate that compared the token directly to
--   the digest, anyone who read the migration constant could register an
--   arbitrary hash.  The FIXED gate hashes the supplied token INSIDE the DB
--   and compares the computed digest to the verifier, so supplying the public
--   digest itself must now FAIL with invalid_confirmation.
--   Non-vacuous proof baked in: sha256(public_digest) is not a fixed point
--   (differs from the digest), so the gate's rejection is real work, not a
--   tautology.
-- =============================================================================
set local role authenticated;
set local request.jwt.claims = '{"sub":"41000000-0000-0000-0000-000000000001"}';

do $$
declare
    d_public_digest constant text := '0b91ed06536d236e343af0ac61392108fa9f55188baa4a19d90c895b63c30781';
begin
    -- mutation/non-vacuous proof: hashing the public digest does NOT produce
    -- the public digest (otherwise the rejection below would be a
    -- tautology, e.g. a gate that rejected everything).
    if encode(extensions.digest(d_public_digest, 'sha256'), 'hex') = d_public_digest then
        raise exception 'FAIL L3-HASH-4: sha256(public_digest) is a fixed point — gate would be tautological';
    end if;

    -- the actual regression: a caller presenting only the READABLE migration
    -- constant (the digest) must be rejected.  This is exactly the capability
    -- that the pre-fix gate handed out to anyone who could read the repo.
    begin
        perform public.create_evidence(
            p_case_id             => '43000000-0000-0000-0000-0000000000a1',
            p_evidence_id         => '44000000-0000-0000-0000-000000000008',
            p_document_version_id => '45000000-0000-0000-0000-000000000008',
            p_title               => 'public digest auth bypass',
            p_description         => null,
            p_type                => 'document',
            p_file_name           => 'public-digest.pdf',
            p_mime_type           => 'application/pdf',
            p_file_size_bytes     => 1208,
            p_sha256              => repeat('8', 64),
            p_storage_key         => '43000000-0000-0000-0000-0000000000a1/44000000-0000-0000-0000-000000000008/45000000-0000-0000-0000-000000000008',
            p_notes               => null,
            p_confirmation_token  => d_public_digest
        );
        raise exception 'FAIL L3-HASH-4: public digest authenticated';
    exception
        when sqlstate 'P0001' then
            if sqlerrm like '%invalid_confirmation%' then null;
            else raise exception 'FAIL L3-HASH-4: unexpected error (expected invalid_confirmation): %', sqlerrm; end if;
    end;
end $$;

set local role postgres;

do $$
declare
    v_n integer;
begin
    select count(*) into v_n
    from public.evidence
    where id = '44000000-0000-0000-0000-000000000008';
    if v_n <> 0 then
        raise exception 'FAIL L3-HASH-4-fail-closed: evidence row exists after rejection (%)', v_n;
    end if;
end $$;

reset role;

do $$ begin raise notice 'l3_evidence_storage_consistency: all tests passed (L3-T1..L3-T7, L3-HASH-1..4)'; end $$;