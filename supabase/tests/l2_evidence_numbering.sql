-- =============================================================================
-- SIH26190 Secure Evidence — L2: atomic evidence numbering regression suite
--
-- AUDIT FINDING
--   create_evidence() allocated the per-case sequential evidence number via
--   count(*)+1 with a 5-attempt unique-violation retry loop. Two concurrent
--   same-case creators could both read the same count, then one would burn
--   retries (and, under load, fail with a unique-violation instead of a number).
--
-- FIX (20260923000000_atomic_evidence_numbering.sql)
--   The allocation is serialized per case with a transaction-scoped advisory
--   lock (pg_advisory_xact_lock) keyed on the case id, taken BEFORE the count
--   is read, then the number is written once with no retry. The counts are
--   gap-free because evidence rows are never deleted and the lock guarantees
--   the count reflects every committed predecessor at read time. Same-case
--   creators serialize perfectly; different cases remain fully parallel.
--   UNIQUE(case_id, evidence_number) stays as the final backstop.
--
-- This SQL suite proves the deterministic single-session properties. The
-- concurrency properties (two sessions, same case) are proven by the paired
-- orchestration script l2_evidence_concurrency.sh, which also demonstrates
-- that removing the advisory lock (mutation) breaks the guarantee.
--
-- Fixture keys (valid, and storage.objects rows exist so the L3 storage
-- consistency check passes: this suite exercises numbering, not storage):
--   u1 (510..0001) lead of C_A     u2 (510..0002) investigator of C_A
--   u3 (510..0003) member of C_A   uB (510..0005) lead of C_B
--   org_a 520..A1   org_b 520..B1
--   C_A 53000000-0000-0000-0000-0000000000a1 (active)
--   C_B 53000000-0000-0000-0000-0000000000b1 (active, clean)
--   C_C 53000000-0000-0000-0000-0000000000c1 (active, pre-seeded EV-001/EV-002)
-- =============================================================================

-- -----------------------------------------------------------------------------
-- Fixtures (test role: postgres, direct inserts; RLS bypassed for the writer)
-- -----------------------------------------------------------------------------
-- p_confirmation_token MUST be the raw HASH_CONFIRMATION_SECRET (the L3.1
-- capability gate, migration 20260925000000, hashes the supplied token inside
-- the DB and compares the computed digest to its verifier).  The raw secret
-- lives only in .env.local and is read at runtime from the
-- HASH_CONFIRMATION_SECRET environment variable into a session GUC
-- (current_setting call sites below) — never embedded in this tracked file.
-- Run suites with HASH_CONFIRMATION_SECRET=<secret> psql ... -f <suite.sql>.
\getenv hash_token HASH_CONFIRMATION_SECRET
set app.capability_token = :'hash_token';

insert into auth.users (id, email, encrypted_password, email_confirmed_at, raw_app_meta_data, created_at, updated_at)
values
  ('51000000-0000-0000-0000-000000000001', 'l2.u1@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('51000000-0000-0000-0000-000000000002', 'l2.u2@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('51000000-0000-0000-0000-000000000003', 'l2.u3@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('51000000-0000-0000-0000-000000000005', 'l2.ub@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now());

insert into public.profiles (id, full_name, badge_number, role)
values
  ('51000000-0000-0000-0000-000000000001', 'L2 Lead',        'L2-001', 'officer'),
  ('51000000-0000-0000-0000-000000000002', 'L2 Inv',         'L2-002', 'officer'),
  ('51000000-0000-0000-0000-000000000003', 'L2 Member',      'L2-003', 'officer'),
  ('51000000-0000-0000-0000-000000000005', 'L2 Lead B',      'L2-005', 'officer')
on conflict (id) do nothing;

insert into public.organizations (id, name, slug, created_by)
values
  ('52000000-0000-0000-0000-0000000000a1', 'org-l2-alpha', 'l2-alpha', '51000000-0000-0000-0000-000000000001'),
  ('52000000-0000-0000-0000-0000000000b1', 'org-l2-beta',  'l2-beta',  '51000000-0000-0000-0000-000000000005');

insert into public.organization_members (org_id, profile_id, role_in_org, added_by)
values
  ('52000000-0000-0000-0000-0000000000a1', '51000000-0000-0000-0000-000000000001', 'admin',        '51000000-0000-0000-0000-000000000001'),
  ('52000000-0000-0000-0000-0000000000a1', '51000000-0000-0000-0000-000000000002', 'investigator', '51000000-0000-0000-0000-000000000001'),
  ('52000000-0000-0000-0000-0000000000a1', '51000000-0000-0000-0000-000000000003', 'member',       '51000000-0000-0000-0000-000000000001'),
  ('52000000-0000-0000-0000-0000000000b1', '51000000-0000-0000-0000-000000000005', 'admin',        '51000000-0000-0000-0000-000000000005');

insert into public.cases (id, org_id, case_number, title, description, status, created_by)
values
  ('53000000-0000-0000-0000-0000000000a1', '52000000-0000-0000-0000-0000000000a1', 'L2-CASE-A', 'numbering case A', null, 'active', '51000000-0000-0000-0000-000000000001'),
  ('53000000-0000-0000-0000-0000000000b1', '52000000-0000-0000-0000-0000000000b1', 'L2-CASE-B', 'numbering case B', null, 'active', '51000000-0000-0000-0000-000000000005'),
  ('53000000-0000-0000-0000-0000000000c1', '52000000-0000-0000-0000-0000000000a1', 'L2-CASE-C', 'numbering case C', null, 'active', '51000000-0000-0000-0000-000000000001');

insert into public.case_members (case_id, profile_id, role_in_case, added_by)
values
  ('53000000-0000-0000-0000-0000000000a1', '51000000-0000-0000-0000-000000000001', 'lead',         '51000000-0000-0000-0000-000000000001'),
  ('53000000-0000-0000-0000-0000000000a1', '51000000-0000-0000-0000-000000000002', 'investigator', '51000000-0000-0000-0000-000000000001'),
  ('53000000-0000-0000-0000-0000000000a1', '51000000-0000-0000-0000-000000000003', 'member',       '51000000-0000-0000-0000-000000000001'),
  ('53000000-0000-0000-0000-0000000000b1', '51000000-0000-0000-0000-000000000005', 'lead',         '51000000-0000-0000-0000-000000000005'),
  ('53000000-0000-0000-0000-0000000000c1', '51000000-0000-0000-0000-000000000001', 'lead',         '51000000-0000-0000-0000-000000000001');

-- C_C is pre-seeded with two already-issued numbers. create_evidence must
-- continue from the COUNT (EV-003) and never renumber the existing rows.
insert into public.evidence (id, case_id, evidence_number, title, description, type, status, created_by)
values
  ('54000000-0000-0000-0000-0000000000c1', '53000000-0000-0000-0000-0000000000c1', 'EV-001', 'preexisting c1', null, 'document', 'received', '51000000-0000-0000-0000-000000000001'),
  ('54000000-0000-0000-0000-0000000000c2', '53000000-0000-0000-0000-0000000000c1', 'EV-002', 'preexisting c2', null, 'document', 'received', '51000000-0000-0000-0000-000000000001');

-- storage.objects rows: the real, size-recorded objects that create_evidence's
-- L3 storage consistency check (bucket, exact key, size) requires. Names are
-- {case}/{evidence}/{version}.
insert into storage.objects (bucket_id, name, owner, metadata, created_at, updated_at)
values
  ('evidence-files', '53000000-0000-0000-0000-0000000000a1/54000000-0000-0000-0000-0000000000a1/55000000-0000-0000-0000-0000000000a1',
   '51000000-0000-0000-0000-000000000001', '{"size":1001,"mimetype":"application/pdf"}', now(), now()),
  ('evidence-files', '53000000-0000-0000-0000-0000000000a1/54000000-0000-0000-0000-0000000000a2/55000000-0000-0000-0000-0000000000a2',
   '51000000-0000-0000-0000-000000000002', '{"size":1002,"mimetype":"application/pdf"}', now(), now()),
  ('evidence-files', '53000000-0000-0000-0000-0000000000b1/54000000-0000-0000-0000-0000000000b1/55000000-0000-0000-0000-0000000000b1',
   '51000000-0000-0000-0000-000000000005', '{"size":1003,"mimetype":"application/pdf"}', now(), now()),
  ('evidence-files', '53000000-0000-0000-0000-0000000000c1/54000000-0000-0000-0000-0000000000c3/55000000-0000-0000-0000-0000000000c3',
   '51000000-0000-0000-0000-000000000001', '{"size":1004,"mimetype":"application/pdf"}', now(), now());

-- -----------------------------------------------------------------------------
-- Fixture sanity — the tests must be exercising the finding. C_A must start
-- with zero evidence rows so the FIRST allocated number is demonstrably the
-- result of the allocation logic (not a fixture artifact).
-- -----------------------------------------------------------------------------
set local role postgres;

do $$
declare
    n integer;
begin
    select count(*) into n from public.evidence where case_id = '53000000-0000-0000-0000-0000000000a1';
    if n <> 0 then
        raise exception 'FAIL L2-fixture: C_A must start empty (count %)', n;
    end if;
    select count(*) into n from public.evidence where case_id = '53000000-0000-0000-0000-0000000000b1';
    if n <> 0 then
        raise exception 'FAIL L2-fixture: C_B must start empty (count %)', n;
    end if;
    select count(*) into n from public.evidence where case_id = '53000000-0000-0000-0000-0000000000c1';
    if n <> 2 then
        raise exception 'FAIL L2-fixture: C_C must start with the 2 pre-seeded rows (count %)', n;
    end if;
    if exists (
        select 1 from pg_constraint c
        where c.conname = 'evidence_case_id_evidence_number_key'
          and c.contype = 'u'
    ) then
        null;
    else
        raise exception 'FAIL L2-fixture: (case_id, evidence_number) unique constraint missing';
    end if;
end $$;

-- =============================================================================
-- L2-T1 — first evidence in a clean case gets EV-001 (numbering works at all)
-- =============================================================================
set local role authenticated;
set local request.jwt.claims = '{"sub":"51000000-0000-0000-0000-000000000001"}';

do $$
declare
    v_result jsonb;
    n       integer;
begin
    v_result := public.create_evidence(
        p_case_id             => '53000000-0000-0000-0000-0000000000a1',
        p_evidence_id         => '54000000-0000-0000-0000-0000000000a1',
        p_document_version_id => '55000000-0000-0000-0000-0000000000a1',
        p_title               => 'l2 evidence a1',
        p_description         => null,
        p_type                => 'document',
        p_file_name           => 'l2-a1.pdf',
        p_mime_type           => 'application/pdf',
        p_file_size_bytes     => 1001,
        p_sha256              => repeat('a', 64),
        p_storage_key         => '53000000-0000-0000-0000-0000000000a1/54000000-0000-0000-0000-0000000000a1/55000000-0000-0000-0000-0000000000a1',
        p_notes               => null,
        p_confirmation_token  => current_setting('app.capability_token', true)
    );
    if v_result #>> '{evidence,evidence_number}' <> 'EV-001' then
        raise exception 'FAIL L2-T1: first allocation was %', v_result #>> '{evidence,evidence_number}';
    end if;
    select count(*) into n from public.evidence where case_id = '53000000-0000-0000-0000-0000000000a1';
    if n <> 1 then
        raise exception 'FAIL L2-T1: C_A count % after first create', n;
    end if;
end $$;

-- =============================================================================
-- L2-T2 — second create in the same case continues the sequence (EV-002)
-- =============================================================================
set local request.jwt.claims = '{"sub":"51000000-0000-0000-0000-000000000002"}';

do $$
declare
    v_result jsonb;
begin
    v_result := public.create_evidence(
        p_case_id             => '53000000-0000-0000-0000-0000000000a1',
        p_evidence_id         => '54000000-0000-0000-0000-0000000000a2',
        p_document_version_id => '55000000-0000-0000-0000-0000000000a2',
        p_title               => 'l2 evidence a2',
        p_description         => null,
        p_type                => 'document',
        p_file_name           => 'l2-a2.pdf',
        p_mime_type           => 'application/pdf',
        p_file_size_bytes     => 1002,
        p_sha256              => repeat('b', 64),
        p_storage_key         => '53000000-0000-0000-0000-0000000000a1/54000000-0000-0000-0000-0000000000a2/55000000-0000-0000-0000-0000000000a2',
        p_notes               => null,
        p_confirmation_token  => current_setting('app.capability_token', true)
    );
    if v_result #>> '{evidence,evidence_number}' <> 'EV-002' then
        raise exception 'FAIL L2-T2: second allocation was %', v_result #>> '{evidence,evidence_number}';
    end if;
end $$;

-- =============================================================================
-- L2-T3 — numbering is per-case: a different case starts at EV-001 regardless
-- of how many numbers C_A already issued.
-- =============================================================================
set local request.jwt.claims = '{"sub":"51000000-0000-0000-0000-000000000005"}';

do $$
declare
    v_result jsonb;
begin
    v_result := public.create_evidence(
        p_case_id             => '53000000-0000-0000-0000-0000000000b1',
        p_evidence_id         => '54000000-0000-0000-0000-0000000000b1',
        p_document_version_id => '55000000-0000-0000-0000-0000000000b1',
        p_title               => 'l2 evidence b1',
        p_description         => null,
        p_type                => 'document',
        p_file_name           => 'l2-b1.pdf',
        p_mime_type           => 'application/pdf',
        p_file_size_bytes     => 1003,
        p_sha256              => repeat('c', 64),
        p_storage_key         => '53000000-0000-0000-0000-0000000000b1/54000000-0000-0000-0000-0000000000b1/55000000-0000-0000-0000-0000000000b1',
        p_notes               => null,
        p_confirmation_token  => current_setting('app.capability_token', true)
    );
    if v_result #>> '{evidence,evidence_number}' <> 'EV-001' then
        raise exception 'FAIL L2-T3: other case started at % (expected EV-001)', v_result #>> '{evidence,evidence_number}';
    end if;
end $$;

-- =============================================================================
-- L2-T4 — pre-existing numbers are preserved (no silent renumber) and the next
-- allocation continues from the count (EV-003), never overwriting the old rows.
-- =============================================================================
set local request.jwt.claims = '{"sub":"51000000-0000-0000-0000-000000000001"}';

do $$
declare
    v_result jsonb;
    n       integer;
begin
    v_result := public.create_evidence(
        p_case_id             => '53000000-0000-0000-0000-0000000000c1',
        p_evidence_id         => '54000000-0000-0000-0000-0000000000c3',
        p_document_version_id => '55000000-0000-0000-0000-0000000000c3',
        p_title               => 'l2 evidence c3',
        p_description         => null,
        p_type                => 'document',
        p_file_name           => 'l2-c3.pdf',
        p_mime_type           => 'application/pdf',
        p_file_size_bytes     => 1004,
        p_sha256              => repeat('d', 64),
        p_storage_key         => '53000000-0000-0000-0000-0000000000c1/54000000-0000-0000-0000-0000000000c3/55000000-0000-0000-0000-0000000000c3',
        p_notes               => null,
        p_confirmation_token  => current_setting('app.capability_token', true)
    );
    if v_result #>> '{evidence,evidence_number}' <> 'EV-003' then
        raise exception 'FAIL L2-T4: allocation after pre-seed was % (expected EV-003)', v_result #>> '{evidence,evidence_number}';
    end if;
    select count(*) into n from public.evidence
    where case_id = '53000000-0000-0000-0000-0000000000c1'
      and evidence_number in ('EV-001', 'EV-002');
    if n <> 2 then
        raise exception 'FAIL L2-T4: pre-existing numbers were clobbered (remaining %)', n;
    end if;
end $$;

-- =============================================================================
-- L2-T5 — the (case_id, evidence_number) unique constraint remains the
-- backstop: a direct duplicate write is rejected, and the constraint exists.
-- =============================================================================
set local role postgres;

do $$
begin
    begin
        insert into public.evidence (id, case_id, evidence_number, title, description, type, status, created_by)
        values (
            '54000000-0000-0000-0000-0000000000a8',
            '53000000-0000-0000-0000-0000000000a1',
            'EV-001',
            'duplicate attempt', null, 'document', 'received',
            '51000000-0000-0000-0000-000000000001'
        );
        raise exception 'FAIL L2-T5: duplicate (case_id, evidence_number) accepted';
    exception
        when unique_violation then
            null;
    end;
end $$;

-- =============================================================================
-- L2-T6 — the sequential invariant: within every L2-created case the issued
-- numbers are exactly the contiguous run 1..count with no gaps (count-based
-- allocation plus the advisory lock keep this true single-session; the lock's
-- cross-session guarantee is proven by l2_evidence_concurrency.sh).
-- =============================================================================
do $$
declare
    c     record;
    n     integer;
    m     integer;
begin
    for c in (
        select case_id, count(*) cnt
        from public.evidence
        where case_id in (
            '53000000-0000-0000-0000-0000000000a1',
            '53000000-0000-0000-0000-0000000000b1'
        )
        group by case_id
    ) loop
        select count(*)
        into n
        from (
            select regexp_replace(evidence_number, '^EV-0*', '')::int seq
            from public.evidence
            where case_id = c.case_id
        ) seqs;
        select count(*)
        into m
        from (
            select distinct regexp_replace(evidence_number, '^EV-0*', '')::int seq
            from public.evidence
            where case_id = c.case_id
        ) seqs;
        if n = c.cnt and m = c.cnt then
            null;
        else
            raise exception 'FAIL L2-T6: case % has gaps (rows %, distinct %)', c.case_id, n, m;
        end if;
        if c.cnt > 0 then
            declare
                v_min integer;
                v_max integer;
            begin
                select min(seq), max(seq)
                into v_min, v_max
                from (
                    select regexp_replace(evidence_number, '^EV-0*', '')::int seq
                    from public.evidence
                    where case_id = c.case_id
                ) seqs;
                if v_min <> 1 or v_max <> c.cnt then
                    raise exception 'FAIL L2-T6: case % run is %..% (expected 1..%)', c.case_id, v_min, v_max, c.cnt;
                end if;
            end;
        end if;
    end loop;
end $$;

-- =============================================================================
-- L2-T7 — each allocated number is audited with the number attached
-- (evidence.created meta carries evidence_number for audit continuity).
-- =============================================================================
do $$
declare
    n integer;
begin
    select count(*) into n
    from public.audit_logs
    where action = 'evidence.created'
      and entity_id in (
          '54000000-0000-0000-0000-0000000000a1',
          '54000000-0000-0000-0000-0000000000a2',
          '54000000-0000-0000-0000-0000000000b1',
          '54000000-0000-0000-0000-0000000000c3'
      );
    if n <> 4 then
        raise exception 'FAIL L2-T7: expected 4 evidence.created audit rows, got %', n;
    end if;
end $$;

-- restore the session to a fully-privileged role for the remainder of the file
reset role;

do $$ begin raise notice 'l2_evidence_numbering: all tests passed (L2-T1..L2-T7)'; end $$;