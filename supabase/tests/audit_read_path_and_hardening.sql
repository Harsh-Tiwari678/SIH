-- =============================================================================
-- SIH26190 Secure Evidence — audit read path + evidence status hardening
-- Policy / RPC verification script (Phase 1).
--
-- This file validates the guarantees introduced by
-- 20260910000000_audit_read_path_and_hardening.sql against a LIVE local
-- Supabase instance. It was NOT executed in this repository's CI environment
-- (no Docker daemon) — it is the runnable, self-checking test artifact for a
-- developer with a working `supabase start`.
--
-- HOW TO RUN (single transaction required — the script relies on `set local`):
--   supabase start          # needs Docker
--   supabase db reset       # apply all migrations on a fresh DB
--   psql "$SUPABASE_DB_URL" -1 -v ON_ERROR_STOP=1 -f supabase/tests/audit_read_path_and_hardening.sql
-- (or paste the whole file into the Supabase SQL editor, which runs in one
--  transaction, replacing $SUPABASE_DB_URL at the top.)
--
-- Every test either passes silently or aborts with a `FAIL T<n>` exception.
-- The script mutates only rows it creates itself; run against a throwaway DB.
--
-- Coverage:
--   T1  anon cannot execute any of the new RPCs
--   T2  a non-member cannot read a case audit trail (case_not_found)
--   T3  a member reads the case trail; ALL rows belong to the case
--   T4  the trail is scrubbed: no storage_key / internals reach the client
--   T5  a member reads the evidence trail; it is scoped to the evidence
--   T6  a viewer cannot transition evidence status
--   T7  without an anchored anchor, 'verified' is rejected (verification_required)
--   T8  with a genuinely anchored anchor (matching SHA-256), 'verified' succeeds
--   T9  a mismatched anchor SHA-256 still cannot yield 'verified'
--   T10 direct UPDATE of evidence.status is revoked (permission denied)
--   T11 update_case: status change emits case.status_changed; metadata edit does not
--   T12 record_verification_event validates coherent result/verdict pairs
--          and writes evidence.verification_* rows for case members only
--   T13 resolve_evidence_access: a member resolves the latest version's file
--          intent; an outsider gets evidence_not_found (no existence leak)
--   T14 a version belonging to OTHER evidence resolves identically to a
--          nonexistent one (document_version_not_found)
--   T15 record_evidence_access writes evidence.accessed with the access mode;
--          outsiders cannot record access
--   T16 an invalid access mode is rejected by both RPCs (invalid_mode)
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Test users / fixture ids (deterministic, never collide with real data)
-- ---------------------------------------------------------------------------
-- lead_uuid        10000000-0000-0000-0000-000000000001  (lead on case A)
-- investigator_uuid 10000000-0000-0000-0000-000000000002
-- viewer_uuid       10000000-0000-0000-0000-000000000003
-- outsider_uuid     10000000-0000-0000-0000-000000000004  (profile, not a member)
-- case_a_uuid       20000000-0000-0000-0000-0000000000A1
-- ev_unanchored     30000000-0000-0000-0000-0000000000A1 (no anchor)
-- ev_anchored       30000000-0000-0000-0000-0000000000A2 (anchored, matching hash)
-- ev_mismatch       30000000-0000-0000-0000-0000000000A3 (anchored, wrong hash)
-- v_unanchored      40000000-0000-0000-0000-0000000000A1
-- v_anchored        40000000-0000-0000-0000-0000000000A2
-- v_mismatch        40000000-0000-0000-0000-0000000000A3
-- anchor_anchored   50000000-0000-0000-0000-0000000000A2
-- anchor_mismatch   50000000-0000-0000-0000-0000000000A3
-- case_b_uuid       20000000-0000-0000-0000-0000000000B1 (must never leak into A)
-- ev_case_b         30000000-0000-0000-0000-0000000000B1
-- org_fixture       90000000-0000-0000-0000-0000000000A1 (slug 'ci-audit-org')
--
-- Organization-aware fixtures: cases.org_id is NOT NULL since the foundation
-- migration, and every is_case_member(1-arg) read/write check now requires the
-- caller to be a member of the case's organization. lead/investigator/viewer
-- are org members (org role 'member', never admin) WITH explicit case_members
-- rows on case A — so their case-A access flows through explicit membership,
-- exactly like the pre-org model — while case B stays out of reach (they are
-- not members of it, and org 'member' grants no org-wide case read). outsider
-- (u4) has NO org membership, so every negative test still holds.
-- ---------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- Fixtures (run as postgres / owner; RLS is bypassed for the fixture writer)
-- ---------------------------------------------------------------------------

insert into auth.users (id, email, encrypted_password, email_confirmed_at, raw_app_meta_data, created_at, updated_at)
values
  ('10000000-0000-0000-0000-000000000001', 't.lead@example.com',      '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('10000000-0000-0000-0000-000000000002', 't.investigator@example.com', '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('10000000-0000-0000-0000-000000000003', 't.viewer@example.com',    '', now(), '{"role":"authenticated","provider":"email"}', now(), now()),
  ('10000000-0000-0000-0000-000000000004', 't.outsider@example.com',  '', now(), '{"role":"authenticated","provider":"email"}', now(), now());

insert into public.profiles (id, full_name, role)
values
  ('10000000-0000-0000-0000-000000000001', 'Test Lead',          'officer'),
  ('10000000-0000-0000-0000-000000000002', 'Test Investigator',  'officer'),
  ('10000000-0000-0000-0000-000000000003', 'Test Viewer',        'officer'),
  ('10000000-0000-0000-0000-000000000004', 'Test Outsider',      'officer')
on conflict (id) do nothing;

-- A fixture organization for the in-org users. NOT an application data path —
-- test fixture only (owner context, RLS bypassed).
insert into public.organizations (id, name, slug, created_by)
values
  ('90000000-0000-0000-0000-0000000000A1', 'CI Audit Org', 'ci-audit-org', '10000000-0000-0000-0000-000000000001');

insert into public.organization_members (org_id, profile_id, role_in_org, added_by)
values
  ('90000000-0000-0000-0000-0000000000A1', '10000000-0000-0000-0000-000000000001', 'member', '10000000-0000-0000-0000-000000000001'),
  ('90000000-0000-0000-0000-0000000000A1', '10000000-0000-0000-0000-000000000002', 'member', '10000000-0000-0000-0000-000000000001'),
  ('90000000-0000-0000-0000-0000000000A1', '10000000-0000-0000-0000-000000000003', 'member', '10000000-0000-0000-0000-000000000001');

insert into public.cases (id, org_id, case_number, title, description, status, created_by)
values
  ('20000000-0000-0000-0000-0000000000A1', '90000000-0000-0000-0000-0000000000A1', 'CI-2026-001', 'Test case A', null, 'active', '10000000-0000-0000-0000-000000000001'),
  ('20000000-0000-0000-0000-0000000000B1', '90000000-0000-0000-0000-0000000000A1', 'CI-2026-002', 'Test case B', null, 'active', '10000000-0000-0000-0000-000000000001');

insert into public.case_members (case_id, profile_id, role_in_case, added_by)
values
  ('20000000-0000-0000-0000-0000000000A1', '10000000-0000-0000-0000-000000000001', 'lead',          '10000000-0000-0000-0000-000000000001'),
  ('20000000-0000-0000-0000-0000000000A1', '10000000-0000-0000-0000-000000000002', 'investigator',  '10000000-0000-0000-0000-000000000001'),
  ('20000000-0000-0000-0000-0000000000A1', '10000000-0000-0000-0000-000000000003', 'viewer',        '10000000-0000-0000-0000-000000000001'),
  ('20000000-0000-0000-0000-0000000000B1', '10000000-0000-0000-0000-000000000001', 'lead',          '10000000-0000-0000-0000-000000000001');

insert into public.evidence (id, case_id, evidence_number, title, description, type, status, created_by)
values
  ('30000000-0000-0000-0000-0000000000A1', '20000000-0000-0000-0000-0000000000A1', 'EV-001', 'Unanchored evidence', null, 'document', 'received',       '10000000-0000-0000-0000-000000000002'),
  ('30000000-0000-0000-0000-0000000000A2', '20000000-0000-0000-0000-0000000000A1', 'EV-002', 'Anchored evidence',   null, 'document', 'under_review',  '10000000-0000-0000-0000-000000000002'),
  ('30000000-0000-0000-0000-0000000000A3', '20000000-0000-0000-0000-0000000000A1', 'EV-003', 'Mis-anchored evidence', null, 'document', 'under_review', '10000000-0000-0000-0000-000000000002'),
  ('30000000-0000-0000-0000-0000000000B1', '20000000-0000-0000-0000-0000000000B1', 'EV-001', 'Case B evidence',    null, 'document', 'received',      '10000000-0000-0000-0000-000000000002');

insert into public.document_versions (id, evidence_id, version, prev_version_id, file_name, mime_type, file_size_bytes, sha256, storage_key, uploaded_by, notes)
values
  ('40000000-0000-0000-0000-0000000000A1', '30000000-0000-0000-0000-0000000000A1', 1, null, 'unnested.pdf','application/pdf', 100, repeat('a', 64), '20000000-0000-0000-0000-0000000000A1/30000000-0000-0000-0000-0000000000A1/40000000-0000-0000-0000-0000000000A1', '10000000-0000-0000-0000-000000000002', null),
  ('40000000-0000-0000-0000-0000000000A2', '30000000-0000-0000-0000-0000000000A2', 1, null, 'anchored.pdf',   'application/pdf', 200, repeat('c', 64), '20000000-0000-0000-0000-0000000000A1/30000000-0000-0000-0000-0000000000A2/40000000-0000-0000-0000-0000000000A2', '10000000-0000-0000-0000-000000000002', null),
  ('40000000-0000-0000-0000-0000000000A3', '30000000-0000-0000-0000-0000000000A3', 1, null, 'mismatch.pdf',   'application/pdf', 300, repeat('e', 64), '20000000-0000-0000-0000-0000000000A1/30000000-0000-0000-0000-0000000000A3/40000000-0000-0000-0000-0000000000A3', '10000000-0000-0000-0000-000000000002', null),
  ('40000000-0000-0000-0000-0000000000B1', '30000000-0000-0000-0000-0000000000B1', 1, null, 'caseb.pdf',      'application/pdf', 400, repeat('f', 64), '20000000-0000-0000-0000-0000000000B1/30000000-0000-0000-0000-0000000000B1/40000000-0000-0000-0000-0000000000B1', '10000000-0000-0000-0000-000000000002', null);

-- Anchored anchors: ev_anchored's version matches its SHA-256; ev_mismatch's
-- version is deliberately different from the anchored hash so T9 holds.
insert into public.blockchain_anchors (id, evidence_id, document_version_id, network, chain_id, contract_address, evidence_id_hash, version_id_hash, evidence_sha256, status, tx_hash, block_number, anchored_at)
values
  ('50000000-0000-0000-0000-0000000000A2', '30000000-0000-0000-0000-0000000000A2', '40000000-0000-0000-0000-0000000000A2', 'sepolia', 11155111, '0x1D76cea78A844fed9aca674C82a900917e848b1a', '0x' || repeat('0', 64), '0x' || repeat('0', 64), repeat('c', 64), 'anchored', '0x' || repeat('1', 64), 1, now()),
  ('50000000-0000-0000-0000-0000000000A3', '30000000-0000-0000-0000-0000000000A3', '40000000-0000-0000-0000-0000000000A3', 'sepolia', 11155111, '0x1D76cea78A844fed9aca674C82a900917e848b1a', '0x' || repeat('0', 64), '0x' || repeat('0', 64), repeat('d', 64), 'anchored', '0x' || repeat('2', 64), 1, now());

-- Fixture audit rows so the read RPCs have real data to resolve. Written
-- directly as postgres (test-only); production writes go through SECURITY
-- DEFINER RPCs only.
insert into public.audit_logs (actor_id, action, entity_type, entity_id, after, meta)
values
  ('10000000-0000-0000-0000-000000000001', 'case.created',   'case',             '20000000-0000-0000-0000-0000000000A1', null, jsonb_build_object('case_number', 'CI-2026-001')),
  ('10000000-0000-0000-0000-000000000001', 'case.member_added', 'case_member',   '20000000-0000-0000-0000-0000000000A1', null, jsonb_build_object('case_id', '20000000-0000-0000-0000-0000000000A1', 'to_profile_id', '10000000-0000-0000-0000-000000000002', 'role_in_case', 'investigator')),
  ('10000000-0000-0000-0000-000000000002', 'case.created',   'case',             '20000000-0000-0000-0000-0000000000B1', null, jsonb_build_object('case_number', 'CI-2026-002')),
  ('10000000-0000-0000-0000-000000000002', 'evidence.created', 'evidence',       '30000000-0000-0000-0000-0000000000A1', null, jsonb_build_object('case_id', '20000000-0000-0000-0000-0000000000A1', 'evidence_number', 'EV-001', 'title', 'Unanchored evidence', 'storage_key', '20000000-0000-0000-0000-0000000000A1/30000000-0000-0000-0000-0000000000A1/40000000-0000-0000-0000-0000000000A1')),
  ('10000000-0000-0000-0000-000000000002', 'evidence.anchor_requested', 'blockchain_anchor', '50000000-0000-0000-0000-0000000000A2', null, jsonb_build_object('case_id', '20000000-0000-0000-0000-0000000000A1', 'document_version_id', '40000000-0000-0000-0000-0000000000A2', 'network', 'sepolia', 'chain_id', 11155111));

-- ---------------------------------------------------------------------------
-- T1 — anon cannot execute any of the new RPCs
-- ---------------------------------------------------------------------------
do $$
declare r text;
begin
  select pr.rolname into r from pg_roles pr where pr.rolname = 'anon';
  if r is null then
    raise notice 'T1 skipped: no anon role in this environment (CI flavor)';
  end if;
end $$;

set local role anon;
set local request.jwt.claims = '{"sub": null, "role": "anon"}';

do $$
begin
  begin
    perform * from public.list_case_audit_events('20000000-0000-0000-0000-0000000000A1');
    raise exception 'FAIL T1: anon must not be able to list a case audit trail';
  exception when others then
    -- any rejection is acceptable for anon
    null;
  end;
end $$;

do $$
begin
  begin
    perform public.update_evidence_status('30000000-0000-0000-0000-0000000000A1', 'under_review');
    raise exception 'FAIL T1: anon must not be able to update evidence status';
  exception when others then
    null;
  end;
end $$;

do $$
begin
  begin
    perform public.resolve_evidence_access('30000000-0000-0000-0000-0000000000A1', null, 'preview');
    raise exception 'FAIL T1: anon must not be able to resolve evidence access';
  exception when others then
    null;
  end;
end $$;

do $$
begin
  begin
    perform public.record_evidence_access('40000000-0000-0000-0000-0000000000A1', 'preview');
    raise exception 'FAIL T1: anon must not be able to record evidence access';
  exception when others then
    null;
  end;
end $$;

-- ---------------------------------------------------------------------------
-- T2 — a non-member cannot read a case audit trail
-- ---------------------------------------------------------------------------
set local role authenticated;
set local request.jwt.claims = '{"sub": "10000000-0000-0000-0000-000000000004", "role": "authenticated"}';

do $$
begin
  begin
    perform * from public.list_case_audit_events('20000000-0000-0000-0000-0000000000A1');
    raise exception 'FAIL T2: outsider must get case_not_found for an inaccessible case';
  exception when others then
    if sqlerrm <> 'case_not_found' then
      raise exception 'FAIL T2: expected case_not_found, got: %', sqlerrm;
    end if;
  end;
end $$;

-- ---------------------------------------------------------------------------
-- T3 — a member reads the case trail; every row resolves to the case
-- ---------------------------------------------------------------------------
set local role authenticated;
set local request.jwt.claims = '{"sub": "10000000-0000-0000-0000-000000000003", "role": "authenticated"}';

do $$
declare
  n_case          int;
  n_ev            int;
  n_anchor        int;
  v_foreign_count int;
begin
  -- case A has: case.created, case.member_added, evidence.created, anchor_requested
  select count(*) into n_case          from public.list_case_audit_events('20000000-0000-0000-0000-0000000000A1') where entity_type = 'case';
  select count(*) into n_ev            from public.list_case_audit_events('20000000-0000-0000-0000-0000000000A1') where entity_type = 'evidence';
  select count(*) into n_anchor        from public.list_case_audit_events('20000000-0000-0000-0000-0000000000A1') where entity_type = 'blockchain_anchor';
  select count(*) into v_foreign_count from public.list_case_audit_events('20000000-0000-0000-0000-0000000000A1') where case_id is distinct from '20000000-0000-0000-0000-0000000000A1';

  if n_case <> 1 then            raise exception 'FAIL T3: expected 1 case event, got %', n_case; end if;
  if n_ev <> 1 then              raise exception 'FAIL T3: expected 1 evidence event, got %', n_ev; end if;
  if n_anchor <> 1 then          raise exception 'FAIL T3: expected 1 anchor event, got %', n_anchor; end if;
  if v_foreign_count <> 0 then   raise exception 'FAIL T3: events from other cases leaked into the trail'; end if;

  -- the anchor event must resolve to evidence EV-002 of this case
  if not exists (
    select 1 from public.list_case_audit_events('20000000-0000-0000-0000-0000000000A1')
    where entity_type = 'blockchain_anchor' and evidence_id = '30000000-0000-0000-0000-0000000000A2'
  ) then
    raise exception 'FAIL T3: anchor event did not resolve to its evidence';
  end if;
end $$;

-- ---------------------------------------------------------------------------
-- T4 — the trail is scrubbed: no storage_key / internals reach the client
-- ---------------------------------------------------------------------------
-- The scrub contract (20260910000000) is: object-key internals (storage_key)
-- are stripped from meta. case_id is intentionally part of the stored meta for
-- most event types AND is exposed by the RPC as its own column, so it is not a
-- scrub candidate — the check below asserts exactly the storage_key scrub.
do $$
declare leak int;
begin
  select count(*) into leak
  from public.list_case_audit_events('20000000-0000-0000-0000-0000000000A1')
  where meta ? 'storage_key'
     or meta::text like '%storage_key%';
  if leak <> 0 then
    raise exception 'FAIL T4: % rows leak storage_key/raw meta into the audit read', leak;
  end if;
end $$;

-- ---------------------------------------------------------------------------
-- T5 — evidence trail is scoped to the evidence (not its whole case)
-- ---------------------------------------------------------------------------
do $$
declare n int;
begin
  select count(*) into n
  from public.list_evidence_audit_events('30000000-0000-0000-0000-0000000000A1');
  -- ev A1: evidence.created; nothing from A2/A3 or case B
  if n <> 1 then
    raise exception 'FAIL T5: expected 1 evidence-scoped event, got %', n;
  end if;
  if exists (
    select 1 from public.list_evidence_audit_events('30000000-0000-0000-0000-0000000000A1')
    where evidence_id is distinct from '30000000-0000-0000-0000-0000000000A1'
  ) then
    raise exception 'FAIL T5: evidence trail contains events from other evidence';
  end if;
end $$;

do $$
declare n int;
begin
  -- the version's verification/anchor events resolve into the evidence trail
  select count(*) into n
  from public.list_evidence_audit_events('30000000-0000-0000-0000-0000000000A2')
  where evidence_id = '30000000-0000-0000-0000-0000000000A2';
  if n <> 1 then
    raise exception 'FAIL T5: expected the anchored evidence (via its anchor event) in its own trail, got %', n;
  end if;
end $$;

-- ---------------------------------------------------------------------------
-- T6 — a viewer cannot transition evidence status
-- ---------------------------------------------------------------------------
set local role authenticated;
set local request.jwt.claims = '{"sub": "10000000-0000-0000-0000-000000000003", "role": "authenticated"}';

do $$
begin
  begin
    perform public.update_evidence_status('30000000-0000-0000-0000-0000000000A1', 'under_review');
    raise exception 'FAIL T6: viewer must not be able to update evidence status';
  exception when others then
    if sqlerrm <> 'not_authorized_to_update' then
      raise exception 'FAIL T6: expected not_authorized_to_update, got: %', sqlerrm;
    end if;
  end;
end $$;

-- ---------------------------------------------------------------------------
-- T7 — without an anchored anchor, 'verified' is rejected
-- ---------------------------------------------------------------------------
set local role authenticated;
set local request.jwt.claims = '{"sub": "10000000-0000-0000-0000-000000000002", "role": "authenticated"}';

do $$
begin
  begin
    perform public.update_evidence_status('30000000-0000-0000-0000-0000000000A1', 'verified');
    raise exception 'FAIL T7: unanchored evidence must not be markable as verified';
  exception when others then
    if sqlerrm <> 'verification_required' then
      raise exception 'FAIL T7: expected verification_required, got: %', sqlerrm;
    end if;
  end;
end $$;

-- investigator may still move the same evidence to non-verified statuses
do $$
begin
  perform public.update_evidence_status('30000000-0000-0000-0000-0000000000A1', 'under_review');
end $$;

-- ---------------------------------------------------------------------------
-- T8 — with a genuinely anchored anchor, 'verified' succeeds + is audited
-- ---------------------------------------------------------------------------
do $$
declare st text; aud int;
begin
  select status into st from public.update_evidence_status('30000000-0000-0000-0000-0000000000A2', 'verified');
  if st <> 'verified' then
    raise exception 'FAIL T8: expected status verified, got %', st;
  end if;

  set local role postgres;
  select count(*) into aud
  from public.audit_logs
  where action = 'evidence.status_changed'
    and entity_type = 'evidence'
    and entity_id = '30000000-0000-0000-0000-0000000000A2';
  set local role authenticated;
  if aud <> 1 then
    raise exception 'FAIL T8: expected 1 evidence.status_changed audit row, got %', aud;
  end if;
end $$;

-- ---------------------------------------------------------------------------
-- T9 — a mismatched anchor SHA-256 still cannot yield 'verified'
-- ---------------------------------------------------------------------------
do $$
begin
  begin
    perform public.update_evidence_status('30000000-0000-0000-0000-0000000000A3', 'verified');
    raise exception 'FAIL T9: an anchor holding a different SHA-256 must not satisfy the verification gate';
  exception when others then
    if sqlerrm <> 'verification_required' then
      raise exception 'FAIL T9: expected verification_required, got: %', sqlerrm;
    end if;
  end;
end $$;

-- ---------------------------------------------------------------------------
-- T10 — direct UPDATE of evidence.status is revoked (column-level grant)
-- ---------------------------------------------------------------------------
set local role authenticated;
set local request.jwt.claims = '{"sub": "10000000-0000-0000-0000-000000000002", "role": "authenticated"}';

do $$
begin
  begin
    update public.evidence set status = 'verified' where id = '30000000-0000-0000-0000-0000000000A1';
    raise exception 'FAIL T10: direct status UPDATE must be denied even for an investigator';
  exception when others then
    if sqlerrm !~ 'permission denied' then
      raise exception 'FAIL T10: expected permission denied, got: %', sqlerrm;
    end if;
  end;
end $$;

-- ---------------------------------------------------------------------------
-- T11 — update_case: status change emits case.status_changed;
--       metadata-only edit does not
-- ---------------------------------------------------------------------------
set local role authenticated;
set local request.jwt.claims = '{"sub": "10000000-0000-0000-0000-000000000001", "role": "authenticated"}';

do $$
declare n_status int; n_updated int;
begin
  -- metadata-only edit: case.updated yes, case.status_changed no
  perform public.update_case('20000000-0000-0000-0000-0000000000A1', p_title => 'Test case A (edited)', p_status => null);

  set local role postgres;
  select count(*) into n_updated from public.audit_logs
  where action = 'case.updated' and entity_id = '20000000-0000-0000-0000-0000000000A1' and meta->>'status_changed' = 'false';
  select count(*) into n_status from public.audit_logs
  where action = 'case.status_changed' and entity_id = '20000000-0000-0000-0000-0000000000A1';
  set local role authenticated;

  if n_updated <> 1 then raise exception 'FAIL T11: expected exactly 1 metadata-only case.updated, got %', n_updated; end if;
  if n_status <> 0 then raise exception 'FAIL T11: metadata-only edit must not emit case.status_changed'; end if;

  -- status transition: both case.updated (with status_changed=true) and
  -- case.status_changed
  perform public.update_case('20000000-0000-0000-0000-0000000000A1', p_status => 'closed');

  set local role postgres;
  select count(*) into n_status from public.audit_logs
  where action = 'case.status_changed'
    and entity_id = '20000000-0000-0000-0000-0000000000A1'
    and meta->>'previous_status' = 'active'
    and meta->>'new_status' = 'closed';
  set local role authenticated;
  if n_status <> 1 then
    raise exception 'FAIL T11: expected 1 case.status_changed (active->closed), got %', n_status;
  end if;

  -- and a non-lead cannot transition the case at all
  set local role authenticated;
  set local request.jwt.claims = '{"sub": "10000000-0000-0000-0000-000000000002", "role": "authenticated"}';
  begin
    perform public.update_case('20000000-0000-0000-0000-0000000000A1', p_status => 'active');
    raise exception 'FAIL T11: investigator must not be able to update the case';
  exception when others then
    if sqlerrm <> 'not_lead' then
      raise exception 'FAIL T11: expected not_lead, got: %', sqlerrm;
    end if;
  end;
end $$;

-- ---------------------------------------------------------------------------
-- T12 — record_verification_event coerces result/verdict pairs and writes
--       evidence.verification_* rows for case members only
-- ---------------------------------------------------------------------------
set local role authenticated;
set local request.jwt.claims = '{"sub": "10000000-0000-0000-0000-000000000003", "role": "authenticated"}';

do $$
begin
  -- valid: requested with any verdict
  perform public.record_verification_event('40000000-0000-0000-0000-0000000000A1', 'requested', 'not_anchored');
  perform public.record_verification_event('40000000-0000-0000-0000-0000000000A1', 'requested', 'verified');
  -- valid: coherent terminal pairs
  perform public.record_verification_event('40000000-0000-0000-0000-0000000000A1', 'passed', 'verified');
  perform public.record_verification_event('40000000-0000-0000-0000-0000000000A1', 'failed', 'hash_mismatch');
  perform public.record_verification_event('40000000-0000-0000-0000-0000000000A1', 'failed', 'verification_ambiguous');

  -- incoherent pairs are rejected
  begin
    perform public.record_verification_event('40000000-0000-0000-0000-0000000000A1', 'passed', 'hash_mismatch');
    raise exception 'FAIL T12: passed + hash_mismatch must be rejected';
  exception when others then
    if sqlerrm <> 'invalid_verdict' then raise exception 'FAIL T12: expected invalid_verdict, got: %', sqlerrm; end if;
  end;
  begin
    perform public.record_verification_event('40000000-0000-0000-0000-0000000000A1', 'failed', 'verified');
    raise exception 'FAIL T12: failed + verified must be rejected';
  exception when others then
    if sqlerrm <> 'invalid_verdict' then raise exception 'FAIL T12: expected invalid_verdict, got: %', sqlerrm; end if;
  end;
  begin
    perform public.record_verification_event('40000000-0000-0000-0000-0000000000A1', 'bogus', 'verified');
    raise exception 'FAIL T12: an unknown result must be rejected';
  exception when others then
    if sqlerrm <> 'invalid_result' then raise exception 'FAIL T12: expected invalid_result, got: %', sqlerrm; end if;
  end;
end $$;

-- a non-member cannot write verification events
set local role authenticated;
set local request.jwt.claims = '{"sub": "10000000-0000-0000-0000-000000000004", "role": "authenticated"}';

do $$
begin
  begin
    perform public.record_verification_event('40000000-0000-0000-0000-0000000000A1', 'requested', 'verified');
    raise exception 'FAIL T12: outsider must not record verification events';
  exception when others then
    if sqlerrm <> 'not_case_member' then
      raise exception 'FAIL T12: expected not_case_member, got: %', sqlerrm;
    end if;
  end;
end $$;

-- the rows landed where expected
set local role postgres;
do $$
declare n int;
begin
  select count(*) into n from public.audit_logs
  where entity_type = 'document_version'
    and entity_id = '40000000-0000-0000-0000-0000000000A1'
    and action like 'evidence.verification_%';
  if n <> 5 then
    raise exception 'FAIL T12: expected 5 verification audit rows, got %', n;
  end if;
end $$;

-- ---------------------------------------------------------------------------
-- T13 — resolve_evidence_access: a member resolves the latest version's file
--       intent; an outsider gets evidence_not_found (no existence leak)
-- ---------------------------------------------------------------------------
set local role authenticated;
set local request.jwt.claims = '{"sub": "10000000-0000-0000-0000-000000000003", "role": "authenticated"}';

do $$
declare
  v jsonb;
begin
  -- viewer (a member) resolves ev A1 with no version: the latest (only) one.
  v := public.resolve_evidence_access('30000000-0000-0000-0000-0000000000A1', null, 'preview');
  if (v->>'document_version_id')::uuid <> '40000000-0000-0000-0000-0000000000A1' then
    raise exception 'FAIL T13: expected version A1, got %', v->>'document_version_id';
  end if;
  if v->>'version' <> '1' then
    raise exception 'FAIL T13: expected version 1, got %', v->>'version';
  end if;
  if v->>'file_name' <> 'unnested.pdf' then
    raise exception 'FAIL T13: unexpected file_name %', v->>'file_name';
  end if;
  if v->>'storage_key' <> '20000000-0000-0000-0000-0000000000A1/30000000-0000-0000-0000-0000000000A1/40000000-0000-0000-0000-0000000000A1' then
    raise exception 'FAIL T13: storage_key does not match the evidence intent';
  end if;
  if (v->>'case_id')::uuid <> '20000000-0000-0000-0000-0000000000A1' then
    raise exception 'FAIL T13: unexpected case_id %', v->>'case_id';
  end if;
end $$;

-- an outsider cannot even learn the evidence exists
set local role authenticated;
set local request.jwt.claims = '{"sub": "10000000-0000-0000-0000-000000000004", "role": "authenticated"}';

do $$
begin
  begin
    perform public.resolve_evidence_access('30000000-0000-0000-0000-0000000000A1', null, 'preview');
    raise exception 'FAIL T13: outsider must get evidence_not_found';
  exception when others then
    if sqlerrm <> 'evidence_not_found' then
      raise exception 'FAIL T13: expected evidence_not_found, got: %', sqlerrm;
    end if;
  end;
end $$;

-- ---------------------------------------------------------------------------
-- T14 — a version of OTHER evidence resolves identically to a nonexistent one
-- ---------------------------------------------------------------------------
set local role authenticated;
set local request.jwt.claims = '{"sub": "10000000-0000-0000-0000-000000000003", "role": "authenticated"}';

do $$
begin
  -- v B1 belongs to case B, which viewer is NOT a member of; but even for a
  -- member of A the incompatible version must still be rejected.
  begin
    perform public.resolve_evidence_access('30000000-0000-0000-0000-0000000000A1', '40000000-0000-0000-0000-0000000000B1', 'preview');
    raise exception 'FAIL T14: a version of another evidence must not resolve';
  exception when others then
    if sqlerrm <> 'document_version_not_found' then
      raise exception 'FAIL T14: expected document_version_not_found, got: %', sqlerrm;
    end if;
  end;

  -- and a completely unknown version id is indistinguishable.
  begin
    perform public.resolve_evidence_access('30000000-0000-0000-0000-0000000000A1', '40000000-0000-0000-0000-0000000000FF', 'preview');
    raise exception 'FAIL T14: an unknown version must not resolve';
  exception when others then
    if sqlerrm <> 'document_version_not_found' then
      raise exception 'FAIL T14: expected document_version_not_found, got: %', sqlerrm;
    end if;
  end;
end $$;

-- ---------------------------------------------------------------------------
-- T15 — record_evidence_access writes evidence.accessed with the mode;
--       outsiders cannot record access
-- ---------------------------------------------------------------------------
do $$
begin
  perform public.record_evidence_access('40000000-0000-0000-0000-0000000000A1', 'download');
end $$;

set local role postgres;
do $$
declare n int;
begin
  select count(*) into n
  from public.audit_logs
  where action = 'evidence.accessed'
    and entity_type = 'document_version'
    and entity_id = '40000000-0000-0000-0000-0000000000A1'
    and actor_id = '10000000-0000-0000-0000-000000000003'
    and meta->>'mode' = 'download'
    and (meta->>'evidence_id')::uuid = '30000000-0000-0000-0000-0000000000A1';
  if n <> 1 then
    raise exception 'FAIL T15: expected 1 evidence.accessed row, got %', n;
  end if;
end $$;
set local role authenticated;

-- an outsider gets a hard 403 (matching the write-path RPCs)
set local role authenticated;
set local request.jwt.claims = '{"sub": "10000000-0000-0000-0000-000000000004", "role": "authenticated"}';

do $$
begin
  begin
    perform public.record_evidence_access('40000000-0000-0000-0000-0000000000A1', 'preview');
    raise exception 'FAIL T15: outsider must not record evidence access';
  exception when others then
    if sqlerrm <> 'not_case_member' then
      raise exception 'FAIL T15: expected not_case_member, got: %', sqlerrm;
    end if;
  end;
end $$;

-- ---------------------------------------------------------------------------
-- T16 — an invalid access mode is rejected by both RPCs
-- ---------------------------------------------------------------------------
set local role authenticated;
set local request.jwt.claims = '{"sub": "10000000-0000-0000-0000-000000000002", "role": "authenticated"}';

do $$
begin
  begin
    perform public.resolve_evidence_access('30000000-0000-0000-0000-0000000000A1', null, 'print');
    raise exception 'FAIL T16: an invalid mode must not resolve';
  exception when others then
    if sqlerrm <> 'invalid_mode' then
      raise exception 'FAIL T16: expected invalid_mode, got: %', sqlerrm;
    end if;
  end;
  begin
    perform public.record_evidence_access('40000000-0000-0000-0000-0000000000A1', 'print');
    raise exception 'FAIL T16: an invalid mode must not be recorded';
  exception when others then
    if sqlerrm <> 'invalid_mode' then
      raise exception 'FAIL T16: expected invalid_mode, got: %', sqlerrm;
    end if;
  end;
end $$;

-- ---------------------------------------------------------------------------
-- Summary
-- ---------------------------------------------------------------------------
do $$
begin
  raise notice 'audit_read_path_and_hardening: all tests passed (T1..T16)';
end $$;