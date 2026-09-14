#!/usr/bin/env bash
# =============================================================================
# SIH26190 Secure Evidence — L2 concurrency oracle (evidence numbering)
#
# Proves the ATOMICITY of the per-case sequential evidence-number allocation
# under two concurrent same-case creators, and doubles as the non-vacuous
# mutation check: if the advisory lock is removed (see MUTATED mode), the
# second session lands on the unique index of the first session's row and
# FAILS instead of receiving the next number.
#
# REQUIREMENTS
#   * A freshly reset local database (supabase db reset) — the fixtures below
#     are inserted as postgres and the script's assertions assume EV-001 is
#     the first number ever allocated to case 530..a1.
#   * MUTATED=1 additionally expects the DB to already carry a weakened
#     create_evidence() (advisory-lock block removed). The harness applies the
#     mutation migration BEFORE calling the script with MUTATED=1.
#
#   Each create_evidence() passes p_confirmation_token = the RAW server-only
#   HASH_CONFIRMATION_SECRET (L3.1 capability gate, migration 20260925000000).
#   The DB hashes the supplied token inside PostgreSQL and compares the
#   computed digest to its verifier, so the digest constant in the migration
#   does NOT authenticate.  The raw secret lives only in .env.local and is
#   read here at runtime (HASH_CONFIRMATION_SECRET env var, falling back to
#   .env.local) — it is never embedded in this tracked file.
#
# ORCHESTRATION (deterministic)
#   session A : begin; create_evidence(...); pg_sleep(4); commit;
#               -> holds the per-case lock for 4s inside an OPEN transaction
#   session B : begin; create_evidence(...); commit;          (launched 1s later)
#   Under the FIXED code B blocks on the advisory lock, then proceeds to the
#   next free number (both succeed, numbers {EV-001, EV-002}, count 2).
#   Under the MUTATION (no lock) B blocks on the unique index of A's visible
#   row and dies with unique_violation when A commits.
#
# FIXTURES
#   u1 510..0001 lead C_A | u2 510..0002 investigator C_A
#   org_a 520..a1 | C_A 530..a1 (active) | storage.objects rows for both keys.
# =============================================================================
set -u

PSQL="psql postgresql://postgres:postgres@127.0.0.1:54322/postgres"
CASE_A="53000000-0000-0000-0000-0000000000a1"
EVA_1="54000000-0000-0000-0000-0000000000a1"
EVA_2="54000000-0000-0000-0000-0000000000a2"
V_A_1="55000000-0000-0000-0000-0000000000a1"
V_A_2="55000000-0000-0000-0000-0000000000a2"
KEY_A_1="${CASE_A}/${EVA_1}/${V_A_1}"
KEY_A_2="${CASE_A}/${EVA_2}/${V_A_2}"

fail() { echo "L2-CONC: FAIL $*"; exit 1; }
pass() { echo "L2-CONC: PASS $*"; }

# -- runtime capability token ---------------------------------------------------
# Raw HASH_CONFIRMATION_SECRET, never committed.  Prefer the environment when
# provided; otherwise source it from .env.local in the repo root.
HASH_TOKEN="${HASH_CONFIRMATION_SECRET:-$(sed -n 's/^HASH_CONFIRMATION_SECRET=//p' .env.local 2>/dev/null)}"
[ -n "$HASH_TOKEN" ] || fail "HASH_CONFIRMATION_SECRET not found (env or .env.local)"

# -- fixtures ------------------------------------------------------------------
$PSQL -1 -v ON_ERROR_STOP=1 -q >/dev/null 2>&1 <<SQL || fail "fixture prep"
insert into auth.users (id, email, encrypted_password, email_confirmed_at, raw_app_meta_data, created_at, updated_at) values
  ('51000000-0000-0000-0000-000000000001','l2c.u1@example.com','',now(),'{"role":"authenticated","provider":"email"}',now(),now()),
  ('51000000-0000-0000-0000-000000000002','l2c.u2@example.com','',now(),'{"role":"authenticated","provider":"email"}',now(),now());
insert into public.profiles (id, full_name, badge_number, role) values
  ('51000000-0000-0000-0000-000000000001','L2C Lead','L2C-01','officer'),
  ('51000000-0000-0000-0000-000000000002','L2C Inv','L2C-02','officer')
on conflict (id) do nothing;
insert into public.organizations (id, name, slug, created_by) values
  ('52000000-0000-0000-0000-0000000000a1','org-l2c-alpha','l2c-alpha','51000000-0000-0000-0000-000000000001');
insert into public.organization_members (org_id, profile_id, role_in_org, added_by) values
  ('52000000-0000-0000-0000-0000000000a1','51000000-0000-0000-0000-000000000001','admin','51000000-0000-0000-0000-000000000001'),
  ('52000000-0000-0000-0000-0000000000a1','51000000-0000-0000-0000-000000000002','investigator','51000000-0000-0000-0000-000000000001');
insert into public.cases (id, org_id, case_number, title, description, status, created_by) values
  ('${CASE_A}','52000000-0000-0000-0000-0000000000a1','L2C-CASE','l2c concurrency case',null,'active','51000000-0000-0000-0000-000000000001');
insert into public.case_members (case_id, profile_id, role_in_case, added_by) values
  ('${CASE_A}','51000000-0000-0000-0000-000000000001','lead','51000000-0000-0000-0000-000000000001'),
  ('${CASE_A}','51000000-0000-0000-0000-000000000002','investigator','51000000-0000-0000-0000-000000000001');
insert into storage.objects (bucket_id, name, owner, metadata, created_at, updated_at) values
  ('evidence-files','${KEY_A_1}','51000000-0000-0000-0000-000000000001','{"size":1101,"mimetype":"application/pdf"}',now(),now()),
  ('evidence-files','${KEY_A_2}','51000000-0000-0000-0000-000000000002','{"size":1102,"mimetype":"application/pdf"}',now(),now());
SQL

# -- concurrent sessions ---------------------------------------------------------
rm -f /tmp/opencode/l2c_A.out /tmp/opencode/l2c_B.out
( $PSQL -q -At -c "
begin;
set local role authenticated;
set local request.jwt.claims = '{\"sub\":\"51000000-0000-0000-0000-000000000001\"}';
select public.create_evidence(
  '${CASE_A}','${EVA_1}','${V_A_1}','l2c ev a1',null,'document','l2c-a1.pdf','application/pdf',
  1101, repeat('a',64), '${KEY_A_1}', null, '${HASH_TOKEN}') #>> '{evidence,evidence_number}' as evnum;
select pg_sleep(4);
commit;" > /tmp/opencode/l2c_A.out 2>&1 ) &
APID=$!

sleep 1

( $PSQL -q -At -c "
begin;
set local role authenticated;
set local request.jwt.claims = '{\"sub\":\"51000000-0000-0000-0000-000000000002\"}';
select public.create_evidence(
  '${CASE_A}','${EVA_2}','${V_A_2}','l2c ev a2',null,'document','l2c-a2.pdf','application/pdf',
  1102, repeat('b',64), '${KEY_A_2}', null, '${HASH_TOKEN}') #>> '{evidence,evidence_number}' as evnum;
commit;" > /tmp/opencode/l2c_B.out 2>&1 ) &
BPID=$!

wait $APID; A_RC=$?
wait $BPID; B_RC=$?

# -- assertions ------------------------------------------------------------------
A_NUM=$(grep -oE 'EV-[0-9]{3}' /tmp/opencode/l2c_A.out | head -1)
B_NUM=$(grep -oE 'EV-[0-9]{3}' /tmp/opencode/l2c_B.out | head -1)

if [ "${MUTATED:-0}" = "1" ]; then
  # Mutation expects session B (the second, lockless creator) to FAIL: A's
  # uncommitted EV-001 blocks B on the unique index and A's commit turns it
  # into a unique_violation. Session A must still have succeeded.
  [ "$A_RC" -eq 0 ]   || fail "session A should have succeeded (rc=$A_RC) but did not"
  [ "$A_NUM" = "EV-001" ] || fail "session A number was '$A_NUM' (expected EV-001)"
  [ "$B_RC" -ne 0 ]   || fail "mutation: session B succeeded ($B_NUM) without the advisory lock"
  grep -qi 'unique_violation\|duplicate key value' /tmp/opencode/l2c_B.out \
      || fail "mutation: session B failed but not with unique_violation: $(cat /tmp/opencode/l2c_B.out)"
  pass "mutation: lockless allocation failed closed for the second session"
  exit 0
fi

# Fixed code: BOTH sessions must succeed and receive the two distinct adjacent
# numbers of the case. (Which session physically got the lock first is
# irrelevant; the guarantee is both succeed with no duplicate.)
[ "$A_RC" -eq 0 ] || fail "session A rc=$A_RC"
[ "$B_RC" -eq 0 ] || fail "session B rc=$B_RC"
[ -n "$A_NUM" ]   || fail "session A produced no number"
[ -n "$B_NUM" ]   || fail "session B produced no number"
[ "$A_NUM" != "$B_NUM" ] || fail "both sessions received the same number '$A_NUM'"

POST_NUMBERS=$($PSQL -q -At -c "select array_agg(evidence_number order by evidence_number) from public.evidence where case_id='${CASE_A}';")
POST_COUNT=$($PSQL -q -At -c "select count(*) from public.evidence where case_id='${CASE_A}';")
[ "$POST_COUNT" = "2" ] || fail "post state count '$POST_COUNT' (expected 2)"
[ "$POST_NUMBERS" = "{EV-001,EV-002}" ] || fail "post state numbers '$POST_NUMBERS' (expected {EV-001,EV-002})"

pass "both sessions succeeded, numbers '$A_NUM' and '$B_NUM', final state $POST_NUMBERS"
exit 0