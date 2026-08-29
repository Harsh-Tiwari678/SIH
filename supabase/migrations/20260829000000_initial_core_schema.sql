-- SIH26190 Secure Evidence — initial core schema
--
-- Creates only the seven core tables plus supporting indexes and integrity
-- CHECK constraints. Deliberately creates:
--   * no RLS policies (added in a later migration, per approved design)
--   * no triggers (updated_at is app-managed)
--   * no AI/ML tables
--
-- Security / evidence-integrity decisions encoded in this schema:
--   * All operational references use ON DELETE RESTRICT so case, evidence,
--     document-version, and custody history can never be silently deleted.
--   * profiles.id *is* the authenticated user's uuid (auth.users), the only
--     link to Supabase Auth identity. Supabase Auth owns identity and
--     credentials.
--   * No password or credential columns exist anywhere in this schema.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1) profiles
-- -----------------------------------------------------------------------------
create table public.profiles (
    id           uuid primary key default gen_random_uuid()
                 references auth.users (id) on delete cascade,
    full_name    text not null,
    badge_number text unique,
    role         text not null default 'officer',
    created_at   timestamptz not null default now(),
    updated_at   timestamptz not null default now()
);

-- -----------------------------------------------------------------------------
-- 2) cases
-- -----------------------------------------------------------------------------
create table public.cases (
    id          uuid primary key default gen_random_uuid(),
    case_number text not null unique,
    title       text not null,
    description text,
    status      text not null default 'active'
                check (status in ('draft', 'active', 'closed', 'archived')),
    created_by  uuid not null references public.profiles (id) on delete restrict,
    created_at  timestamptz not null default now(),
    updated_at  timestamptz not null default now(),
    closed_at   timestamptz,
    closed_by   uuid references public.profiles (id) on delete restrict,
    check ((closed_at is null) = (closed_by is null))
);

-- -----------------------------------------------------------------------------
-- 3) case_members
-- -----------------------------------------------------------------------------
create table public.case_members (
    id           uuid primary key default gen_random_uuid(),
    case_id      uuid not null references public.cases (id) on delete restrict,
    profile_id   uuid not null references public.profiles (id) on delete restrict,
    role_in_case text not null default 'member',
    added_by     uuid not null references public.profiles (id) on delete restrict,
    added_at     timestamptz not null default now(),
    unique (case_id, profile_id)
);

-- -----------------------------------------------------------------------------
-- 4) evidence
-- -----------------------------------------------------------------------------
create table public.evidence (
    id              uuid primary key default gen_random_uuid(),
    case_id         uuid not null references public.cases (id) on delete restrict,
    evidence_number text not null,
    title           text not null,
    description     text,
    type            text not null check (type in ('document', 'image', 'video', 'audio', 'other')),
    status          text not null default 'received'
                    check (status in ('received', 'under_review', 'verified', 'rejected', 'archived')),
    created_by      uuid not null references public.profiles (id) on delete restrict,
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now(),
    unique (case_id, evidence_number)
);

-- -----------------------------------------------------------------------------
-- 5) document_versions
-- -----------------------------------------------------------------------------
create table public.document_versions (
    id              uuid primary key default gen_random_uuid(),
    evidence_id     uuid not null references public.evidence (id) on delete restrict,
    version         integer not null check (version >= 1),
    prev_version_id uuid references public.document_versions (id) on delete restrict,
    file_name       text not null,
    mime_type       text not null,
    file_size_bytes bigint not null check (file_size_bytes >= 0),
    sha256          text not null check (sha256 ~ '^[0-9a-f]{64}$'),
    storage_key     text not null unique,
    uploaded_by     uuid not null references public.profiles (id) on delete restrict,
    uploaded_at     timestamptz not null default now(),
    notes           text,
    unique (evidence_id, version)
);

-- -----------------------------------------------------------------------------
-- 6) chain_of_custody
-- -----------------------------------------------------------------------------
create table public.chain_of_custody (
    id                  uuid primary key default gen_random_uuid(),
    evidence_id         uuid not null references public.evidence (id) on delete restrict,
    document_version_id uuid references public.document_versions (id) on delete restrict,
    action              text not null
                        check (action in ('received', 'transferred', 'returned', 'verified', 'released', 'archived')),
    actor_id            uuid not null references public.profiles (id) on delete restrict,
    from_profile_id     uuid references public.profiles (id) on delete restrict,
    to_profile_id       uuid references public.profiles (id) on delete restrict,
    location            text,
    notes               text,
    occurred_at         timestamptz not null default now(),
    check (from_profile_id is distinct from to_profile_id)
);

-- -----------------------------------------------------------------------------
-- 7) audit_logs
-- -----------------------------------------------------------------------------
create table public.audit_logs (
    id          uuid primary key default gen_random_uuid(),
    actor_id    uuid references public.profiles (id) on delete restrict,
    action      text not null check (char_length(action) > 0),
    entity_type text not null,
    entity_id   uuid not null,
    before      jsonb,
    after       jsonb,
    ip_address  inet,
    meta        jsonb not null default '{}'::jsonb,
    created_at  timestamptz not null default now()
);

-- -----------------------------------------------------------------------------
-- Indexes
-- Foreign-key columns and the query patterns from the approved design.
-- -----------------------------------------------------------------------------
create index cases_created_by_idx on public.cases (created_by);
create index cases_status_idx on public.cases (status);
create index cases_closed_by_idx on public.cases (closed_by);

-- unique (case_id, profile_id) already covers lookups by case_id.
create index case_members_profile_id_idx on public.case_members (profile_id);
create index case_members_added_by_idx on public.case_members (added_by);

-- unique (case_id, evidence_number) already covers lookups by case_id.
create index evidence_status_idx on public.evidence (status);
create index evidence_created_by_idx on public.evidence (created_by);

create index document_versions_uploaded_by_idx on public.document_versions (uploaded_by);
create index document_versions_prev_version_id_idx on public.document_versions (prev_version_id);

create index chain_of_custody_evidence_id_occurred_idx
    on public.chain_of_custody (evidence_id, occurred_at desc);
create index chain_of_custody_actor_id_idx on public.chain_of_custody (actor_id);
create index chain_of_custody_from_profile_id_idx on public.chain_of_custody (from_profile_id);
create index chain_of_custody_to_profile_id_idx on public.chain_of_custody (to_profile_id);
create index chain_of_custody_document_version_id_idx
    on public.chain_of_custody (document_version_id);

create index audit_logs_entity_idx
    on public.audit_logs (entity_type, entity_id, created_at desc);
create index audit_logs_actor_id_created_idx
    on public.audit_logs (actor_id, created_at desc);
create index audit_logs_created_at_idx on public.audit_logs (created_at desc);

-- -----------------------------------------------------------------------------
-- Comments documenting security / evidence-integrity decisions
-- -----------------------------------------------------------------------------
comment on table public.profiles is
  'Application profile for an authenticated Supabase user. 1:1 with auth.users. Never stores credentials.';
comment on column public.profiles.id is
  'Primary key and FK to auth.users. Equals the authenticated user''s uuid; Supabase Auth owns identity and credentials.';
comment on column public.profiles.role is
  'Global RBAC role, reserved for later authorization work. Role vocabulary enforced once RBAC is implemented.';

comment on table public.cases is
  'Investigation case grouping members and evidence. Cases are closed/archived, never hard-deleted.';
comment on column public.cases.created_by is 'Profile that created the case (case owner).';

comment on table public.case_members is
  'Many-to-many link between cases and profiles; carries the case-scoped role used later for RLS/authorization.';
comment on column public.case_members.role_in_case is
  'Case-scoped role for object-level authorization (e.g. member, lead). Vocabulary enforced later with RBAC.';

comment on table public.evidence is
  'Evidentiary record belonging to a case. Files live in MinIO; document_versions tracks the file history.';
comment on column public.evidence.evidence_number is
  'Per-case sequential label, unique within its case: unique (case_id, evidence_number).';

comment on table public.document_versions is
  'Immutable file version history. Append-only: rows are never updated or deleted (evidence is versioned, never clobbered).';
comment on column public.document_versions.sha256 is
  'SHA-256 digest (64 lowercase hex) for integrity verification only. It is not encryption and, alone, is not proof of who modified the file.';
comment on column public.document_versions.prev_version_id is
  'Optional pointer to the previous version, forming the version chain.';
comment on column public.document_versions.storage_key is
  'MinIO object key: {case_id}/{evidence_id}/{document_version_id}. Independent of the original filename.';

comment on table public.chain_of_custody is
  'Append-only record of who handled a piece of evidence (possession trail). Separate concept from audit_logs.';
comment on column public.chain_of_custody.actor_id is
  'Profile that performed the custody action; never null.';

comment on table public.audit_logs is
  'Append-only operational log of what happened in the system. Separate concept from chain_of_custody.';
comment on column public.audit_logs.actor_id is
  'Profile that performed the action; null for system events.';
comment on column public.audit_logs.entity_type is
  'Target entity kind of the polymorphic reference (case, evidence, document_version, profile, ...).';
comment on column public.audit_logs.entity_id is
  'Target row id of the polymorphic reference.';
comment on column public.audit_logs.meta is
  'Structured extra context for the event, JSON only.';