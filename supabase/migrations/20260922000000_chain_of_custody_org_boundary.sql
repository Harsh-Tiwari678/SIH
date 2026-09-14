-- =============================================================================
-- SIH26190 Secure Evidence — L1: chain-of-custody organization boundary
--
-- AUDIT FINDING
--   record_custody_event() validated from_profile_id / to_profile_id through
--   the two-argument is_case_member(profile, case), which only checks the
--   explicit case_members row. A profile removed from the case's organization
--   keeps its (stale) case_members row, so it could still be named in a
--   custody event. Cross-organization case memberships were therefore
--   accepted whenever an old row survived.
--
-- FIX (this migration)
--   Every profile referenced by from_profile_id / to_profile_id must be BOTH
--   an explicit member of the case AND a CURRENT member of the case's
--   organization. The authorization uses the current organization model:
--
--       organizations → organization_members → cases → case_members
--
--   The actor-facing authorization (org-aware is_case_member + explicit
--   lead/investigator role) is unchanged; only the from/to profile predicate
--   gains the organization boundary. The case-open/closed/archived
--   restriction, the possession-neutral (null, null) events, the self-handoff
--   ban, and the 'verified' anchor gate are all preserved verbatim.
--
--   Deliberately NOT changed:
--     * the shared two-arg is_case_member(uuid, uuid) helper — its semantics
--       ("is this arbitrary profile an explicit case member") stay intact;
--       the boundary is enforced at the only call site that vets custody
--       parties.
--     * organization membership alone grants nothing — the explicit
--       case_members requirement remains, so a cross-org ADMIN cannot name
--       arbitrary org members in a custody event.
-- =============================================================================

create or replace function public.record_custody_event(
    p_evidence_id         uuid,
    p_action              text,
    p_document_version_id uuid default null,
    p_from_profile_id     uuid default null,
    p_to_profile_id       uuid default null,
    p_location            text default null,
    p_notes               text default null
)
returns public.chain_of_custody
language plpgsql
security definer
set search_path = ''
as $function$
declare
    v_actor     uuid := auth.uid();
    v_case      public.cases;
    v_evidence  public.evidence;
    v_custody   public.chain_of_custody;
    v_action    text  := lower(btrim(p_action));
begin
    -- 1. authenticate — the actor is ALWAYS the session user; the function
    --    never accepts an actor_id (or occurred_at) argument.
    if v_actor is null then
        raise exception 'not_authenticated';
    end if;

    -- 2. the actor must have an application profile.
    if not exists (select 1 from public.profiles p where p.id = v_actor) then
        raise exception 'profile_not_found';
    end if;

    -- 3. load the evidence with a visibility constraint (mirrors
    --    create_evidence), so an evidence the caller cannot see — including
    --    one in another organization — is reported identically to a
    --    nonexistent one (no existence leak).
    select e.*
    into v_evidence
    from public.evidence e
    where e.id = p_evidence_id
      and (
          e.created_by = v_actor
          or exists (
              select 1
              from public.case_members m
              where m.case_id = e.case_id
                and m.profile_id = v_actor
          )
      );
    if not found then
        raise exception 'evidence_not_found';
    end if;

    select c.* into v_case from public.cases c where c.id = v_evidence.case_id;
    if not found then
        raise exception 'case_not_found';
    end if;

    -- 4. authorize: the caller must belong to the evidence case's
    --    ORGANIZATION. The org-aware is_case_member(v_case.id) already
    --    enforces the current-organization boundary for the actor; the
    --    explicit is_org_member assertion below makes requirement 2 of the
    --    L1 finding ("the case must belong to the actor's current
    --    organization") a literal, self-documenting check. It is logically
    --    implied by is_case_member, so the accepted set is unchanged.
    if not public.is_case_member(v_case.id) then
        raise exception 'not_authorized_for_custody';
    end if;
    if not public.is_org_member(v_case.org_id) then
        raise exception 'not_authorized_for_custody';
    end if;

    -- 5. … and hold an explicit lead / investigator role in the case
    --    (viewers read custody, they never record it).
    if not exists (
        select 1
        from public.case_members m
        where m.case_id = v_case.id
          and m.profile_id = v_actor
          and m.role_in_case in ('lead', 'investigator')
    ) then
        raise exception 'not_authorized_for_custody';
    end if;

    -- 5b. business rule: a closed/archived case is a frozen possession trail.
    --     No new custody event may be recorded once the case is not open.
    if v_case.status not in ('draft', 'active') then
        raise exception 'case_not_open';
    end if;

    -- 6. validate the action against the existing vocabulary.
    if v_action not in ('received', 'transferred', 'returned', 'verified', 'released', 'archived') then
        raise exception 'action_not_allowed';
    end if;

    -- 7. 'received' is written by create_evidence on intake and must not be
    --    freely reproducible through this workflow.
    if v_action = 'received' then
        raise exception 'received_created_on_intake';
    end if;

    -- 8. action shape rules: transfer/return require a recipient; release and
    --    archive terminate possession (a target is meaningless and rejected).
    if v_action in ('transferred', 'returned') and p_to_profile_id is null then
        raise exception 'to_profile_required';
    end if;
    if v_action in ('released', 'archived') and p_to_profile_id is not null then
        raise exception 'to_profile_not_allowed';
    end if;
    --    you cannot hand custody to yourself — a transfer needs a real
    --    receiving party (there is no acceptor handshake in this phase).
    if v_action in ('transferred', 'returned') and p_to_profile_id = v_actor then
        raise exception 'to_profile_is_actor';
    end if;

    -- 9. an optional document version must belong to THIS evidence.
    if p_document_version_id is not null and not exists (
        select 1
        from public.document_versions dv
        where dv.id = p_document_version_id
          and dv.evidence_id = v_evidence.id
    ) then
        raise exception 'document_version_not_found';
    end if;

    -- 10. from / to profiles (when provided) must be members of the SAME case
    --     AND CURRENT members of the case's organization (L1).
    --
    --     The two-argument is_case_member vets the explicit case_members row
    --     (case-membership rules are preserved — organization membership
    --     ALONE still grants nothing), and the organization_members check
    --     proves that row is not stale: a profile removed from the
    --     organization keeps its case_members row, and such a profile must
    --     never appear in a custody event. Cross-organization profiles are
    --     rejected no matter what their case_members row claims.
    if p_from_profile_id is not null and (
        not public.is_case_member(p_from_profile_id, v_case.id)
        or not exists (
            select 1
            from public.organization_members om
            where om.org_id = v_case.org_id
              and om.profile_id = p_from_profile_id
        )
    ) then
        raise exception 'from_profile_not_in_case';
    end if;
    if p_to_profile_id is not null and (
        not public.is_case_member(p_to_profile_id, v_case.id)
        or not exists (
            select 1
            from public.organization_members om
            where om.org_id = v_case.org_id
              and om.profile_id = p_to_profile_id
        )
    ) then
        raise exception 'to_profile_not_in_case';
    end if;
    if p_from_profile_id is not null and p_to_profile_id is not null and p_from_profile_id = p_to_profile_id then
        raise exception 'from_to_same_profile';
    end if;

    -- 11. 'verified' must reflect a real on-chain verification — the same
    --     invariant update_evidence_status enforces (no hand-flip).
    if v_action = 'verified' then
        if not exists (
            select 1
            from public.blockchain_anchors ba
            join public.document_versions dv on dv.id = ba.document_version_id
            where ba.evidence_id = v_evidence.id
              and ba.status = 'anchored'
              and ba.evidence_sha256 = dv.sha256
        ) then
            raise exception 'verification_required';
        end if;
    end if;

    -- 12. metadata limits (defense in depth; the route already trims).
    if p_location is not null and char_length(p_location) > 500 then
        raise exception 'invalid_custody_detail';
    end if;
    if p_notes is not null and char_length(p_notes) > 2000 then
        raise exception 'invalid_custody_detail';
    end if;

    -- 13. write the custody event. occurred_at is server-set to now(); a
    --     caller can never backdate (or predate) a possession record.
    insert into public.chain_of_custody (
        evidence_id, document_version_id, action, actor_id,
        from_profile_id, to_profile_id, location, notes, occurred_at
    ) values (
        v_evidence.id,
        p_document_version_id,
        v_action,
        v_actor,
        p_from_profile_id,
        p_to_profile_id,
        p_location,
        p_notes,
        now()
    )
    returning * into v_custody;

    -- 14. audit mirror in the SAME transaction. entity_type is 'evidence' (the
    --     portfolio-level audit vocabulary); org_id is set explicitly because
    --     case-level RPCs predate the org_id column and list_*_audit_events
    --     joins the case row — the explicit org_id keeps the reference resolvable.
    insert into public.audit_logs (actor_id, action, entity_type, entity_id, org_id, meta)
    values (
        v_actor,
        'custody.' || v_action,
        'evidence',
        v_evidence.id,
        v_case.org_id,
        jsonb_build_object(
            'case_id', v_case.id,
            'case_number', v_case.case_number,
            'evidence_id', v_evidence.id,
            'evidence_number', v_evidence.evidence_number,
            'title', v_evidence.title,
            'document_version_id', v_custody.document_version_id,
            'custody_event_id', v_custody.id,
            'action', v_action,
            'from_profile_id', v_custody.from_profile_id,
            'from_profile_name', (select p.full_name from public.profiles p where p.id = v_custody.from_profile_id),
            'to_profile_id', v_custody.to_profile_id,
            'to_profile_name', (select p.full_name from public.profiles p where p.id = v_custody.to_profile_id),
            'location', v_custody.location,
            'notes', v_custody.notes
        )
    );

    return v_custody;
end;
$function$;

alter function public.record_custody_event(uuid, text, uuid, uuid, uuid, text, text) owner to postgres;
revoke execute on function public.record_custody_event(uuid, text, uuid, uuid, uuid, text, text) from public, anon;
grant execute on function public.record_custody_event(uuid, text, uuid, uuid, uuid, text, text) to authenticated;