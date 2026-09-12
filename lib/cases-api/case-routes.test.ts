import assert from "node:assert/strict";
import { describe, it, beforeEach } from "node:test";
import { NextRequest } from "next/server.js";
import { PATCH as updateCase, GET as getCase } from "../../app/api/cases/[id]/route.ts";
import { PATCH as updateEvidenceStatus } from "../../app/api/cases/[id]/evidence/[evidenceId]/status/route.ts";
import { POST as recordCustody } from "../../app/api/cases/[id]/evidence/[evidenceId]/custody/route.ts";
import { POST as anchorVersion } from "../../app/api/cases/[id]/evidence/[evidenceId]/anchor/route.ts";
import {
  caseClientHolder,
  makeCaseClient,
  type CaseFakeSupabaseClient,
} from "./test-support/case-server-stub.ts";
import {
  clientHolder as blockchainClientHolder,
  makeFakeClient as makeBlockchainClient,
} from "../blockchain/test-support/supabase-server-stub.ts";

// ---------------------------------------------------------------------------
// Route-level unit tests for the case lifecycle hardening:
//
//   1. Case status is transitioned ONLY through update_case (PATCH
//      /api/cases/[id]), whose transition matrix + closed_at/closed_by
//      invariant live in the SECURITY DEFINER RPC. This file proves the route
//      reaches that RPC with actor-free parameters, maps the transition
//      enforcement error to 409, and still allows metadata-only edits and
//      reads after a case is closed/archived.
//   2. The closed/archived case gate (case_not_open) blocks evidence status
//      changes, custody events and NEW blockchain anchors with 409 — without
//      touching reads, which remain available on closed/archived cases.
//   3. The DB-level guarantees (the transition matrix itself, RLS, the
//      revoked UPDATE grants, const case.updated/case.status_changed audit)
//      live in supabase/migrations/. They are enforced inside the RPCs and are
//      exercised by the migration SQL — these route tests verify the routing,
//      the parameter contract and the error translation.
//
// The @/lib/supabase/server alias resolves per-importer: non-access
// /app/api/cases/ routes use THIS module's case-server-stub, while the anchor
// route's orchestrator (lib/blockchain/orchestrator.ts) resolves to the
// blockchain stub. next/server resolves to next/server.js and the other @/lib
// aliases map to the real sources.
// ---------------------------------------------------------------------------

const CASE_ID = "20000000-0000-0000-0000-0000000000A1";
const EVIDENCE_ID = "30000000-0000-0000-0000-0000000000A1";
const VERSION_ID = "40000000-0000-0000-0000-0000000000A1";
const ACTOR_ID = "81000000-0000-0000-0000-000000000001";

function rpcResult(data: unknown, message: string | null = null) {
  return { data, error: message ? { message } : null };
}

function rpcError(message: string) {
  return { data: null, error: { message } };
}

function installProfile(client: CaseFakeSupabaseClient, id = ACTOR_ID) {
  client.tableHandlers.set("profiles", () => ({
    data: { id },
    error: null,
  }));
}

// --- case PATCH builders ----------------------------------------------------

function caseUrl(): string {
  return `http://localhost/api/cases/${CASE_ID}`;
}

async function callUpdateCase(
  body: unknown,
  client: CaseFakeSupabaseClient,
): Promise<Response> {
  caseClientHolder.current = client;
  const ctx = { params: Promise.resolve({ id: CASE_ID }) };
  const req = new Request(caseUrl(), {
    method: "PATCH",
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
  return updateCase(req, ctx as never);
}

async function callGetCase(client: CaseFakeSupabaseClient): Promise<Response> {
  caseClientHolder.current = client;
  const ctx = { params: Promise.resolve({ id: CASE_ID }) };
  return getCase(new Request(caseUrl()), ctx as never);
}

// --- evidence status PATCH builders ------------------------------------------

async function callUpdateEvidenceStatus(
  body: unknown,
  client: CaseFakeSupabaseClient,
): Promise<Response> {
  caseClientHolder.current = client;
  const ctx = { params: Promise.resolve({ id: CASE_ID, evidenceId: EVIDENCE_ID }) };
  const req = new Request(
    `http://localhost/api/cases/${CASE_ID}/evidence/${EVIDENCE_ID}/status`,
    { method: "PATCH", body: typeof body === "string" ? body : JSON.stringify(body) },
  );
  return updateEvidenceStatus(req, ctx as never);
}

// --- custody POST builders ---------------------------------------------------

async function callRecordCustody(
  body: unknown,
  client: CaseFakeSupabaseClient,
): Promise<Response> {
  caseClientHolder.current = client;
  const ctx = { params: Promise.resolve({ id: CASE_ID, evidenceId: EVIDENCE_ID }) };
  const req = new NextRequest(
    `http://localhost/api/cases/${CASE_ID}/evidence/${EVIDENCE_ID}/custody`,
    { method: "POST", body: typeof body === "string" ? body : JSON.stringify(body) },
  );
  return recordCustody(req, ctx as never);
}

// --- helpers for asserting parameter contracts --------------------------------

const CASE_PATCH_RPC_KEYS = [
  "p_case_id",
  "p_title",
  "p_description",
  "p_set_description_null",
  "p_status",
];

function assertMutableRpcParams(
  client: CaseFakeSupabaseClient,
  fn: string,
  allowed: string[],
) {
  const call = client.calls.find((c) => c.fn === fn);
  assert.ok(call, `${fn} must have been called`);
  const keys = Object.keys(call.params);
  assert.deepEqual(
    keys.filter((k) => !allowed.includes(k)),
    [],
    `${fn} received unexpected/user-supplied params: ${keys.join(", ")}`,
  );
  // Identity, timestamps and custody provenance are NEVER client-supplied.
  const banned = ["actor", "actor_id", "occurred_at", "closed_by", "created_by"];
  for (const key of keys) {
    assert.ok(
      !banned.some((b) => key.includes(b)),
      `${fn} must not accept ${key}`,
    );
  }
}

describe("PATCH /api/cases/[id] — status transition + metadata edits", () => {
  beforeEach(() => {
    caseClientHolder.current = null;
  });

  it("rejects an unauthenticated request with 401", async () => {
    const client = makeCaseClient();
    client.user = null;
    const res = await callUpdateCase({ status: "closed" }, client);
    assert.equal(res.status, 401);
    assert.deepEqual(await res.json(), { error: "Unauthorized" });
  });

  it("rejects a user without a profile with 403", async () => {
    const client = makeCaseClient();
    client.tableHandlers.set("profiles", () => ({ data: null, error: null }));
    const res = await callUpdateCase({ status: "closed" }, client);
    assert.equal(res.status, 403);
  });

  it("maps case_not_found from update_case to 404", async () => {
    const client = makeCaseClient();
    installProfile(client);
    client.rpcHandlers.set("update_case", () => rpcError("case_not_found"));
    const res = await callUpdateCase({ status: "closed" }, client);
    assert.equal(res.status, 404);
    assert.deepEqual(await res.json(), { error: "Case not found" });
  });

  it("maps not_lead from update_case to 403 with a safe message", async () => {
    const client = makeCaseClient();
    installProfile(client);
    client.rpcHandlers.set("update_case", () => rpcError("not_lead"));
    const res = await callUpdateCase({ status: "closed" }, client);
    assert.equal(res.status, 403);
    assert.deepEqual(await res.json(), {
      error: "Only the case lead can edit this case",
    });
  });

  it("rejects an off-vocabulary status at the route", async () => {
    const client = makeCaseClient();
    installProfile(client);
    const res = await callUpdateCase({ status: "frozen" }, client);
    assert.equal(res.status, 400);
  });

  it("maps the transition matrix rejection (transition_not_allowed) to 409", async () => {
    // The transition matrix itself is enforced inside update_case; this
    // exercise proves a rejection is surfaced as 409, e.g. draft -> closed.
    const client = makeCaseClient();
    installProfile(client);
    client.rpcHandlers.set("update_case", () => rpcError("transition_not_allowed"));
    const res = await callUpdateCase({ status: "closed" }, client);
    assert.equal(res.status, 409);
    assert.deepEqual(await res.json(), {
      error: "That case status transition is not allowed",
    });
  });

  it("reaches update_case with actor-free parameters for a close", async () => {
    const client = makeCaseClient();
    installProfile(client);
    client.rpcHandlers.set("update_case", () =>
      rpcResult({ id: CASE_ID, status: "closed", closed_at: "2026-09-18T10:00:00Z" }),
    );
    const res = await callUpdateCase({ status: "closed" }, client);
    assert.equal(res.status, 200);
    const call = client.calls.find((c) => c.fn === "update_case");
    assert.ok(call, "update_case must have been called");
    assert.equal(call.params.p_case_id, CASE_ID);
    assert.equal(call.params.p_status, "closed");
    assert.equal(call.params.p_set_description_null, false);
    assertMutableRpcParams(client, "update_case", CASE_PATCH_RPC_KEYS);
  });

  it("allows a metadata-only edit without sending a status (post-close edits stay possible)", async () => {
    // Closing is irreversible only in transition terms; the lead may still
    // update title/description, and update_case audits it. p_status null means
    // the RPC performs no transition (the matrix is not consulted).
    const client = makeCaseClient();
    installProfile(client);
    client.rpcHandlers.set("update_case", () =>
      rpcResult({ id: CASE_ID, title: "Updated after close", status: "closed" }),
    );
    const res = await callUpdateCase({ title: "Updated after close" }, client);
    assert.equal(res.status, 200);
    const call = client.calls.find((c) => c.fn === "update_case");
    assert.ok(call, "update_case must have been called");
    assert.equal(call.params.p_title, "Updated after close");
    assert.equal(call.params.p_status, null);
    assertMutableRpcParams(client, "update_case", CASE_PATCH_RPC_KEYS);
  });

  it("rejects empty-body and invalid-shape updates", async () => {
    const client = makeCaseClient();
    installProfile(client);
    assert.equal((await callUpdateCase({}, client)).status, 400);
    assert.equal((await callUpdateCase({ not_a_field: 1 }, client)).status, 400);
    assert.equal((await callUpdateCase({ status: 7 }, client)).status, 400);
  });
});

describe("GET /api/cases/[id] — closed/archived cases remain readable", () => {
  beforeEach(() => {
    caseClientHolder.current = null;
  });

  it("returns a closed case with its members (read is never blocked)", async () => {
    const client = makeCaseClient();
    client.tableHandlers.set("cases", () =>
      rpcResult({
        id: CASE_ID,
        case_number: "CSE-2026-0001",
        title: "Evidence case",
        description: null,
        status: "closed",
        created_at: "2026-09-01T00:00:00Z",
        updated_at: "2026-09-18T10:00:00Z",
        created_by: ACTOR_ID,
        closed_at: "2026-09-18T10:00:00Z",
        closed_by: ACTOR_ID,
        case_members: [
          {
            profile_id: ACTOR_ID,
            role_in_case: "lead",
            added_at: "2026-09-01T00:00:00Z",
            profiles: { id: ACTOR_ID, full_name: "Case Lead" },
          },
        ],
      }),
    );
    const res = await callGetCase(client);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.case.status, "closed");
    assert.equal(body.case.closed_at, "2026-09-18T10:00:00Z");
    assert.equal(body.my_role, "lead");
  });

  it("reports an inaccessible/absent case as 404, never 403", async () => {
    const client = makeCaseClient();
    client.tableHandlers.set("cases", () => ({ data: null, error: null }));
    const res = await callGetCase(client);
    assert.equal(res.status, 404);
  });
});

describe("PATCH /api/cases/[id]/evidence/[evidenceId]/status — closed-case gate", () => {
  beforeEach(() => {
    caseClientHolder.current = null;
  });

  it("rejects an unauthenticated request with 401", async () => {
    const client = makeCaseClient();
    client.user = null;
    const res = await callUpdateEvidenceStatus({ status: "verified" }, client);
    assert.equal(res.status, 401);
  });

  it("maps the case_not_open DB gate to 409 (closed/archived evidence is immutable)", async () => {
    const client = makeCaseClient();
    installProfile(client);
    client.rpcHandlers.set("update_evidence_status", () => rpcError("case_not_open"));
    const res = await callUpdateEvidenceStatus({ status: "verified" }, client);
    assert.equal(res.status, 409);
    assert.match((await res.json()).error, /closed or archived/);
  });

  it("maps evidence_not_found and not_authorized_to_update faithfully", async () => {
    const client = makeCaseClient();
    installProfile(client);
    client.rpcHandlers.set("update_evidence_status", () => rpcError("evidence_not_found"));
    assert.equal((await callUpdateEvidenceStatus({ status: "verified" }, client)).status, 404);
    client.rpcHandlers.set("update_evidence_status", () => rpcError("not_authorized_to_update"));
    const res = await callUpdateEvidenceStatus({ status: "verified" }, client);
    assert.equal(res.status, 403);
    assert.match((await res.json()).error, /lead or an investigator/);
  });

  it("rejects an off-vocabulary status at the route", async () => {
    const client = makeCaseClient();
    installProfile(client);
    assert.equal((await callUpdateEvidenceStatus({ status: "burned" }, client)).status, 400);
  });

  it("reaches update_evidence_status with actor-free params on an open case", async () => {
    const client = makeCaseClient();
    installProfile(client);
    client.rpcHandlers.set("update_evidence_status", () =>
      rpcResult({ id: EVIDENCE_ID, status: "verified", updated_at: "2026-09-18T10:00:00Z" }),
    );
    const res = await callUpdateEvidenceStatus({ status: "verified" }, client);
    assert.equal(res.status, 200);
    const call = client.calls.find((c) => c.fn === "update_evidence_status");
    assert.ok(call, "update_evidence_status must have been called");
    assert.equal(call.params.p_evidence_id, EVIDENCE_ID);
    assert.equal(call.params.p_status, "verified");
    assertMutableRpcParams(client, "update_evidence_status", ["p_evidence_id", "p_status"]);
  });
});

describe("POST /api/cases/[id]/evidence/[evidenceId]/custody — closed-case gate", () => {
  beforeEach(() => {
    caseClientHolder.current = null;
  });

  it("maps the case_not_open DB gate to 409 (custody is frozen on closed/archived cases)", async () => {
    const client = makeCaseClient();
    installProfile(client);
    client.rpcHandlers.set("record_custody_event", () => rpcError("case_not_open"));
    const res = await callRecordCustody(
      {
        action: "transferred",
        documentVersionId: VERSION_ID,
        fromProfileId: ACTOR_ID,
        toProfileId: "81000000-0000-0000-0000-000000000006",
      },
      client,
    );
    assert.equal(res.status, 409);
    assert.match((await res.json()).error, /closed or archived/);
  });

  it("rejects an off-vocabulary custody action at the route", async () => {
    const client = makeCaseClient();
    installProfile(client);
    const res = await callRecordCustody({ action: "received" }, client);
    assert.equal(res.status, 400);
  });

  it("reaches record_custody_event with actor-free params on an open case", async () => {
    const client = makeCaseClient();
    installProfile(client);
    client.rpcHandlers.set("record_custody_event", () =>
      rpcResult({
        id: "50000000-0000-0000-0000-000000000001",
        action: "transferred",
        actor_id: ACTOR_ID,
        from_profile_id: null,
        to_profile_id: "81000000-0000-0000-0000-000000000006",
        location: "Forensics lab",
        notes: null,
        occurred_at: "2026-09-18T10:00:00Z",
      }),
    );
    const res = await callRecordCustody(
      {
        action: "transferred",
        documentVersionId: VERSION_ID,
        fromProfileId: ACTOR_ID,
        toProfileId: "81000000-0000-0000-0000-000000000006",
        location: "Forensics lab",
      },
      client,
    );
    assert.equal(res.status, 200);
    const call = client.calls.find((c) => c.fn === "record_custody_event");
    assert.ok(call, "record_custody_event must have been called");
    assert.equal(call.params.p_evidence_id, EVIDENCE_ID);
    assert.equal(call.params.p_action, "transferred");
    assertMutableRpcParams(client, "record_custody_event", [
      "p_evidence_id",
      "p_action",
      "p_document_version_id",
      "p_from_profile_id",
      "p_to_profile_id",
      "p_location",
      "p_notes",
    ]);
  });
});

describe("POST /api/cases/[id]/evidence/[evidenceId]/anchor — new anchors blocked on closed cases", () => {
  beforeEach(() => {
    blockchainClientHolder.current = null;
  });

  async function callAnchorVersion(): Promise<Response> {
    const ctx = { params: Promise.resolve({ id: CASE_ID, evidenceId: VERSION_ID }) };
    const req = new Request(
      `http://localhost/api/cases/${CASE_ID}/evidence/${VERSION_ID}/anchor`,
      { method: "POST" },
    );
    return anchorVersion(req, ctx as never);
  }

  it("maps the case_not_open DB gate to 409 when minting a NEW anchor", async () => {
    const client = makeBlockchainClient();
    client.handlers.set("create_blockchain_anchor", () =>
      rpcError(
        "case_not_open: this case is closed or archived; new anchors cannot be created",
      ),
    );
    blockchainClientHolder.current = client;

    const res = await callAnchorVersion();
    assert.equal(res.status, 409);
    const body = await res.json();
    assert.equal(body.anchor, undefined);
  });

  it("still passes a fresh pending/reused slot through to the orchestrator (create errors only)", async () => {
    // The DB gate raises case_not_open ONLY on a fresh mint (no existing
    // anchor row). A pre-existing pending row is reused — the orchestrator's
    // create call succeeds — so anchors created before a case closed can still
    // be reconciled. Here the create RPC returns a pending row (not an error),
    // proving the route/orchestrator are not gated on the error path.
    const client = makeBlockchainClient();
    client.handlers.set("create_blockchain_anchor", () =>
      rpcResult({ id: VERSION_ID, document_version_id: VERSION_ID, state: "pending" }),
    );
    blockchainClientHolder.current = client;

    // The create call must be attempted (not short-circuited by the route) and
    // must carry only server-safe params. A reused pending slot is not a
    // case_not_open error, so the route must NOT answer 409; whatever the
    // on-chain service does downstream, the DB "reuse, don't regenerate" path
    // is the orchestrator's decision, not this route's.
    const res = await callAnchorVersion();
    assert.notEqual(res.status, 409, "a reused pending slot must not be gated");
    assert.notEqual(res.status, 400, "a reused pending slot must not be a shape error");
    const create = client.calls.find((c) => c.fn === "create_blockchain_anchor");
    assert.ok(create, "create_blockchain_anchor must have been reached");
    assert.equal(create.params.p_document_version_id, VERSION_ID);
    assert.equal(create.params.p_actor_id, undefined);
  });
});