import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { NextRequest } from "next/server.js";
import {
  GET as getMembers,
  POST as addMember,
} from "../../app/api/organizations/[id]/members/route.ts";
import {
  PATCH as changeMemberRole,
  DELETE as removeMember,
} from "../../app/api/organizations/[id]/members/[profileId]/route.ts";
import {
  GET as lookupMembers,
} from "../../app/api/organizations/[id]/members/lookup/route.ts";
import {
  GET as getOrgAudit,
} from "../../app/api/organizations/[id]/audit/route.ts";
import {
  orgClientHolder,
  makeOrgClient,
  type OrgFakeSupabaseClient,
} from "./test-support/org-server-stub.ts";

// ---------------------------------------------------------------------------
// Route-level unit tests for the organization member / audit API:
//
//   authenticate -> authorize (profile) -> validate -> SECURITY DEFINER RPC
//
// The @/lib/supabase/server alias resolves to org-server-stub.ts (via
// lib/blockchain/test-support/test-loader.mjs), next/server resolves to
// next/server.js, and the other @/lib aliases map to the real sources. This
// exercises the real route handlers without a live Supabase and without
// weakening the live SQL security tests in supabase/tests/. The DB RPCs are
// the authorization boundary; these tests verify the routes reach the right
// RPC with the right (actor-free) parameters and translate errors faithfully.
// ---------------------------------------------------------------------------

const ORG_ALPHA = "82000000-0000-0000-0000-0000000000A1";
const ORG_BETA = "82000000-0000-0000-0000-0000000000B1";
const ACTOR_ID = "81000000-0000-0000-0000-000000000001";
const TARGET_ID = "81000000-0000-0000-0000-000000000006";

function installProfile(client: OrgFakeSupabaseClient) {
  client.tableHandlers.set("profiles", () => ({
    data: { id: ACTOR_ID },
    error: null,
  }));
}

function rpcResult(data: unknown, message: string | null = null) {
  return { data, error: message ? { message } : null };
}

function rpcError(message: string) {
  return { data: null, error: { message } };
}

// --- request builders --------------------------------------------------------

function memberUrl(orgId = ORG_ALPHA): string {
  return `http://localhost/api/organizations/${orgId}/members`;
}

function auditUrl(orgId = ORG_ALPHA): string {
  return `http://localhost/api/organizations/${orgId}/audit`;
}

function lookupUrl(q: string | null, orgId = ORG_ALPHA): string {
  const qs = q === null ? "" : `?q=${encodeURIComponent(q)}`;
  return `http://localhost/api/organizations/${orgId}/members/lookup${qs}`;
}

function memberTargetUrl(
  orgId: string,
  profileId: string,
): string {
  return `http://localhost/api/organizations/${orgId}/members/${profileId}`;
}

async function makeGet(
  url: string,
  orgId = ORG_ALPHA,
  extra: Record<string, string> = {},
): Promise<Response> {
  const ctx = { params: Promise.resolve({ id: orgId, ...extra }) };
  return getMembers(new NextRequest(url), ctx as never);
}

async function makePost(body: unknown, orgId = ORG_ALPHA): Promise<Response> {
  const ctx = { params: Promise.resolve({ id: orgId }) };
  const req = new Request(memberUrl(orgId), {
    method: "POST",
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
  return addMember(req, ctx as never);
}

async function makePatch(
  body: unknown,
  orgId = ORG_ALPHA,
  profileId = TARGET_ID,
): Promise<Response> {
  const ctx = { params: Promise.resolve({ id: orgId, profileId }) };
  const req = new Request(memberTargetUrl(orgId, profileId), {
    method: "PATCH",
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
  return changeMemberRole(req, ctx as never);
}

async function makeDelete(
  orgId = ORG_ALPHA,
  profileId = TARGET_ID,
): Promise<Response> {
  const ctx = { params: Promise.resolve({ id: orgId, profileId }) };
  const req = new Request(memberTargetUrl(orgId, profileId), { method: "DELETE" });
  return removeMember(req, ctx as never);
}

async function makeLookup(q: string | null, orgId = ORG_ALPHA): Promise<Response> {
  const ctx = { params: Promise.resolve({ id: orgId }) };
  return lookupMembers(new NextRequest(lookupUrl(q, orgId)), ctx as never);
}

async function makeAudit(orgId = ORG_ALPHA): Promise<Response> {
  const ctx = { params: Promise.resolve({ id: orgId }) };
  return getOrgAudit(new NextRequest(auditUrl(orgId)), ctx as never);
}

// --- fixtures -----------------------------------------------------------------

const ROSTER = [
  {
    id: "90000000-0000-0000-0000-0000000000A1",
    profile_id: ACTOR_ID,
    full_name: "Aarav Sharma",
    badge_number: "A-1001",
    role_in_org: "admin",
    added_by_name: "Aarav Sharma",
    added_by: ACTOR_ID,
    added_at: "2026-09-01T08:00:00Z",
  },
  {
    id: "90000000-0000-0000-0000-0000000000A2",
    profile_id: TARGET_ID,
    full_name: "Priya Nair",
    badge_number: "B-2002",
    role_in_org: "investigator",
    added_by_name: "Aarav Sharma",
    added_by: ACTOR_ID,
    added_at: "2026-09-02T08:00:00Z",
  },
];

const CANDIDATES = [
  { id: TARGET_ID, full_name: "Priya Nair", badge_number: "B-2002" },
  { id: "81000000-0000-0000-0000-000000000007", full_name: "Ravi Kumar", badge_number: "C-3003" },
];

const AUDIT_ROWS = [
  {
    id: "91000000-0000-0000-0000-0000000000A1",
    action: "organization.member_role_changed",
    entity_type: "organization_member",
    entity_id: "90000000-0000-0000-0000-0000000000A2",
    actor_id: ACTOR_ID,
    actor_name: "Aarav Sharma",
    entity_label: "Priya Nair",
    created_at: "2026-09-12T09:00:00Z",
    meta: {
      old_role_in_org: "member",
      new_role_in_org: "investigator",
      // defense-in-depth fixture: even if the RPC ever re-introduced a
      // storage_key in meta, the serializer must drop it.
      storage_key: `${ORG_ALPHA}/objects/private-location`,
    },
  },
  {
    id: "91000000-0000-0000-0000-0000000000A2",
    action: "organization.created",
    entity_type: "organization",
    entity_id: ORG_ALPHA,
    actor_id: ACTOR_ID,
    actor_name: "Aarav Sharma",
    entity_label: "Alpha Bureau",
    created_at: "2026-09-01T08:00:00Z",
    meta: { name: "Alpha Bureau", slug: "alpha-bureau" },
  },
];

// =============================================================================
// AUTHENTICATION — every route rejects an unauthenticated session with 401
// =============================================================================

describe("organization member API — authentication", () => {
  it("rejects unauthenticated roster requests", async () => {
    const client = makeOrgClient();
    client.user = null;
    orgClientHolder.current = client;

    const res = await makeGet(memberUrl());
    assert.equal(res.status, 401);
    assert.equal((await res.json()).error, "Unauthorized");
    assert.equal(client.calls.length, 0);
  });

  it("rejects unauthenticated audit requests", async () => {
    const client = makeOrgClient();
    client.user = null;
    orgClientHolder.current = client;

    const res = await makeAudit();
    assert.equal(res.status, 401);
    assert.equal((await res.json()).error, "Unauthorized");
    assert.equal(client.calls.length, 0);
  });

  it("rejects unauthenticated lookup requests", async () => {
    const client = makeOrgClient();
    client.user = null;
    orgClientHolder.current = client;

    const res = await makeLookup("Priya");
    assert.equal(res.status, 401);
    assert.equal((await res.json()).error, "Unauthorized");
    assert.equal(client.calls.length, 0);
  });

  it("rejects unauthenticated add-member requests", async () => {
    const client = makeOrgClient();
    client.user = null;
    orgClientHolder.current = client;

    const res = await makePost({
      profile_id: TARGET_ID,
      role_in_org: "investigator",
    });
    assert.equal(res.status, 401);
    assert.equal((await res.json()).error, "Unauthorized");
    assert.equal(client.calls.length, 0);
  });

  it("rejects unauthenticated role-change requests", async () => {
    const client = makeOrgClient();
    client.user = null;
    orgClientHolder.current = client;

    const res = await makePatch({ role_in_org: "member" });
    assert.equal(res.status, 401);
    assert.equal((await res.json()).error, "Unauthorized");
    assert.equal(client.calls.length, 0);
  });

  it("rejects unauthenticated remove-member requests", async () => {
    const client = makeOrgClient();
    client.user = null;
    orgClientHolder.current = client;

    const res = await makeDelete();
    assert.equal(res.status, 401);
    assert.equal((await res.json()).error, "Unauthorized");
    assert.equal(client.calls.length, 0);
  });
});

// =============================================================================
// MEMBER LIST — GET /api/organizations/[id]/members
// =============================================================================

describe("GET /api/organizations/[id]/members", () => {
  it("returns the member roster for an authenticated member", async () => {
    const client = makeOrgClient();
    installProfile(client);
    client.rpcHandlers.set("list_organization_members", () => rpcResult(ROSTER));
    orgClientHolder.current = client;

    const res = await makeGet(memberUrl());
    const body = await res.json();

    assert.equal(res.status, 200);
    assert.deepEqual(body.members, ROSTER);
    const call = client.calls.find((c) => c.fn === "list_organization_members");
    assert.ok(call, "list_organization_members must be called");
    assert.deepEqual(call!.params, { p_org_id: ORG_ALPHA });
  });

  it("rejects an invalid organization id without calling the RPC", async () => {
    const client = makeOrgClient();
    installProfile(client);
    orgClientHolder.current = client;

    const res = await makeGet(memberUrl("not-a-uuid"), "not-a-uuid");
    assert.equal(res.status, 400);
    assert.equal((await res.json()).error, "Invalid organization id");
    assert.equal(client.calls.length, 0);
  });

  it("rejects a caller without an application profile", async () => {
    const client = makeOrgClient();
    // profiles query returns no row -> the route answers 403 before any RPC.
    client.tableHandlers.set("profiles", () => rpcResult(null));
    orgClientHolder.current = client;

    const res = await makeGet(memberUrl());
    assert.equal(res.status, 403);
    assert.equal((await res.json()).error, "Forbidden");
    assert.equal(client.calls.length, 0);
  });

  it("rejects cross-organization access via the DB boundary (org_not_found => 404)", async () => {
    const client = makeOrgClient();
    installProfile(client);
    client.rpcHandlers.set("list_organization_members", () => rpcError("org_not_found"));
    orgClientHolder.current = client;

    const res = await makeGet(memberUrl(ORG_BETA), ORG_BETA);
    const body = await res.json();

    // Identical to a nonexistent org: existence is never leaked.
    assert.equal(res.status, 404);
    assert.equal(body.error, "Organization not found");
    assert.ok(!JSON.stringify(body).includes("org_not_found"));
    assert.ok(!JSON.stringify(body).includes("internal"));
  });
});

// =============================================================================
// ORG AUDIT — GET /api/organizations/[id]/audit
// =============================================================================

describe("GET /api/organizations/[id]/audit", () => {
  it("returns the sanitized org audit trail for an authorized member", async () => {
    const client = makeOrgClient();
    installProfile(client);
    client.rpcHandlers.set("list_organization_audit_events", () =>
      rpcResult(AUDIT_ROWS),
    );
    orgClientHolder.current = client;

    const res = await makeAudit();
    const body = await res.json();

    assert.equal(res.status, 200);
    assert.equal(body.events.length, 2);
    assert.equal(body.events[0]!.action, "organization.member_role_changed");
    assert.equal(body.events[0]!.action_label, "Member role changed");
    assert.equal(body.events[0]!.entity_type_label, "Organization member");
    assert.equal(body.events[0]!.entity_label, "Priya Nair");
    // the storage_key present in the raw RPC row is stripped by the serializer
    assert.deepEqual(body.events[0]!.meta, [
      { key: "old_role_in_org", label: "Role from", value: "member" },
      { key: "new_role_in_org", label: "Role to", value: "investigator" },
    ]);
    const serialized = JSON.stringify(body);
    assert.ok(!serialized.includes("storage_key"));
    assert.ok(!serialized.includes("private-location"));

    const call = client.calls.find((c) => c.fn === "list_organization_audit_events");
    assert.ok(call, "list_organization_audit_events must be called");
    assert.deepEqual(call!.params, { p_org_id: ORG_ALPHA });
  });

  it("rejects cross-organization audit access with 404 (existence not leaked)", async () => {
    const client = makeOrgClient();
    installProfile(client);
    client.rpcHandlers.set("list_organization_audit_events", () =>
      rpcError("org_not_found"),
    );
    orgClientHolder.current = client;

    const res = await makeAudit(ORG_BETA);
    const body = await res.json();

    assert.equal(res.status, 404);
    assert.equal(body.error, "Organization not found");
    assert.ok(!JSON.stringify(body).includes("org_not_found"));
  });

  it("rejects an invalid organization id before the RPC", async () => {
    const client = makeOrgClient();
    installProfile(client);
    orgClientHolder.current = client;

    const res = await makeAudit("not-a-uuid");
    assert.equal(res.status, 400);
    assert.equal(client.calls.length, 0);
  });
});

// =============================================================================
// LOOKUP — GET /api/organizations/[id]/members/lookup?q=
// =============================================================================

describe("GET /api/organizations/[id]/members/lookup", () => {
  it("authorized user can search candidates", async () => {
    const client = makeOrgClient();
    installProfile(client);
    client.rpcHandlers.set("lookup_profiles_for_organization", () =>
      rpcResult(CANDIDATES),
    );
    orgClientHolder.current = client;

    const res = await makeLookup("Priya");
    const body = await res.json();

    assert.equal(res.status, 200);
    assert.equal(body.profiles.length, 2);
    const call = client.calls.find(
      (c) => c.fn === "lookup_profiles_for_organization",
    );
    assert.ok(call, "lookup RPC must be called");
    assert.deepEqual(call!.params, { p_org_id: ORG_ALPHA, p_query: "Priya" });
  });

  it("forwards a blank query as NULL so the RPC returns the capped candidate list", async () => {
    const client = makeOrgClient();
    installProfile(client);
    client.rpcHandlers.set("lookup_profiles_for_organization", () =>
      rpcResult([]),
    );
    orgClientHolder.current = client;

    await makeLookup("");
    const call = client.calls.find(
      (c) => c.fn === "lookup_profiles_for_organization",
    );
    assert.equal(call!.params.p_query, null);

    await makeLookup("   ");
    const second = client.calls.filter(
      (c) => c.fn === "lookup_profiles_for_organization",
    );
    assert.equal(second[1]!.params.p_query, null);
  });

  it("name and badge searches reach the RPC as the trim/optional query", async () => {
    const client = makeOrgClient();
    installProfile(client);
    client.rpcHandlers.set("lookup_profiles_for_organization", () => rpcResult([]));
    orgClientHolder.current = client;

    await makeLookup("  Priya Nair  ");
    await makeLookup("B-2002");
    const calls = client.calls.filter(
      (c) => c.fn === "lookup_profiles_for_organization",
    );
    assert.equal(calls[0]!.params.p_query, "Priya Nair");
    assert.equal(calls[1]!.params.p_query, "B-2002");
  });

  it("rejects an oversized query before the RPC", async () => {
    const client = makeOrgClient();
    installProfile(client);
    orgClientHolder.current = client;

    const res = await makeLookup("x".repeat(201));
    assert.equal(res.status, 400);
    assert.equal(client.calls.length, 0);
  });

  it("result shape contains only id/full_name/badge_number and no member exclusion in JS", async () => {
    const client = makeOrgClient();
    installProfile(client);
    client.rpcHandlers.set("lookup_profiles_for_organization", () =>
      rpcResult(CANDIDATES),
    );
    orgClientHolder.current = client;

    const res = await makeLookup(null);
    const body = await res.json();

    for (const profile of body.profiles) {
      assert.deepEqual(Object.keys(profile).sort(), [
        "badge_number",
        "full_name",
        "id",
      ]);
    }
    // The API performs no broader profile / membership query of its own: only
    // the lookup RPC runs. Any attempt to query organization_members (i.e. an
    // app-level exclusion by the JS layer) would throw "unexpected table query"
    // in the stub and fail this test loudly.
    const calls = client.calls.filter((c) => c.fn === "lookup_profiles_for_organization");
    assert.equal(calls.length, 1);
    assert.ok(!client.calls.some((c) => c.fn !== "lookup_profiles_for_organization"));
  });

  it("rejects cross-organization lookup via the DB boundary (404)", async () => {
    const client = makeOrgClient();
    installProfile(client);
    client.rpcHandlers.set("lookup_profiles_for_organization", () =>
      rpcError("org_not_found"),
    );
    orgClientHolder.current = client;

    const res = await makeLookup("Priya", ORG_BETA);
    assert.equal(res.status, 404);
    assert.equal((await res.json()).error, "Organization not found");
  });
});

// =============================================================================
// ADD — POST /api/organizations/[id]/members
// =============================================================================

describe("POST /api/organizations/[id]/members", () => {
  it("valid authorized operation reaches add_organization_member and returns 201", async () => {
    const client = makeOrgClient();
    installProfile(client);
    client.rpcHandlers.set("add_organization_member", () =>
      rpcResult("90000000-0000-0000-0000-0000000000A9"),
    );
    orgClientHolder.current = client;

    const res = await makePost({
      profile_id: TARGET_ID,
      role_in_org: "investigator",
    });
    const body = await res.json();

    assert.equal(res.status, 201);
    assert.deepEqual(body.member, {
      organization_member_id: "90000000-0000-0000-0000-0000000000A9",
      profile_id: TARGET_ID,
      role_in_org: "investigator",
    });
    const call = client.calls.find((c) => c.fn === "add_organization_member");
    assert.ok(call, "add_organization_member must be called");
    assert.deepEqual(call!.params, {
      p_org_id: ORG_ALPHA,
      p_profile_id: TARGET_ID,
      p_role: "investigator",
    });
  });

  it("rejects malformed input before the RPC", async () => {
    const cases: Array<[unknown, string]> = [
      [{ role_in_org: "investigator" }, "profile_id must be a valid uuid"],
      [{ profile_id: "nope", role_in_org: "investigator" }, "profile_id must be a valid uuid"],
      [{ profile_id: TARGET_ID }, "role_in_org must be one of admin, investigator, member"],
      [{ profile_id: TARGET_ID, role_in_org: "superadmin" }, "role_in_org must be one of admin, investigator, member"],
      [{ profile_id: TARGET_ID, role_in_org: 42 }, "role_in_org must be one of admin, investigator, member"],
    ];

    for (const [body, message] of cases) {
      const client = makeOrgClient();
      installProfile(client);
      orgClientHolder.current = client;

      const res = await makePost(body);
      assert.equal(res.status, 400, `expected 400 for ${JSON.stringify(body)}`);
      assert.equal((await res.json()).error, message);
      assert.equal(client.calls.length, 0, `no RPC for ${JSON.stringify(body)}`);
    }
  });

  it("rejects an invalid JSON body with 400 before the RPC", async () => {
    const client = makeOrgClient();
    installProfile(client);
    orgClientHolder.current = client;

    const res = await makePost("{not json", ORG_ALPHA);
    assert.equal(res.status, 400);
    assert.equal((await res.json()).error, "Invalid JSON body");
    assert.equal(client.calls.length, 0);
  });

  it("maps not_org_admin to 403 (authorization boundary preserved)", async () => {
    const client = makeOrgClient();
    installProfile(client);
    client.rpcHandlers.set("add_organization_member", () => rpcError("not_org_admin"));
    orgClientHolder.current = client;

    const res = await makePost({ profile_id: TARGET_ID, role_in_org: "member" });
    const body = await res.json();

    assert.equal(res.status, 403);
    assert.equal(body.error, "Only an organization admin can add members");
    assert.ok(!JSON.stringify(body).includes("not_org_admin"));
  });

  it("maps duplicate membership to 409", async () => {
    const client = makeOrgClient();
    installProfile(client);
    client.rpcHandlers.set("add_organization_member", () =>
      rpcError("already_org_member"),
    );
    orgClientHolder.current = client;

    const res = await makePost({ profile_id: TARGET_ID, role_in_org: "member" });
    assert.equal(res.status, 409);
    assert.equal(
      (await res.json()).error,
      "User is already a member of this organization",
    );
  });

  it("maps a nonexistent target profile to 404", async () => {
    const client = makeOrgClient();
    installProfile(client);
    client.rpcHandlers.set("add_organization_member", () =>
      rpcError("profile_not_found"),
    );
    orgClientHolder.current = client;

    const res = await makePost({ profile_id: TARGET_ID, role_in_org: "member" });
    assert.equal(res.status, 404);
    assert.equal((await res.json()).error, "Profile not found");
  });

  it("never forwards a client-supplied actor id to the RPC", async () => {
    const client = makeOrgClient();
    installProfile(client);
    client.rpcHandlers.set("add_organization_member", () => rpcResult("90000000-0000-0000-0000-0000000000A9"));
    orgClientHolder.current = client;

    // A hostile body tries to smuggle actor/user/role claims. They must be
    // ignored: the RPC is called with only p_org_id/p_profile_id/p_role.
    const res = await makePost({
      profile_id: TARGET_ID,
      role_in_org: "investigator",
      actor_id: "11111111-1111-1111-1111-111111111111",
      user_id: "22222222-2222-2222-2222-222222222222",
      added_by: "33333333-3333-3333-3333-333333333333",
      role: "admin",
    });

    assert.equal(res.status, 201);
    const call = client.calls.find((c) => c.fn === "add_organization_member");
    assert.deepEqual(call!.params, {
      p_org_id: ORG_ALPHA,
      p_profile_id: TARGET_ID,
      p_role: "investigator",
    });
  });
});

// =============================================================================
// ROLE CHANGE — PATCH /api/organizations/[id]/members/[profileId]
// =============================================================================

describe("PATCH /api/organizations/[id]/members/[profileId]", () => {
  it("a valid role reaches change_organization_member_role and returns 200", async () => {
    const client = makeOrgClient();
    installProfile(client);
    client.rpcHandlers.set("change_organization_member_role", () =>
      rpcResult("admin"),
    );
    orgClientHolder.current = client;

    const res = await makePatch({ role_in_org: "admin" });
    const body = await res.json();

    assert.equal(res.status, 200);
    assert.deepEqual(body.member, { profile_id: TARGET_ID, role_in_org: "admin" });
    const call = client.calls.find((c) => c.fn === "change_organization_member_role");
    assert.ok(call, "change_organization_member_role must be called");
    assert.deepEqual(call!.params, {
      p_org_id: ORG_ALPHA,
      p_profile_id: TARGET_ID,
      p_new_role: "admin",
    });
  });

  it("rejects an invalid role before the RPC", async () => {
    const client = makeOrgClient();
    installProfile(client);
    orgClientHolder.current = client;

    const res = await makePatch({ role_in_org: "lead" });
    assert.equal(res.status, 400);
    assert.equal(
      (await res.json()).error,
      "role_in_org must be one of admin, investigator, member",
    );
    assert.equal(client.calls.length, 0);
  });

  it("rejects a missing role before the RPC", async () => {
    const client = makeOrgClient();
    installProfile(client);
    orgClientHolder.current = client;

    const res = await makePatch({});
    assert.equal(res.status, 400);
    assert.equal(client.calls.length, 0);
  });

  it("rejects an invalid target profile id before the RPC", async () => {
    const client = makeOrgClient();
    installProfile(client);
    orgClientHolder.current = client;

    const res = await makePatch({ role_in_org: "member" }, ORG_ALPHA, "not-a-uuid");
    assert.equal(res.status, 400);
    assert.equal((await res.json()).error, "profileId must be a valid uuid");
    assert.equal(client.calls.length, 0);
  });

  it("maps not_org_admin to 403", async () => {
    const client = makeOrgClient();
    installProfile(client);
    client.rpcHandlers.set("change_organization_member_role", () =>
      rpcError("not_org_admin"),
    );
    orgClientHolder.current = client;

    const res = await makePatch({ role_in_org: "member" });
    assert.equal(res.status, 403);
    assert.equal((await res.json()).error, "Only an organization admin can manage members");
  });

  it("maps a nonexistent member to 404", async () => {
    const client = makeOrgClient();
    installProfile(client);
    client.rpcHandlers.set("change_organization_member_role", () =>
      rpcError("member_not_found"),
    );
    orgClientHolder.current = client;

    const res = await makePatch({ role_in_org: "member" });
    assert.equal(res.status, 404);
    assert.equal((await res.json()).error, "Member not found");
  });

  it("maps a last-admin demotion to 409", async () => {
    const client = makeOrgClient();
    installProfile(client);
    client.rpcHandlers.set("change_organization_member_role", () =>
      rpcError("last_org_admin_cannot_be_demoted"),
    );
    orgClientHolder.current = client;

    const res = await makePatch({ role_in_org: "member" });
    assert.equal(res.status, 409);
    assert.equal((await res.json()).error, "The last organization admin cannot be demoted");
  });

  it("never forwards a client-supplied actor id to the RPC", async () => {
    const client = makeOrgClient();
    installProfile(client);
    client.rpcHandlers.set("change_organization_member_role", () =>
      rpcResult("member"),
    );
    orgClientHolder.current = client;

    const res = await makePatch({
      role_in_org: "member",
      actor_id: "11111111-1111-1111-1111-111111111111",
      profile_id: "22222222-2222-2222-2222-222222222222",
    });
    assert.equal(res.status, 200);
    const call = client.calls.find((c) => c.fn === "change_organization_member_role");
    // The target is bound to the path param, not the body.
    assert.deepEqual(call!.params, {
      p_org_id: ORG_ALPHA,
      p_profile_id: TARGET_ID,
      p_new_role: "member",
    });
  });

  it("derives the actor id from the session for the RPC (never a parameter)", async () => {
    const client = makeOrgClient();
    installProfile(client);
    client.rpcHandlers.set("change_organization_member_role", () =>
      rpcResult("member"),
    );
    orgClientHolder.current = client;

    await makePatch({ role_in_org: "member" });
    const call = client.calls.find((c) => c.fn === "change_organization_member_role");
    assert.ok("p_org_id" in call!.params);
    assert.ok("p_profile_id" in call!.params);
    assert.ok("p_new_role" in call!.params);
    // The authz corpus deliberately contains no actor-bearing parameter.
    const keys = Object.keys(call!.params);
    assert.ok(!keys.some((k) => /actor|user/.test(k)));
  });
});

// =============================================================================
// REMOVE — DELETE /api/organizations/[id]/members/[profileId]
// =============================================================================

describe("DELETE /api/organizations/[id]/members/[profileId]", () => {
  it("a valid removal reaches remove_organization_member and returns 200", async () => {
    const client = makeOrgClient();
    installProfile(client);
    client.rpcHandlers.set("remove_organization_member", () => rpcResult(null));
    orgClientHolder.current = client;

    const res = await makeDelete();
    const body = await res.json();

    assert.equal(res.status, 200);
    assert.equal(body.ok, true);
    assert.equal(body.profile_id, TARGET_ID);
    const call = client.calls.find((c) => c.fn === "remove_organization_member");
    assert.ok(call, "remove_organization_member must be called");
    assert.deepEqual(call!.params, {
      p_org_id: ORG_ALPHA,
      p_profile_id: TARGET_ID,
    });
  });

  it("rejects an invalid target profile id before the RPC", async () => {
    const client = makeOrgClient();
    installProfile(client);
    orgClientHolder.current = client;

    const res = await makeDelete(ORG_ALPHA, "not-a-uuid");
    assert.equal(res.status, 400);
    assert.equal(client.calls.length, 0);
  });

  it("maps not_org_admin to 403", async () => {
    const client = makeOrgClient();
    installProfile(client);
    client.rpcHandlers.set("remove_organization_member", () =>
      rpcError("not_org_admin"),
    );
    orgClientHolder.current = client;

    const res = await makeDelete();
    const body = await res.json();

    assert.equal(res.status, 403);
    assert.equal(body.error, "Only an organization admin can manage members");
    assert.ok(!JSON.stringify(body).includes("not_org_admin"));
  });

  it("maps a nonexistent member to 404", async () => {
    const client = makeOrgClient();
    installProfile(client);
    client.rpcHandlers.set("remove_organization_member", () =>
      rpcError("member_not_found"),
    );
    orgClientHolder.current = client;

    const res = await makeDelete();
    assert.equal(res.status, 404);
    assert.equal((await res.json()).error, "Member not found");
  });

  it("maps a last-admin removal to 409", async () => {
    const client = makeOrgClient();
    installProfile(client);
    client.rpcHandlers.set("remove_organization_member", () =>
      rpcError("last_org_admin_cannot_be_removed"),
    );
    orgClientHolder.current = client;

    const res = await makeDelete();
    assert.equal(res.status, 409);
    assert.equal((await res.json()).error, "The last organization admin cannot be removed");
  });

  it("accepts no request body — the actor cannot be spoofed", async () => {
    const client = makeOrgClient();
    installProfile(client);
    // Should the latest handler try to read a body/actor claim, the stub
    // calling remove_organization_member with only p_org_id/p_profile_id proves
    // there is no actor-bearing input on this path.
    client.rpcHandlers.set("remove_organization_member", () => rpcResult(null));
    orgClientHolder.current = client;

    const res = await makeDelete();
    assert.equal(res.status, 200);

    const call = client.calls.find((c) => c.fn === "remove_organization_member");
    assert.deepEqual(Object.keys(call!.params).sort(), ["p_org_id", "p_profile_id"]);
  });
});

// =============================================================================
// Defense in depth — raw RPC internals never leak into responses
// =============================================================================

describe("organization API — RPC error messages never leak internals", () => {
  it("unknown RPC failures map to a safe 500 without echoing the message", async () => {
    const client = makeOrgClient();
    installProfile(client);
    client.rpcHandlers.set("list_organization_members", () =>
      rpcError("connection reset by peer: secret db credentials"),
    );
    orgClientHolder.current = client;

    const res = await makeGet(memberUrl());
    const body = await res.json();

    assert.equal(res.status, 500);
    assert.equal(body.error, "Failed to load members");
    const serialized = JSON.stringify(body);
    assert.ok(!serialized.includes("connection reset"));
    assert.ok(!serialized.includes("credentials"));
  });
});