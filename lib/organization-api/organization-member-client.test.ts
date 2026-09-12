import { describe, it, after, beforeEach } from "node:test"
import assert from "node:assert/strict"
import {
  addOrganizationMember,
  changeMemberRole,
  removeOrganizationMember,
  fetchMemberLookup,
} from "./organization-member-client.ts"

// ---------------------------------------------------------------------------
// Client-side API helper tests for the member management UI:
//   – request shape: correct URL, method, and body
//   – actor identity is never sent (authz is server-side)
//   – known error statuses map to concise user-facing messages
//   – generic failures never leak server internals
// globalThis.fetch is mocked; no live network or backend is involved.
// ---------------------------------------------------------------------------

const ORG = "82000000-0000-0000-0000-0000000000A1"
const TARGET = "81000000-0000-0000-0000-000000000006"

type FetchState = {
  calls: Array<{ url: string; init?: RequestInit }>
  handler: (url: string, init?: RequestInit) => Response | Promise<Response>
}

const fetchState: FetchState = {
  calls: [],
  handler: () => jsonResponse(200, {}),
}

let origFetch: typeof globalThis.fetch

function jsonResponse(status: number, body: object): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  })
}

beforeEach(() => {
  fetchState.calls = []
  fetchState.handler = () => jsonResponse(200, {})
  origFetch = origFetch ?? globalThis.fetch
  globalThis.fetch = ((url: string | URL | Request, init?: RequestInit) => {
    fetchState.calls.push({ url: String(url), init })
    return Promise.resolve(fetchState.handler(String(url), init))
  }) as typeof globalThis.fetch
})

after(() => {
  globalThis.fetch = origFetch
})

function lastBody(): Record<string, unknown> | undefined {
  const init = fetchState.calls.at(-1)?.init
  if (!init?.body) return undefined
  try {
    return JSON.parse(String(init.body)) as Record<string, unknown>
  } catch {
    return undefined
  }
}

const ADD_INPUT = { profile_id: TARGET, role_in_org: "investigator" as const }

describe("organization-member-client", () => {
  describe("addOrganizationMember", () => {
    it("sends the correct request shape and returns ok on success", async () => {
      fetchState.handler = () =>
        jsonResponse(201, { member: { organization_member_id: "new-id" } })

      const result = await addOrganizationMember(ORG, ADD_INPUT)

      assert.deepEqual(result, { ok: true })
      assert.equal(fetchState.calls.length, 1)
      assert.equal(fetchState.calls[0]?.url, `/api/organizations/${ORG}/members`)
      assert.equal(fetchState.calls[0]?.init?.method, "POST")
      assert.deepEqual(lastBody(), ADD_INPUT)
    })

    it("never sends an actor, user, or added_by field", async () => {
      fetchState.handler = () => jsonResponse(201, { member: {} })

      await addOrganizationMember(ORG, ADD_INPUT)

      const body = lastBody() ?? {}
      const keys = Object.keys(body)
      assert.ok(
        !keys.some((k) => /actor|user|added_by/i.test(k)),
        `unexpected credential-bearing field in ${JSON.stringify(body)}`,
      )
    })

    it("maps 403 to a permission message", async () => {
      fetchState.handler = () => jsonResponse(403, { error: "not_org_admin" })

      const result = await addOrganizationMember(ORG, ADD_INPUT)

      assert.equal(result.ok, false)
      if (!result.ok) {
        assert.match(result.message, /permission/i)
        assert.ok(!result.message.includes("not_org_admin"))
      }
    })

    it("maps 409 duplicate membership to a duplicate message", async () => {
      fetchState.handler = () =>
        jsonResponse(409, {
          error: "User is already a member of this organization",
        })

      const result = await addOrganizationMember(ORG, ADD_INPUT)

      assert.equal(result.ok, false)
      if (!result.ok) {
        assert.match(result.message, /already a member/i)
      }
    })

    it("maps 404 to a not-found message", async () => {
      fetchState.handler = () =>
        jsonResponse(404, { error: "organization_not_found" })

      const result = await addOrganizationMember(ORG, ADD_INPUT)

      assert.equal(result.ok, false)
      if (!result.ok) {
        assert.match(result.message, /not be found/i)
        assert.ok(!result.message.includes("organization_not_found"))
      }
    })

    it("maps 500 to a generic message without leaking details", async () => {
      fetchState.handler = () =>
        jsonResponse(500, {
          error: "connection reset by peer: secret db credentials",
        })

      const result = await addOrganizationMember(ORG, ADD_INPUT)

      assert.equal(result.ok, false)
      if (!result.ok) {
        assert.match(result.message, /something went wrong/i)
        assert.ok(!result.message.includes("connection"))
        assert.ok(!result.message.includes("credentials"))
      }
    })
  })

  describe("changeMemberRole", () => {
    it("sends the correct request shape and returns ok on success", async () => {
      fetchState.handler = () =>
        jsonResponse(200, { member: { profile_id: TARGET, role_in_org: "admin" } })

      const result = await changeMemberRole(ORG, TARGET, "admin")

      assert.deepEqual(result, { ok: true })
      assert.equal(fetchState.calls.length, 1)
      assert.equal(
        fetchState.calls[0]?.url,
        `/api/organizations/${ORG}/members/${TARGET}`,
      )
      assert.equal(fetchState.calls[0]?.init?.method, "PATCH")
      assert.deepEqual(lastBody(), { role_in_org: "admin" })
    })

    it("never sends an actor or user field", async () => {
      fetchState.handler = () => jsonResponse(200, { member: {} })

      await changeMemberRole(ORG, TARGET, "member")

      const body = lastBody() ?? {}
      assert.ok(
        !Object.keys(body).some((k) => /actor|user|added_by/i.test(k)),
      )
    })

    it("maps 409 last-admin demotion to the last-admin message", async () => {
      fetchState.handler = () =>
        jsonResponse(409, {
          error: "The last organization admin cannot be demoted",
        })

      const result = await changeMemberRole(ORG, TARGET, "member")

      assert.equal(result.ok, false)
      if (!result.ok) {
        assert.match(result.message, /last organization admin/i)
      }
    })
  })

  describe("removeOrganizationMember", () => {
    it("sends a DELETE request with no body and returns ok", async () => {
      fetchState.handler = () => jsonResponse(200, { ok: true })

      const result = await removeOrganizationMember(ORG, TARGET)

      assert.deepEqual(result, { ok: true })
      assert.equal(fetchState.calls.length, 1)
      assert.equal(
        fetchState.calls[0]?.url,
        `/api/organizations/${ORG}/members/${TARGET}`,
      )
      assert.equal(fetchState.calls[0]?.init?.method, "DELETE")
      assert.ok(!fetchState.calls[0]?.init?.body)
    })

    it("maps 404 to a not-found message", async () => {
      fetchState.handler = () =>
        jsonResponse(404, { error: "member_not_found" })

      const result = await removeOrganizationMember(ORG, TARGET)

      assert.equal(result.ok, false)
      if (!result.ok) {
        assert.match(result.message, /not be found/i)
      }
    })

    it("maps 409 last-admin removal to the last-admin message", async () => {
      fetchState.handler = () =>
        jsonResponse(409, {
          error: "The last organization admin cannot be removed",
        })

      const result = await removeOrganizationMember(ORG, TARGET)

      assert.equal(result.ok, false)
      if (!result.ok) {
        assert.match(result.message, /last organization admin/i)
      }
    })

    it("maps a network failure to a generic message", async () => {
      fetchState.handler = () => {
        throw new TypeError("fetch failed")
      }

      const result = await removeOrganizationMember(ORG, TARGET)

      assert.equal(result.ok, false)
      if (!result.ok) {
        assert.match(result.message, /something went wrong/i)
      }
    })
  })

  describe("fetchMemberLookup", () => {
    it("sends a GET with the query parameter and returns profiles", async () => {
      fetchState.handler = () =>
        jsonResponse(200, {
          profiles: [
            { id: TARGET, full_name: "Priya Nair", badge_number: "B-2002" },
          ],
        })

      const result = await fetchMemberLookup(ORG, "Priya")

      assert.equal(result.ok, true)
      if (result.ok) {
        assert.equal(result.profiles.length, 1)
        assert.equal(result.profiles[0]?.id, TARGET)
      }
      assert.equal(fetchState.calls.length, 1)
      assert.ok(fetchState.calls[0]?.url.includes("q=Priya"))
    })

    it("returns an empty list for an empty result set", async () => {
      fetchState.handler = () => jsonResponse(200, { profiles: [] })

      const result = await fetchMemberLookup(ORG, "zzzz")

      assert.equal(result.ok, true)
      if (result.ok) {
        assert.equal(result.profiles.length, 0)
      }
    })

    it("maps 403 to a permission message", async () => {
      fetchState.handler = () => jsonResponse(403, { error: "Forbidden" })

      const result = await fetchMemberLookup(ORG, "Test")

      assert.equal(result.ok, false)
      if (!result.ok) {
        assert.match(result.message, /permission/i)
      }
    })
  })
})