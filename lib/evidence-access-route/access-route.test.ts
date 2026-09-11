import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { NextRequest } from "next/server.js";
import { EVIDENCE_BUCKET } from "../storage.ts";
import { SIGNED_URL_LIFETIME_SECONDS } from "../evidence-access.ts";
import { GET } from "../../app/api/cases/[id]/evidence/[evidenceId]/access/route.ts";
import {
  accessClientHolder,
  makeAccessClient,
  type AccessFakeSupabaseClient,
} from "./test-support/access-server-stub.ts";

// ---------------------------------------------------------------------------
// Route-level unit tests for the fail-closed evidence.accessed audit:
//
//   authenticate -> authorize -> resolve -> signed URL -> audit -> return URL
//
// The @/lib/supabase/server alias resolves to access-server-stub.ts (via
// lib/blockchain/test-support/test-loader.mjs), next/server resolves to
// next/server.js, and the other @/lib aliases map to the real sources. This
// exercises the real route handler without a live Supabase and without
// weakening the live SQL security tests in supabase/tests/.
// ---------------------------------------------------------------------------

const CASE_ID = "20000000-0000-0000-0000-0000000000A1";
const EVIDENCE_ID = "30000000-0000-0000-0000-0000000000A1";
const VERSION_ID = "40000000-0000-0000-0000-0000000000A1";
const STORAGE_KEY = `${CASE_ID}/${EVIDENCE_ID}/${VERSION_ID}`;

const RESOLVED = {
  case_id: CASE_ID,
  evidence_id: EVIDENCE_ID,
  document_version_id: VERSION_ID,
  version: 1,
  file_name: "unnested.pdf",
  mime_type: "application/pdf",
  file_size_bytes: 100,
  storage_key: STORAGE_KEY,
};

const SIGNED_URL_MARKER = "https://storage.example/object/sign/evidence-files/";

function installHappyPath(client: AccessFakeSupabaseClient) {
  client.tableHandlers.set("profiles", () => ({
    data: { id: "00000000-0000-4000-8000-000000000001" },
    error: null,
  }));
  client.rpcHandlers.set("resolve_evidence_access", () => ({
    data: RESOLVED,
    error: null,
  }));
  client.rpcHandlers.set("record_evidence_access", () => ({
    data: null,
    error: null,
  }));
}

function request(query: string): NextRequest {
  return new NextRequest(
    `http://localhost/api/cases/${CASE_ID}/evidence/${EVIDENCE_ID}/access${query}`,
  );
}

async function callGet(query = "") {
  const ctx = {
    params: Promise.resolve({ id: CASE_ID, evidenceId: EVIDENCE_ID }),
  };
  return GET(request(query), ctx as never);
}

interface CapturedLog {
  entries: string[];
  restore(): void;
}

function captureConsoleError(): CapturedLog {
  const original = console.error;
  const entries: string[] = [];
  console.error = (...args: unknown[]) => {
    entries.push(args.map(String).join(" "));
  };
  return {
    entries,
    restore() {
      console.error = original;
    },
  };
}

describe("evidence access route — fail-closed audit ordering", () => {
  it("returns the signed URL ONLY when the audit is recorded", async () => {
    const client = makeAccessClient();
    installHappyPath(client);
    accessClientHolder.current = client;

    const res = await callGet("?mode=preview&version=" + VERSION_ID);
    const body = await res.json();

    assert.equal(res.status, 200);
    assert.equal(res.headers.get("Cache-Control"), "no-store");
    assert.ok(body.access, "expected an access payload");
    assert.equal(body.access.mode, "preview");
    assert.ok(body.access.url.startsWith(SIGNED_URL_MARKER), "expected a signed URL");
    assert.equal(body.access.file_name, RESOLVED.file_name);
    assert.equal(body.access.mime_type, RESOLVED.mime_type);
    assert.equal(body.access.version, RESOLVED.version);

    // the server minted the URL for exactly the server-resolved storage key...
    assert.equal(client.signs.length, 1);
    assert.equal(client.signs[0]!.path, STORAGE_KEY);
    assert.equal(client.signs[0]!.expiresIn, SIGNED_URL_LIFETIME_SECONDS);
    assert.deepEqual(client.signs[0]!.options, { download: false });

    // ...and the audit ran for the resolved version, in the same mode.
    const audit = client.calls.find((c) => c.fn === "record_evidence_access");
    assert.ok(audit, "record_evidence_access must have been called");
    assert.equal(audit.params.p_document_version_id, VERSION_ID);
    assert.equal(audit.params.p_mode, "preview");

    // storage_key never appears as a discrete field; the object path only
    // exists inside the signed URL (as its time-limited target), which is the
    // only permitted disclosure — the same server-derived key, in URL form.
    const serialized = JSON.stringify(body);
    assert.ok(!serialized.includes("storage_key"));
    assert.ok(!("path" in body.access), "no standalone path field");
    assert.ok(!("storage_key" in body.access), "no standalone storage_key field");
    const signedUrl = new URL(body.access.url);
    assert.ok(signedUrl.pathname.includes(STORAGE_KEY), "signed URL targets the resolved object");
  });

  it("download mode asks the storage layer to force a same-name download", async () => {
    const client = makeAccessClient();
    installHappyPath(client);
    accessClientHolder.current = client;

    const res = await callGet("?mode=download&version=" + VERSION_ID);
    const body = await res.json();

    assert.equal(res.status, 200);
    assert.equal(body.access.mode, "download");
    assert.equal(client.signs[0]!.options?.download, RESOLVED.file_name);
    const audit = client.calls.find((c) => c.fn === "record_evidence_access");
    assert.equal(audit!.params.p_mode, "download");
  });

  it("FAILS CLOSED: audit failure => 500, signed URL never delivered or leaked", async () => {
    const client = makeAccessClient();
    installHappyPath(client);
    // audit breaks; the error text mimics internal detail that must not leak
    client.rpcHandlers.set("record_evidence_access", () => ({
      data: null,
      error: { message: "internal: audit sink unreachable (credential rotated)" },
    }));
    accessClientHolder.current = client;

    const log = captureConsoleError();
    try {
      const res = await callGet("?mode=preview");
      const body = await res.json();

      assert.equal(res.status, 500);
      assert.ok(!("access" in body), "no access payload may be returned");
      // generic message; internal audit error detail is never exposed
      assert.equal(typeof body.error, "string");
      const responseText = JSON.stringify(body);
      assert.ok(!responseText.includes("credential rotated"));
      assert.ok(!responseText.includes("audit sink"));

      // the signed URL was minted but must not appear anywhere in the response
      const mintedUrl = client.signUrls[0]!;
      assert.ok(mintedUrl.startsWith(SIGNED_URL_MARKER), "expected a minted signed URL");
      assert.ok(!responseText.includes(mintedUrl));
      assert.ok(!responseText.includes(SIGNED_URL_MARKER));

      // server-side log: identifiers + event only, never URL, storage key or
      // the internal audit error text
      const logged = log.entries.join("\n");
      assert.ok(logged.includes("evidence_access_audit_failed"));
      assert.ok(!logged.includes(mintedUrl));
      assert.ok(!logged.includes(STORAGE_KEY));
      assert.ok(!logged.includes("credential rotated"));
      assert.ok(!logged.includes("audit sink unreachable"));
    } finally {
      log.restore();
    }
  });

  it("sign failure => 500 and the audit is never attempted", async () => {
    const client = makeAccessClient();
    installHappyPath(client);
    client.rpcHandlers.set("record_evidence_access", () => {
      throw new Error("record must not be called");
    });
    client.signHandler = () => ({ data: null, error: { message: "storage sign error" } });
    accessClientHolder.current = client;

    const res = await callGet("?mode=preview");
    const body = await res.json();

    assert.equal(res.status, 500);
    assert.ok(!("access" in body));
    assert.ok(!client.calls.some((c) => c.fn === "record_evidence_access"));
    assert.ok(!JSON.stringify(body).includes("storage sign error"));
  });

  it("authorization failure (resolve) => 404 and execution stops before signing/audit", async () => {
    const client = makeAccessClient();
    client.tableHandlers.set("profiles", () => ({
      data: { id: "00000000-0000-4000-8000-000000000001" },
      error: null,
    }));
    client.rpcHandlers.set("resolve_evidence_access", () => ({
      data: null,
      error: { message: "evidence_not_found" },
    }));
    accessClientHolder.current = client;

    const res = await callGet("?mode=preview");
    const body = await res.json();

    assert.equal(res.status, 404);
    assert.equal(body.error, "Evidence not found");
    assert.equal(client.signs.length, 0);
    assert.ok(!client.calls.some((c) => c.fn === "record_evidence_access"));
  });

  it("binds the sign call to the server-resolved bucket and key (no client path)", async () => {
    const client = makeAccessClient();
    installHappyPath(client);
    accessClientHolder.current = client;

    await callGet("?mode=preview");
    // The storage path is exactly the RPC-returned storage_key inside the
    // fixed private bucket; there is no route, query or header driven path.
    assert.equal(client.signs[0]!.path, RESOLVED.storage_key);
    assert.notEqual(EVIDENCE_BUCKET.length, 0); // bucket constant, not a client value
  });
});