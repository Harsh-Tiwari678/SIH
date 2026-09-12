// Unit tests for the evidence-upload ↔ blockchain-anchor integration boundary.
// Uses Node's built-in test runner (node:test) + node:assert/strict. No real
// blockchain transaction and no DB access: requestPendingAnchor runs against a
// stubbed rpc() client, and the HTTP helpers are pure.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  anchorErrorStatus,
  anchorOutcomeBody,
  anchorOutcomeHttpStatus,
  persistedVersionIdFromResponse,
  requestPendingAnchor,
  type AnchorRpcClient,
} from "./upload-integration.ts";
import type { AnchorOutcome } from "./orchestrator.ts";

// Test fixtures (NOT the already-anchored live Sepolia pair).
const EVIDENCE_UUID = "12345678-1234-4234-8234-123456789abc";
const PERSISTED_VERSION_ID = "22222222-2222-4222-8222-222222222222";
const ANCHOR_ID = "aaaaaaaa-1111-4111-8111-111111111111";

function createEvidenceResponse(documentVersionId: unknown): unknown {
  return {
    evidence: { id: EVIDENCE_UUID, title: "evidence-note.pdf" },
    document_version: { id: documentVersionId, version: 1, sha256: "a".repeat(64) },
  };
}

function fakeClient(result: {
  data?: unknown;
  error?: { message: string };
}): AnchorRpcClient & {
  calls: Array<{ fn: string; params: Record<string, string> }>;
} {
  const calls: Array<{ fn: string; params: Record<string, string> }> = [];
  return {
    calls,
    async rpc(fn: string, params: Record<string, string>) {
      calls.push({ fn, params });
      if (result.error) return { data: null, error: result.error };
      return { data: result.data ?? null, error: null };
    },
  };
}

// ---- persistedVersionIdFromResponse ----------------------------------------

test("persistedVersionIdFromResponse returns the actual persisted version id", () => {
  assert.equal(
    persistedVersionIdFromResponse(
      createEvidenceResponse(PERSISTED_VERSION_ID),
    ),
    PERSISTED_VERSION_ID,
  );
});

test("persistedVersionIdFromResponse returns null when no document_version is present", () => {
  // Shape of a failed/malformed creation — an anchor must not be requested.
  assert.equal(persistedVersionIdFromResponse({ error: "db_down" }), null);
  assert.equal(persistedVersionIdFromResponse(null), null);
  assert.equal(persistedVersionIdFromResponse(undefined), null);
});

test("persistedVersionIdFromResponse returns null for a malformed version id", () => {
  assert.equal(
    persistedVersionIdFromResponse(
      createEvidenceResponse("not-a-uuid"),
    ),
    null,
  );
  assert.equal(
    persistedVersionIdFromResponse(createEvidenceResponse(12345)),
    null,
  );
});

// ---- requestPendingAnchor ----------------------------------------------------

test("requestPendingAnchor returns pending with the committed anchor id", async () => {
  const client = fakeClient({
    data: {
      anchor: {
        id: ANCHOR_ID,
        status: "pending",
        document_version_id: PERSISTED_VERSION_ID,
      },
      reused: false,
    },
  });

  const result = await requestPendingAnchor(client, PERSISTED_VERSION_ID);

  assert.deepEqual(result, { status: "pending", anchorId: ANCHOR_ID });
  assert.deepEqual(client.calls, [
    {
      fn: "create_blockchain_anchor",
      params: { p_document_version_id: PERSISTED_VERSION_ID },
    },
  ]);
});

test("requestPendingAnchor returns pending for a reused (already pending) row", async () => {
  const client = fakeClient({
    data: {
      anchor: { id: ANCHOR_ID, status: "pending" },
      reused: true,
    },
  });

  const result = await requestPendingAnchor(client, PERSISTED_VERSION_ID);

  assert.deepEqual(result, { status: "pending", anchorId: ANCHOR_ID });
});

test("requestPendingAnchor maps an already_anchored RPC error defensively", async () => {
  const client = fakeClient({
    error: { message: "already_anchored" },
  });

  const result = await requestPendingAnchor(client, PERSISTED_VERSION_ID);

  assert.deepEqual(result, { status: "already_anchored" });
});

test("requestPendingAnchor maps a returned anchored row defensively", async () => {
  const client = fakeClient({
    data: { anchor: { id: ANCHOR_ID, status: "anchored" } },
  });

  const result = await requestPendingAnchor(client, PERSISTED_VERSION_ID);

  assert.deepEqual(result, { status: "already_anchored" });
});

test("requestPendingAnchor returns null on an RPC failure without throwing", async () => {
  // create_blockchain_anchor only fails here if it can't create the row
  // (e.g. DB error). Evidence creation stays successful and the anchor is
  // simply not created yet.
  const client = fakeClient({
    error: { message: "remote database error" },
  });

  const result = await requestPendingAnchor(client, PERSISTED_VERSION_ID);

  assert.equal(result, null);
});

test("requestPendingAnchor returns null for a malformed RPC response", async () => {
  const client = fakeClient({ data: {} });

  const result = await requestPendingAnchor(client, PERSISTED_VERSION_ID);

  assert.equal(result, null);
});

test("requestPendingAnchor rejects an invalid version id without calling the RPC", async () => {
  const client = fakeClient({ data: { anchor: { id: ANCHOR_ID, status: "pending" } } });

  const result = await requestPendingAnchor(client, "not-a-uuid");

  assert.equal(result, null);
  assert.equal(client.calls.length, 0);
});

// ---- anchorOutcomeBody ------------------------------------------------------

test("anchorOutcomeBody exposes the full anchored state", () => {
  const outcome: AnchorOutcome = {
    status: "anchored",
    anchorId: ANCHOR_ID,
    txHash: "0x" + "a".repeat(64),
    blockNumber: 123,
    anchoredAt: "2023-11-14T22:13:20.000Z",
  };
  assert.deepEqual(anchorOutcomeBody(outcome), {
    status: "anchored",
    anchor_id: ANCHOR_ID,
    tx_hash: "0x" + "a".repeat(64),
    block_number: 123,
    anchored_at: "2023-11-14T22:13:20.000Z",
  });
});

test("[10] reconciling exposes the recovered block metadata but NEVER a tx hash", () => {
  assert.deepEqual(
    anchorOutcomeBody({
      status: "reconciled",
      anchorId: ANCHOR_ID,
      blockNumber: 19_000_000,
      anchoredAt: "2023-11-14T22:13:20.000Z",
    }),
    {
      status: "reconciled",
      anchor_id: ANCHOR_ID,
      block_number: 19_000_000,
      anchored_at: "2023-11-14T22:13:20.000Z",
    },
  );
});

test("anchorOutcomeBody maps already_anchored", () => {
  assert.deepEqual(anchorOutcomeBody({ status: "already_anchored" }), {
    status: "already_anchored",
  });
});

test("anchorOutcomeBody maps failed", () => {
  assert.deepEqual(
    anchorOutcomeBody({
      status: "failed",
      anchorId: ANCHOR_ID,
      category: "network_error",
      message: "Unable to reach the blockchain network",
    }),
    {
      status: "failed",
      anchor_id: ANCHOR_ID,
      category: "network_error",
      message: "Unable to reach the blockchain network",
    },
  );
});

test("anchorOutcomeBody maps verification_failed", () => {
  assert.deepEqual(
    anchorOutcomeBody({
      status: "verification_failed",
      anchorId: ANCHOR_ID,
      message: "mismatch",
    }),
    { status: "verification_failed", anchor_id: ANCHOR_ID, message: "mismatch" },
  );
});

test("anchorOutcomeBody maps verification_ambiguous", () => {
  assert.deepEqual(
    anchorOutcomeBody({
      status: "verification_ambiguous",
      anchorId: ANCHOR_ID,
      message: "read unavailable",
    }),
    { status: "verification_ambiguous", anchor_id: ANCHOR_ID },
  );
});

test("anchorOutcomeBody maps db_sync_failed", () => {
  assert.deepEqual(
    anchorOutcomeBody({
      status: "db_sync_failed",
      anchorId: ANCHOR_ID,
      message: "db sync window",
    }),
    { status: "db_sync_failed", anchor_id: ANCHOR_ID },
  );
});

// ---- anchorOutcomeHttpStatus ------------------------------------------------

test("anchorOutcomeHttpStatus returns 200 for anchored outcomes", () => {
  assert.equal(anchorOutcomeHttpStatus({ status: "anchored", anchorId: ANCHOR_ID, txHash: "0x" + "a".repeat(64), blockNumber: 1, anchoredAt: "x" }), 200);
  assert.equal(anchorOutcomeHttpStatus({ status: "reconciled", anchorId: ANCHOR_ID, blockNumber: 1, anchoredAt: "x" }), 200);
  assert.equal(anchorOutcomeHttpStatus({ status: "already_anchored" }), 200);
});

test("anchorOutcomeHttpStatus returns 202 for reconcilable outcomes", () => {
  assert.equal(anchorOutcomeHttpStatus({ status: "verification_ambiguous", anchorId: ANCHOR_ID, message: "x" }), 202);
  assert.equal(anchorOutcomeHttpStatus({ status: "db_sync_failed", anchorId: ANCHOR_ID, message: "x" }), 202);
});

test("anchorOutcomeHttpStatus returns 502 for definitive upstream failures", () => {
  assert.equal(anchorOutcomeHttpStatus({ status: "failed", anchorId: ANCHOR_ID, category: "network_error", message: "x" }), 502);
  assert.equal(anchorOutcomeHttpStatus({ status: "verification_failed", anchorId: ANCHOR_ID, message: "x" }), 502);
});

// ---- anchorErrorStatus ------------------------------------------------------

test("anchorErrorStatus maps orchestration error kinds to HTTP statuses", () => {
  assert.equal(anchorErrorStatus({ kind: "invalid_request", message: "m" }).status, 400);
  assert.equal(anchorErrorStatus({ kind: "not_authenticated", message: "m" }).status, 401);
  assert.equal(anchorErrorStatus({ kind: "profile_not_found", message: "m" }).status, 403);
  assert.equal(anchorErrorStatus({ kind: "not_authorized_to_anchor", message: "m" }).status, 403);
  assert.equal(anchorErrorStatus({ kind: "case_not_open", message: "m" }).status, 409);
  assert.equal(anchorErrorStatus({ kind: "document_version_not_found", message: "m" }).status, 404);
  assert.equal(anchorErrorStatus({ kind: "evidence_not_found", message: "m" }).status, 404);
  assert.equal(anchorErrorStatus({ kind: "rpc_error", message: "m" }).status, 500);
  assert.equal(anchorErrorStatus({ kind: "invalid_rpc_result", message: "m" }).status, 500);
  assert.equal(anchorErrorStatus({ kind: "database_error", message: "m" }).status, 500);
});

test("[7] authorization failures surface as 4xx, never as an anchor success", () => {
  // Requirement 7: authorization is server-side. A session-less or non-leading
  // actor must never see a 200 anchor outcome — only a 401/403 error.
  assert.notEqual(anchorErrorStatus({ kind: "not_authenticated", message: "m" }).status, 200);
  assert.notEqual(anchorErrorStatus({ kind: "not_authorized_to_anchor", message: "m" }).status, 200);
  assert.equal(
    anchorErrorStatus({ kind: "not_authenticated", message: "m" }).error,
    "m",
  );
});

test("anchorErrorStatus keeps the safe orchestration message", () => {
  assert.equal(
    anchorErrorStatus({ kind: "not_authorized_to_anchor", message: "Only the case lead or an investigator can anchor evidence" }).error,
    "Only the case lead or an investigator can anchor evidence",
  );
});

test("anchorErrorStatus returns a generic 500 for unexpected errors", () => {
  assert.deepEqual(anchorErrorStatus(new Error("boom")), {
    status: 500,
    error: "Unexpected error",
  });
});