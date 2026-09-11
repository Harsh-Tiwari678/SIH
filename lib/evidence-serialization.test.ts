// Unit tests for the pure evidence response-shaping helpers. Uses Node's built-in
// test runner (node:test) — no DB/network. Covers the serialization contracts the
// new read endpoints and the client views rely on.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  parseAnchorContext,
  serializeEvidenceDetail,
  serializeEvidenceListItem,
  type AnchorRawRow,
  type CustodyRawRow,
  type EvidenceCoreRawRow,
  type EvidenceListRawRow,
  type VersionRawRow,
} from "./evidence-serialization.ts";

const EVIDENCE_UUID = "12345678-1234-4234-8234-123456789abc";
const VERSION_UUID_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1";
const VERSION_UUID_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2";
const SHA256 =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

const coreBase = (): EvidenceCoreRawRow => ({
  id: EVIDENCE_UUID,
  case_id: "22222222-2222-4222-8222-222222222222",
  evidence_number: "EV-001",
  title: "Crime scene photo",
  description: "Shot on a phone, transferred raw.",
  type: "image",
  status: "under_review",
  created_at: "2026-09-01T10:00:00Z",
  updated_at: "2026-09-01T10:00:00Z",
  created_by: "33333333-3333-4333-8333-333333333333",
  creator: { id: "33333333-3333-4333-8333-333333333333", full_name: "A. Inspector" },
});

// ---- serializeEvidenceListItem -------------------------------------------------

test("serializeEvidenceListItem picks the highest version regardless of array order", () => {
  const row = {
    ...coreBase(),
    document_versions: [
      {
        id: VERSION_UUID_A,
        version: 1,
        file_name: "a.txt",
        mime_type: "text/plain",
        file_size_bytes: 10,
        sha256: SHA256,
        uploaded_at: "2026-09-01T10:00:00Z",
      },
      {
        id: VERSION_UUID_B,
        version: 2,
        file_name: "b.txt",
        mime_type: "text/plain",
        file_size_bytes: 20,
        sha256: SHA256,
        uploaded_at: "2026-09-02T10:00:00Z",
      },
    ],
  } satisfies EvidenceListRawRow;
  const item = serializeEvidenceListItem(row);

  assert.equal(item.evidence_number, "EV-001");
  assert.equal(item.version_count, 2);
  assert.equal(item.latest_version?.id, VERSION_UUID_B);
  assert.equal(item.latest_version?.version, 2);
  assert.equal(item.creator_name, "A. Inspector");
  assert.equal(item.status, "under_review");
  assert.equal(item.type, "image");
});

test("serializeEvidenceListItem handles an evidence row with no versions and no creator", () => {
  const item = serializeEvidenceListItem({
    ...coreBase(),
    creator: null,
    document_versions: [],
  });
  assert.equal(item.latest_version, null);
  assert.equal(item.version_count, 0);
  assert.equal(item.creator_name, null);
});

test("serializeEvidenceListItem copies the digest fields exactly for integrity display", () => {
  const item = serializeEvidenceListItem({
    ...coreBase(),
    document_versions: [
      {
        id: VERSION_UUID_A,
        version: 1,
        file_name: "a.txt",
        mime_type: "text/plain",
        file_size_bytes: 10,
        sha256: SHA256,
        uploaded_at: "2026-09-01T10:00:00Z",
      },
    ],
  });
  assert.equal(item.latest_version?.sha256, SHA256);
  assert.equal(item.latest_version?.file_name, "a.txt");
});

// ---- parseAnchorContext --------------------------------------------------------

const anchorBase = (): AnchorRawRow => ({
  id: "44444444-4444-4444-8444-444444444444",
  document_version_id: VERSION_UUID_A,
  status: "anchored",
  tx_hash: `0x${"a".repeat(64)}`,
  block_number: 19_000_000,
  anchored_at: "2026-09-03T10:00:00Z",
  network: "sepolia",
  chain_id: 11155111,
  contract_address: "0x1D76cea78A844fed9aca674C82a900917e848b1a",
  error_message: null,
});

test("parseAnchorContext keeps the permit-listed anchored facts", () => {
  const ctx = parseAnchorContext(anchorBase());
  assert.ok(ctx);
  assert.equal(ctx.status, "anchored");
  assert.equal(ctx.tx_hash, `0x${"a".repeat(64)}`);
  assert.equal(ctx.block_number, 19_000_000);
  assert.equal(ctx.network, "sepolia");
  assert.equal(ctx.chain_id, 11155111);
});

test("parseAnchorContext drops a non-genuine tx_hash (reconciled rows keep NULL)", () => {
  const ctx = parseAnchorContext({
    ...anchorBase(),
    status: "anchored",
    tx_hash: "not-a-hash",
  });
  assert.ok(ctx);
  assert.equal(ctx.tx_hash, null);
});

test("parseAnchorContext rejects unknown statuses entirely", () => {
  assert.equal(parseAnchorContext({ ...anchorBase(), status: "confirmed" }), null);
});

test("parseAnchorContext coerces string chain_id/block_number and passes NULLs through", () => {
  const ctx = parseAnchorContext({
    ...anchorBase(),
    status: "pending",
    chain_id: "11155111",
    block_number: null,
    anchored_at: null,
    error_message: "nope",
  });
  assert.ok(ctx);
  assert.equal(ctx.chain_id, 11155111);
  assert.equal(ctx.block_number, null);
  assert.equal(ctx.anchored_at, null);
  assert.equal(ctx.error_message, "nope");
});

test("parseAnchorContext returns null for a missing row", () => {
  assert.equal(parseAnchorContext(null), null);
  assert.equal(parseAnchorContext(undefined), null);
});

// ---- serializeEvidenceDetail ---------------------------------------------------

const versionA = (): VersionRawRow => ({
  id: VERSION_UUID_A,
  version: 1,
  prev_version_id: null,
  file_name: "a.txt",
  mime_type: "text/plain",
  file_size_bytes: 10,
  sha256: SHA256,
  uploaded_by: "33333333-3333-4333-8333-333333333333",
  uploaded_at: "2026-09-01T10:00:00Z",
  notes: null,
  uploader: { id: "33333333-3333-4333-8333-333333333333", full_name: "A. Inspector" },
});

const custodyRow = (): CustodyRawRow => ({
  id: "55555555-5555-4555-8555-555555555555",
  action: "received",
  actor_id: "33333333-3333-4333-8333-333333333333",
  from_profile_id: null,
  to_profile_id: "33333333-3333-4333-8333-333333333333",
  location: "Station 4",
  notes: "Initial intake",
  occurred_at: "2026-09-01T10:00:01Z",
  actor: { id: "33333333-3333-4333-8333-333333333333", full_name: "A. Inspector" },
  to_profile: { id: "33333333-3333-4333-8333-333333333333", full_name: "A. Inspector" },
});

test("serializeEvidenceDetail assembles evidence, versions with anchors, and custody", () => {
  const detail = serializeEvidenceDetail(
    coreBase(),
    [versionA()],
    [anchorBase()],
    [custodyRow()],
  );

  assert.equal(detail.evidence.evidence_number, "EV-001");
  assert.equal(detail.evidence.creator_name, "A. Inspector");
  assert.equal(detail.versions.length, 1);
  assert.equal(detail.versions[0].anchor?.status, "anchored");
  assert.equal(detail.versions[0].uploader_name, "A. Inspector");
  assert.equal(detail.custody.length, 1);
  assert.equal(detail.custody[0].action, "received");
  assert.equal(detail.custody[0].actor_name, "A. Inspector");
});

test("serializeEvidenceDetail attaches each anchor only to its own version", () => {
  const detail = serializeEvidenceDetail(
    coreBase(),
    [versionA(), { ...versionA(), id: VERSION_UUID_B, version: 2 }],
    [anchorBase()],
    [custodyRow()],
  );

  assert.equal(detail.versions[0].anchor?.document_version_id, VERSION_UUID_A);
  assert.equal(detail.versions[1].anchor, null);
});

test("serializeEvidenceDetail ignores malformed anchor rows rather than echoing them", () => {
  const detail = serializeEvidenceDetail(
    coreBase(),
    [versionA()],
    [{ ...anchorBase(), status: "bogus" }],
    [custodyRow()],
  );
  assert.equal(detail.versions[0].anchor, null);
});

test("serializeEvidenceDetail survives missing creator and custody embeds", () => {
  const detail = serializeEvidenceDetail(
    { ...coreBase(), creator: null },
    [{ ...versionA(), uploader: null }],
    [],
    [{ ...custodyRow(), actor: null, from_profile: null, to_profile: null }],
  );
  assert.equal(detail.evidence.creator_name, null);
  assert.equal(detail.versions[0].uploader_name, null);
  assert.equal(detail.custody[0].actor_name, null);
  assert.equal(detail.custody[0].to_name, null);
});