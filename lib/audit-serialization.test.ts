import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  auditActionLabel,
  auditEntityLabel,
  auditEntityTypeLabel,
  sanitizeAuditMeta,
  serializeAuditEvent,
  verificationAuditOutcome,
} from "./audit-serialization";

const META_MAX = 200;

describe("auditActionLabel", () => {
  it("labels every known dotted action", () => {
    const known: Array<[string, string]> = [
      ["case.created", "Case created"],
      ["case.updated", "Case updated"],
      ["case.status_changed", "Case status changed"],
      ["case.member_added", "Member added"],
      ["case.member_role_changed", "Member role changed"],
      ["case.member_removed", "Member removed"],
      ["evidence.created", "Evidence uploaded"],
      ["evidence.hash_generated", "Fingerprint generated"],
      ["evidence.status_changed", "Evidence status changed"],
      ["evidence.verification_requested", "Verification requested"],
      ["evidence.verification_passed", "Verification passed"],
      ["evidence.verification_failed", "Verification failed"],
      ["evidence.anchor_requested", "Anchor requested"],
      ["evidence.anchor_retry", "Anchor retried"],
      ["evidence.anchored", "Anchor confirmed on chain"],
      ["evidence.anchor_failed", "Anchor failed"],
      ["evidence.anchor_reconciled", "Anchor reconciled"],
      ["evidence.custody_received", "Evidence received into custody"],
      ["evidence.accessed", "Evidence accessed"],
      ["custody.transferred", "Custody transferred"],
      ["custody.returned", "Custody returned"],
      ["custody.verified", "Custody verified"],
      ["custody.released", "Custody released"],
      ["custody.archived", "Custody archived"],
      ["organization.created", "Organization created"],
      ["organization.member_added", "Member added"],
      ["organization.member_role_changed", "Member role changed"],
      ["organization.member_removed", "Member removed"],
    ];
    for (const [action, label] of known) {
      assert.equal(auditActionLabel(action), label);
    }
  });

  it("humanizes an unknown dotted action without crashing", () => {
    assert.equal(auditActionLabel("evidence.something_new"), "Something New");
    assert.equal(auditActionLabel("weird"), "Weird");
    assert.equal(auditActionLabel(""), "");
  });
});

describe("auditEntityTypeLabel", () => {
  it("labels known entity types and falls back verbatim", () => {
    assert.equal(auditEntityTypeLabel("case"), "Case");
    assert.equal(auditEntityTypeLabel("case_member"), "Member");
    assert.equal(auditEntityTypeLabel("evidence"), "Evidence");
    assert.equal(auditEntityTypeLabel("document_version"), "Version");
    assert.equal(auditEntityTypeLabel("blockchain_anchor"), "Blockchain anchor");
    assert.equal(auditEntityTypeLabel("organization"), "Organization");
    assert.equal(auditEntityTypeLabel("organization_member"), "Organization member");
    assert.equal(auditEntityTypeLabel("unexpected_type"), "unexpected_type");
  });
});

describe("auditEntityLabel", () => {
  const base = {
    id: "1",
    action: "case.updated",
    entity_type: "case",
    entity_id: "c1",
    actor_id: null,
    actor_name: null,
    case_id: "c1",
    evidence_id: null,
    created_at: "2026-09-10T10:00:00Z",
    meta: null,
  };

  it("prefers the server-resolved label", () => {
    const row = { ...base, entity_label: "CI-2026-001" };
    assert.equal(auditEntityLabel(row), "CI-2026-001");
  });

  it("falls back to the entity type label for known vocabulary", () => {
    assert.equal(auditEntityLabel({ ...base, entity_type: "case_member", entity_label: null }), "Member");
    assert.equal(auditEntityLabel({ ...base, entity_type: "blockchain_anchor", entity_label: null }), "Blockchain anchor");
  });

  it("returns null for an unknown entity type with no label", () => {
    assert.equal(
      auditEntityLabel({ ...base, entity_type: "mystery", entity_label: null }),
      null,
    );
  });
});

describe("sanitizeAuditMeta", () => {
  it("drops storage_key and any key outside the allow-list", () => {
    const meta = {
      case_number: "CI-2026-001",
      evidence_number: "EV-001",
      title: "CCTV footage",
      sha256: "a".repeat(64),
      storage_key: "c1/e1/v1",
      mime_type: "video/mp4",
      before: { anything: "this is nested" },
      ip_address: "10.0.0.1",
    };
    const items = sanitizeAuditMeta(meta);
    const keys = items.map((i) => i.key);
    assert.deepEqual(keys, ["case_number", "evidence_number", "title", "sha256"]);
    assert.ok(!keys.includes("storage_key"));
    assert.ok(!keys.includes("mime_type"));
    assert.ok(!keys.includes("before"));
    assert.ok(!keys.includes("ip_address"));
  });

  it("renders only flat scalar values and coerces numbers", () => {
    const items = sanitizeAuditMeta({
      chain_id: 11155111,
      block_number: 8123456,
      previous_status: "under_review",
      new_status: null,
    });
    assert.deepEqual(items, [
      { key: "previous_status", label: "Status from", value: "under_review" },
      { key: "chain_id", label: "Chain ID", value: "11155111" },
      { key: "block_number", label: "Block", value: "8123456" },
    ]);
  });

  it("renders the access mode meta with its own label", () => {
    const items = sanitizeAuditMeta({
      file_name: "report.pdf",
      mode: "download",
    });
    assert.deepEqual(items, [
      { key: "file_name", label: "File", value: "report.pdf" },
      { key: "mode", label: "Mode", value: "download" },
    ]);
  });

  it("strips line breaks from messages and truncates over-long values", () => {
    const long = "x".repeat(400);
    const items = sanitizeAuditMeta({
      error_message: "line1\r\nline2\nline3",
      notes: long,
    });
    assert.equal(items[0]!.value, "line1 line2 line3");
    assert.equal(items[1]!.value.length, META_MAX);
  });

  it("returns an empty list for null, empty or non-scalar-only meta", () => {
    assert.deepEqual(sanitizeAuditMeta(null), []);
    assert.deepEqual(sanitizeAuditMeta({}), []);
    assert.deepEqual(sanitizeAuditMeta({ nested: { a: 1 }, list: [1], empty: "" }), []);
  });

  it("renders organization member role meta with its own labels", () => {
    const items = sanitizeAuditMeta({
      old_role_in_org: "investigator",
      new_role_in_org: "admin",
      removed_role_in_org: "member",
      role_in_org: "member",
      name: "Alpha Bureau",
      slug: "alpha-bureau",
    });
    assert.deepEqual(items, [
      { key: "old_role_in_org", label: "Role from", value: "investigator" },
      { key: "new_role_in_org", label: "Role to", value: "admin" },
      { key: "removed_role_in_org", label: "Role removed", value: "member" },
      { key: "role_in_org", label: "Role", value: "member" },
      { key: "name", label: "Name", value: "Alpha Bureau" },
      { key: "slug", label: "Slug", value: "alpha-bureau" },
    ]);
  });
});

describe("verificationAuditOutcome", () => {
  it("maps a verified frame to passed/verified", () => {
    assert.deepEqual(verificationAuditOutcome("verified"), {
      result: "passed",
      verdict: "verified",
    });
  });

  it("maps hash_mismatch and ambiguous frames to failed", () => {
    assert.deepEqual(verificationAuditOutcome("hash_mismatch"), {
      result: "failed",
      verdict: "hash_mismatch",
    });
    assert.deepEqual(verificationAuditOutcome("verification_ambiguous"), {
      result: "failed",
      verdict: "verification_ambiguous",
    });
  });

  it("maps not_anchored and unknown verdicts to no terminal event", () => {
    assert.equal(verificationAuditOutcome("not_anchored"), null);
    assert.equal(verificationAuditOutcome("bogus"), null);
  });
});

describe("serializeAuditEvent", () => {
  it("produces a display-safe event shape", () => {
    const row = {
      id: "a1",
      action: "evidence.status_changed",
      entity_type: "evidence",
      entity_id: "e1",
      actor_id: "u1",
      actor_name: "Harsh Tiwari",
      case_id: "c1",
      evidence_id: "e1",
      entity_label: "CCTV footage",
      created_at: "2026-09-10T10:32:00Z",
      meta: {
        previous_status: "received",
        new_status: "verified",
        storage_key: "c1/e1/v1",
      },
    };
    const item = serializeAuditEvent(row);
    assert.equal(item.action_label, "Evidence status changed");
    assert.equal(item.entity_type_label, "Evidence");
    assert.equal(item.entity_label, "CCTV footage");
    assert.equal(item.actor_name, "Harsh Tiwari");
    assert.deepEqual(item.meta, [
      { key: "previous_status", label: "Status from", value: "received" },
      { key: "new_status", label: "Status to", value: "verified" },
    ]);
  });

  it("serializes an organization member role-change event and keeps storage_key out", () => {
    const row = {
      id: "a2",
      action: "organization.member_role_changed",
      entity_type: "organization_member",
      entity_id: "om1",
      actor_id: "u1",
      actor_name: "Harsh Tiwari",
      case_id: null,
      evidence_id: null,
      entity_label: "Aarav Sharma",
      created_at: "2026-09-12T09:00:00Z",
      meta: {
        old_role_in_org: "member",
        new_role_in_org: "admin",
        storage_key: "org/secret/location",
        raw: { nested: true },
      },
    };
    const item = serializeAuditEvent(row);
    assert.equal(item.action, "organization.member_role_changed");
    assert.equal(item.action_label, "Member role changed");
    assert.equal(item.entity_type_label, "Organization member");
    assert.equal(item.entity_label, "Aarav Sharma");
    assert.equal(item.actor_name, "Harsh Tiwari");
    assert.deepEqual(item.meta, [
      { key: "old_role_in_org", label: "Role from", value: "member" },
      { key: "new_role_in_org", label: "Role to", value: "admin" },
    ]);
  });
});