import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  buildAccessResponse,
  evidencePreviewKind,
  evidencePreviewKindLabel,
  isEvidenceAccessMode,
  signedUrlExpiry,
  SIGNED_URL_LIFETIME_SECONDS,
} from "./evidence-access";

describe("isEvidenceAccessMode", () => {
  it("accepts exactly the fixed vocabulary", () => {
    assert.equal(isEvidenceAccessMode("preview"), true);
    assert.equal(isEvidenceAccessMode("download"), true);
  });

  it("rejects everything else", () => {
    assert.equal(isEvidenceAccessMode("open"), false);
    assert.equal(isEvidenceAccessMode(""), false);
    assert.equal(isEvidenceAccessMode(null), false);
    assert.equal(isEvidenceAccessMode(undefined), false);
    assert.equal(isEvidenceAccessMode(1), false);
  });
});

describe("signed URL lifetime", () => {
  it("is capped at a short ceiling", () => {
    assert.ok(SIGNED_URL_LIFETIME_SECONDS > 0);
    assert.ok(SIGNED_URL_LIFETIME_SECONDS <= 120);
  });

  it("expiry is a valid ISO timestamp at lifetime + now", () => {
    const now = Date.parse("2026-09-10T12:00:00Z");
    const expiry = signedUrlExpiry(now);
    assert.equal(Date.parse(expiry), now + SIGNED_URL_LIFETIME_SECONDS * 1000);
  });
});

describe("evidencePreviewKind", () => {
  it("maps every permitted upload MIME type to a renderer", () => {
    assert.equal(evidencePreviewKind("application/pdf"), "pdf");
    assert.equal(evidencePreviewKind("image/png"), "image");
    assert.equal(evidencePreviewKind("image/jpeg"), "image");
    assert.equal(evidencePreviewKind("video/mp4"), "video");
    assert.equal(evidencePreviewKind("audio/mpeg"), "audio");
    assert.equal(evidencePreviewKind("text/plain"), "text");
  });

  it("is case-insensitive", () => {
    assert.equal(evidencePreviewKind("Application/PDF"), "pdf");
    assert.equal(evidencePreviewKind("TEXT/PLAIN"), "text");
  });

  it("is download-only for anything else", () => {
    assert.equal(evidencePreviewKind("image/gif"), "none");
    assert.equal(evidencePreviewKind("application/octet-stream"), "none");
    assert.equal(evidencePreviewKind(""), "none");
    assert.equal(evidencePreviewKind(undefined as unknown as string), "none");
  });

  it("labels the kinds", () => {
    assert.equal(evidencePreviewKindLabel("image"), "Image");
    assert.equal(evidencePreviewKindLabel("pdf"), "PDF document");
    assert.equal(evidencePreviewKindLabel("text"), "Plain text");
    assert.equal(evidencePreviewKindLabel("video"), "Video");
    assert.equal(evidencePreviewKindLabel("audio"), "Audio");
    assert.equal(evidencePreviewKindLabel("none"), "");
  });
});

describe("buildAccessResponse", () => {
  const source = { file_name: "report.pdf", mime_type: "application/pdf", version: 2 };
  const expiry = "2026-09-10T12:02:00.000Z";

  it("builds the minimal safe surface", () => {
    const res = buildAccessResponse(source, "download", "https://x.example/object/sign/evidence-files/a/b/c?token=abc&expires=1", expiry);
    assert.deepEqual(res, {
      url: "https://x.example/object/sign/evidence-files/a/b/c?token=abc&expires=1",
      expires_at: expiry,
      mode: "download",
      file_name: "report.pdf",
      mime_type: "application/pdf",
      version: 2,
    });
  });

  it("rejects a non-http(s) url (programming error, never served)", () => {
    assert.equal(buildAccessResponse(source, "preview", "file:///etc/passwd", expiry), null);
    assert.equal(buildAccessResponse(source, "preview", "", expiry), null);
  });

  it("rejects an invalid expiry", () => {
    assert.equal(buildAccessResponse(source, "preview", "https://x.example/u", ""), null);
    assert.equal(buildAccessResponse(source, "preview", "https://x.example/u", "not-a-date"), null);
  });
});