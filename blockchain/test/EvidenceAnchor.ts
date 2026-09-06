import { expect } from "chai";
import { network } from "hardhat";
import type { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/types";
import { FunctionFragment } from "ethers";
import type { EventLog, Log } from "ethers";
import type { EvidenceAnchor } from "../types/ethers-contracts/EvidenceAnchor.js";

const { ethers } = await network.create();

// ── Helpers ──────────────────────────────────────────────────────────────

/**
 * Convert a UUID string to the deterministic bytes32 encoding used by
 * EvidenceAnchor.  The contract left-pads the 16-byte UUID with 16 zero
 * bytes, so the UUID occupies the right-most 16 bytes of the bytes32 value.
 *
 * Example: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
 *   → 0x000000000000000000000000a1b2c3d4e5f67890abcdef1234567890
 */
function uuidToBytes32(uuid: string): string {
  const hex = uuid.replace(/-/g, "");
  if (hex.length !== 32)
    throw new Error(`Invalid UUID hex length: ${hex.length}`);
  return "0x" + hex.padStart(64, "0");
}

/**
 * Encode a 64-character lowercase hex SHA-256 string into bytes32.
 */
function sha256ToBytes32(hex64: string): string {
  const clean = hex64.startsWith("0x") ? hex64.slice(2) : hex64;
  if (clean.length !== 64 || !/^[0-9a-f]{64}$/.test(clean)) {
    throw new Error(`Invalid SHA-256 hex: ${hex64}`);
  }
  return "0x" + clean;
}

// ── Fixed test data ──────────────────────────────────────────────────────

const EVIDENCE_UUID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const VERSION_UUID = "11223344-5566-7788-99aa-bbccddeeff00";
const SHA256_HEX =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

const EVIDENCE_HASH = uuidToBytes32(EVIDENCE_UUID);
const VERSION_HASH = uuidToBytes32(VERSION_UUID);
const FILE_HASH = sha256ToBytes32(SHA256_HEX);

// Second evidence/version pair for cross-check tests.
const EVIDENCE_UUID_B = "beefbeef-beef-beefbeef-beefbeefbeef";
const VERSION_UUID_B = "deadbeef-dead-deadbeef-deadbeefdead";
const EVIDENCE_HASH_B = uuidToBytes32(EVIDENCE_UUID_B);
const VERSION_HASH_B = uuidToBytes32(VERSION_UUID_B);

// ── Test suite ───────────────────────────────────────────────────────────

describe("EvidenceAnchor", function () {
  let owner: HardhatEthersSigner;
  let stranger: HardhatEthersSigner;
  let newOwner: HardhatEthersSigner;
  let anchor: EvidenceAnchor;

  beforeEach(async function () {
    [owner, stranger, newOwner] = await ethers.getSigners();
    anchor = (await ethers.deployContract("EvidenceAnchor", [
      owner.address,
    ])) as unknown as EvidenceAnchor;
  });

  // ── 1. Successful anchor ────────────────────────────────────────────

  describe("anchoring", function () {
    it("should anchor a valid evidence/version pair", async function () {
      const tx = await anchor
        .connect(owner)
        .anchor(EVIDENCE_HASH, VERSION_HASH, FILE_HASH);
      const receipt = await tx.wait();
      expect(receipt!.status).to.equal(1);
    });

    // ── 2. Correct stored values ──────────────────────────────────────

    it("should store correct values after anchoring", async function () {
      await anchor
        .connect(owner)
        .anchor(EVIDENCE_HASH, VERSION_HASH, FILE_HASH);

      const [hash, timestamp, blockNum, exists] = await anchor.getAnchor(
        EVIDENCE_HASH,
        VERSION_HASH,
      );

      expect(exists).to.be.true;
      expect(hash).to.equal(FILE_HASH);
      expect(timestamp).to.be.gt(0n);
      expect(blockNum).to.be.gt(0n);
    });

    // ── 3. Event emission ─────────────────────────────────────────────

    it("should emit Anchored event with correct fields", async function () {
      const tx = await anchor
        .connect(owner)
        .anchor(EVIDENCE_HASH, VERSION_HASH, FILE_HASH);
      const receipt = await tx.wait();

      // Find the Anchored event by name (logs are EventLog | Log; narrow to EventLog)
      const isEventLog = (l: EventLog | Log): l is EventLog => "args" in l;
      const anchoredEvent = receipt!.logs.find(isEventLog);
      expect(anchoredEvent).to.not.be.undefined;

      // Verify the indexed and non-indexed args
      const args = (anchoredEvent as EventLog).args;
      expect(args[0]).to.equal(EVIDENCE_HASH);
      expect(args[1]).to.equal(VERSION_HASH);
      expect(args[2]).to.equal(FILE_HASH);
      expect(args[3]).to.be.gt(0n); // anchoredAt
      expect(args[4]).to.be.gt(0n); // blockNumber
    });
  });

  // ── 4. Unauthorized anchor rejection ────────────────────────────────

  describe("access control", function () {
    it("should revert when a non-owner tries to anchor", async function () {
      await expect(
        anchor
          .connect(stranger)
          .anchor(EVIDENCE_HASH, VERSION_HASH, FILE_HASH),
      ).to.be.revertedWithCustomError(anchor, "OwnableUnauthorizedAccount");
    });
  });

  // ── 5. Duplicate anchor rejection ───────────────────────────────────

  describe("uniqueness", function () {
    it("should revert when anchoring the same evidence/version twice", async function () {
      await anchor
        .connect(owner)
        .anchor(EVIDENCE_HASH, VERSION_HASH, FILE_HASH);

      await expect(
        anchor.connect(owner).anchor(EVIDENCE_HASH, VERSION_HASH, FILE_HASH),
      ).to.be.revertedWithCustomError(anchor, "AlreadyAnchored");
    });

    it("should allow anchoring the same evidence with a different version", async function () {
      await anchor
        .connect(owner)
        .anchor(EVIDENCE_HASH, VERSION_HASH, FILE_HASH);

      const otherVersion = uuidToBytes32(
        "22222222-2222-2222-2222-222222222222",
      );
      const tx = await anchor
        .connect(owner)
        .anchor(EVIDENCE_HASH, otherVersion, FILE_HASH);
      const receipt = await tx.wait();
      expect(receipt!.status).to.equal(1);
    });
  });

  // ── 6-8. Zero/empty identifier rejection ────────────────────────────

  describe("input validation", function () {
    it("should revert on zero evidence ID hash", async function () {
      await expect(
        anchor
          .connect(owner)
          .anchor(ethers.ZeroHash, VERSION_HASH, FILE_HASH),
      ).to.be.revertedWithCustomError(anchor, "ZeroEvidenceIdHash");
    });

    it("should revert on zero version ID hash", async function () {
      await expect(
        anchor
          .connect(owner)
          .anchor(EVIDENCE_HASH, ethers.ZeroHash, FILE_HASH),
      ).to.be.revertedWithCustomError(anchor, "ZeroVersionIdHash");
    });

    it("should revert on zero SHA-256 hash", async function () {
      await expect(
        anchor
          .connect(owner)
          .anchor(EVIDENCE_HASH, VERSION_HASH, ethers.ZeroHash),
      ).to.be.revertedWithCustomError(anchor, "ZeroSha256");
    });
  });

  // ── 9-10. Verification ─────────────────────────────────────────────

  describe("verify", function () {
    beforeEach(async function () {
      await anchor
        .connect(owner)
        .anchor(EVIDENCE_HASH, VERSION_HASH, FILE_HASH);
    });

    it("should return true for a matching hash", async function () {
      expect(
        await anchor.verify(EVIDENCE_HASH, VERSION_HASH, FILE_HASH),
      ).to.be.true;
    });

    it("should return false for a different hash", async function () {
      const wrongHash = sha256ToBytes32(
        "0000000000000000000000000000000000000000000000000000000000000001",
      );
      expect(
        await anchor.verify(EVIDENCE_HASH, VERSION_HASH, wrongHash),
      ).to.be.false;
    });

    it("should return false for a non-existent evidence/version pair", async function () {
      expect(
        await anchor.verify(EVIDENCE_HASH_B, VERSION_HASH_B, FILE_HASH),
      ).to.be.false;
    });

    it("should return false when only the version ID differs", async function () {
      expect(
        await anchor.verify(EVIDENCE_HASH, VERSION_HASH_B, FILE_HASH),
      ).to.be.false;
    });
  });

  // ── 11. Immutability ───────────────────────────────────────────────

  describe("immutability", function () {
    it("should not expose any function to modify an anchor", async function () {
      // Verify the ABI contains exactly the expected functions — no
      // setAnchor, updateAnchor, or deleteAnchor exists.
      const abi = anchor.interface;
      const fns = abi.fragments
        .filter(FunctionFragment.isFunction)
        .map((f) => f.name)
        .sort();

      expect(fns).to.deep.equal([
        "anchor",
        "getAnchor",
        "owner",
        "renounceOwnership",
        "transferOwnership",
        "verify",
      ]);
    });

    it("should return the same values on repeated getAnchor calls", async function () {
      await anchor
        .connect(owner)
        .anchor(EVIDENCE_HASH, VERSION_HASH, FILE_HASH);

      const [h1, t1, b1, e1] = await anchor.getAnchor(
        EVIDENCE_HASH,
        VERSION_HASH,
      );
      const [h2, t2, b2, e2] = await anchor.getAnchor(
        EVIDENCE_HASH,
        VERSION_HASH,
      );

      expect(h1).to.equal(h2);
      expect(t1).to.equal(t2);
      expect(b1).to.equal(b2);
      expect(e1).to.equal(e2);
    });
  });

  // ── 12-14. Ownership transfer ──────────────────────────────────────

  describe("ownership", function () {
    it("should transfer ownership to a new address", async function () {
      await anchor.connect(owner).transferOwnership(newOwner.address);
      expect(await anchor.owner()).to.equal(newOwner.address);
    });

    it("should revert anchoring from old owner after transfer", async function () {
      await anchor.connect(owner).transferOwnership(newOwner.address);

      await expect(
        anchor.connect(owner).anchor(EVIDENCE_HASH, VERSION_HASH, FILE_HASH),
      ).to.be.revertedWithCustomError(anchor, "OwnableUnauthorizedAccount");
    });

    it("should allow anchoring from new owner after transfer", async function () {
      await anchor.connect(owner).transferOwnership(newOwner.address);

      const tx = await anchor
        .connect(newOwner)
        .anchor(EVIDENCE_HASH, VERSION_HASH, FILE_HASH);
      const receipt = await tx.wait();
      expect(receipt!.status).to.equal(1);

      const [, , , exists] = await anchor.getAnchor(
        EVIDENCE_HASH,
        VERSION_HASH,
      );
      expect(exists).to.be.true;
    });

    it("should allow renouncing ownership", async function () {
      await anchor.connect(owner).renounceOwnership();
      expect(await anchor.owner()).to.equal(ethers.ZeroAddress);
    });

    it("should prevent anchoring after ownership is renounced", async function () {
      await anchor.connect(owner).renounceOwnership();

      await expect(
        anchor.connect(owner).anchor(EVIDENCE_HASH, VERSION_HASH, FILE_HASH),
      ).to.be.revertedWithCustomError(anchor, "OwnableUnauthorizedAccount");
    });
  });

  // ── getAnchor for non-existent entries ──────────────────────────────

  describe("getAnchor", function () {
    it("should return exists=false for a non-existent entry", async function () {
      const [hash, timestamp, blockNum, exists] = await anchor.getAnchor(
        EVIDENCE_HASH,
        VERSION_HASH,
      );

      expect(exists).to.be.false;
      expect(hash).to.equal(ethers.ZeroHash);
      expect(timestamp).to.equal(0n);
      expect(blockNum).to.equal(0n);
    });
  });
});
