// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @title EvidenceAnchor — append-only integrity anchoring for digital evidence
/// @author SIH 26190 Secure Evidence
/// @notice Stores a SHA-256 fingerprint of each evidence version on-chain.
///
/// Why only the hash?
///   Evidence files can be large (PDFs, video, audio). Putting them on-chain
///   would be prohibitively expensive and would expose private data to every
///   full node. A SHA-256 digest is 32 bytes — cheap to store and sufficient
///   for independent verification: anyone can recompute the hash of a file and
///   compare it to the anchored value.
///
/// Why is evidence not stored?
///   The actual files live in private Supabase Storage, protected by
///   application-level RBAC and RLS. The blockchain serves solely as a
///   tamper-evident timestamped ledger of "this hash existed at this time."
///
/// Why are anchors immutable?
///   Once anchored, a record proves that a particular file hash was committed
///   at a particular block. If anchors could bemodified, the integrity guarantee
///   would be meaningless. There is deliberately no update or delete function.
///
/// How verification works:
///   1. Call `getAnchor(evidenceIdHash, versionIdHash)` to retrieve the
///      on-chain record.
///   2. Recompute SHA-256 of the local file.
///   3. Call `verify(evidenceIdHash, versionIdHash, recomputedHash)` — it
///      returns true if and only if the on-chain record exists AND the hash
///      matches.
///
/// UUID → bytes32 encoding:
///   The application identifies evidence and versions by UUID strings
///   (e.g. "a1b2c3d4-e5f6-7890-abcd-ef1234567890"). UUIDs are 16 bytes.
///   We left-pad them with 16 zero bytes to produce a deterministic bytes32:
///   `bytes32(uint256(uint128(bytes16(uuid))))` — i.e. the 16-byte UUID
///   occupies the right-most 16 bytes of the bytes32 value. This is
///   deterministic, lossless, and reversible off-chain.
contract EvidenceAnchor is Ownable {
    // ── Storage ──────────────────────────────────────────────────────────

    struct Anchor {
        bytes32 evidenceSha256;
        uint256 anchoredAt;
        uint256 blockNumber;
    }

    /// @dev evidenceIdHash → versionIdHash → anchor data.
    ///      A non-default anchor.anchoredAt (i.e. > 0) means the slot is filled.
    mapping(bytes32 => mapping(bytes32 => Anchor)) private _anchors;

    // ── Events ───────────────────────────────────────────────────────────

    /// @notice Emitted when a new evidence version is anchored.
    /// @param evidenceIdHash  bytes32-encoded evidence UUID (see encoding above).
    /// @param versionIdHash   bytes32-encoded document version UUID.
    /// @param evidenceSha256  SHA-256 digest of the evidence file bytes.
    /// @param anchoredAt      Block timestamp of anchoring.
    /// @param blockNumber     Block number at anchoring.
    event Anchored(
        bytes32 indexed evidenceIdHash,
        bytes32 indexed versionIdHash,
        bytes32 evidenceSha256,
        uint256 anchoredAt,
        uint256 blockNumber
    );

    // ── Errors ───────────────────────────────────────────────────────────

    error ZeroEvidenceIdHash();
    error ZeroVersionIdHash();
    error ZeroSha256();
    error AlreadyAnchored();

    // ── Constructor ──────────────────────────────────────────────────────

    /// @param initialOwner The address that will own the contract and be the
    ///        only account permitted to anchor evidence.
    constructor(address initialOwner) Ownable(initialOwner) {}

    // ── Core: append-only anchoring ──────────────────────────────────────

    /// @notice Anchor an evidence version. Can only be called by the owner.
    /// @dev The three hashes must be non-zero. The evidence/version combination
    ///      must not have been anchored before — re-anchoring reverts.
    /// @param evidenceIdHash  bytes32-encoded evidence UUID.
    /// @param versionIdHash   bytes32-encoded document version UUID.
    /// @param evidenceSha256  SHA-256 of the evidence file (64 hex chars, stored as bytes32).
    function anchor(
        bytes32 evidenceIdHash,
        bytes32 versionIdHash,
        bytes32 evidenceSha256
    ) external onlyOwner {
        if (evidenceIdHash == bytes32(0)) revert ZeroEvidenceIdHash();
        if (versionIdHash == bytes32(0)) revert ZeroVersionIdHash();
        if (evidenceSha256 == bytes32(0)) revert ZeroSha256();

        Anchor storage slot = _anchors[evidenceIdHash][versionIdHash];
        if (slot.anchoredAt != 0) revert AlreadyAnchored();

        slot.evidenceSha256 = evidenceSha256;
        slot.anchoredAt = block.timestamp;
        slot.blockNumber = block.number;

        emit Anchored(
            evidenceIdHash,
            versionIdHash,
            evidenceSha256,
            block.timestamp,
            block.number
        );
    }

    // ── Read: get & verify ───────────────────────────────────────────────

    /// @notice Retrieve the anchor for a given evidence/version pair.
    /// @return evidenceSha256  The anchored SHA-256 hash.
    /// @return anchoredAt      Timestamp when the anchor was created.
    /// @return blockNumber     Block number when the anchor was created.
    /// @return exists          True if an anchor has been recorded.
    function getAnchor(
        bytes32 evidenceIdHash,
        bytes32 versionIdHash
    )
        external
        view
        returns (
            bytes32 evidenceSha256,
            uint256 anchoredAt,
            uint256 blockNumber,
            bool exists
        )
    {
        Anchor storage slot = _anchors[evidenceIdHash][versionIdHash];
        return (
            slot.evidenceSha256,
            slot.anchoredAt,
            slot.blockNumber,
            slot.anchoredAt != 0
        );
    }

    /// @notice Verify that a supplied SHA-256 hash matches the anchored hash.
    /// @dev Returns false (not revert) when the anchor does not exist or the
    ///      hash differs — callers can distinguish the two cases via getAnchor.
    /// @param evidenceIdHash  bytes32-encoded evidence UUID.
    /// @param versionIdHash   bytes32-encoded document version UUID.
    /// @param expectedHash    The SHA-256 hash to compare against.
    /// @return matches        True if the anchor exists and hashes match.
    function verify(
        bytes32 evidenceIdHash,
        bytes32 versionIdHash,
        bytes32 expectedHash
    ) external view returns (bool matches) {
        Anchor storage slot = _anchors[evidenceIdHash][versionIdHash];
        return slot.anchoredAt != 0 && slot.evidenceSha256 == expectedHash;
    }
}
