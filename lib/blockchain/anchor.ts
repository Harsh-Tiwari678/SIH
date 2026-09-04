// Server-only blockchain service for anchoring evidence integrity hashes on
// the deployed EvidenceAnchor contract (Ethereum Sepolia).
//
// SECURITY: This module MUST only ever be imported from server-side code. The
// write path reads a signer private key from process.env and transmits a
// transaction, so it must never be bundled into browser/client code. The read
// path never touches the private key.

import {
  Contract,
  JsonRpcProvider,
  Wallet,
  type ContractTransactionReceipt,
  type Provider,
} from "ethers";
import {
  uuidToBytes32,
  sha256ToBytes32,
  type Bytes32Hex,
} from "./encoding";
import {
  BlockchainAnchorError,
  type AnchorErrorCategory,
} from "./errors";

// ---- Configuration ----------------------------------------------------------

export const SEPOLIA_CHAIN_ID = 11155111;

const CONTRACT_ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/;
const TX_HASH_PATTERN = /^0x[0-9a-fA-F]{64}$/;

interface ReadConfig {
  rpcUrl: string;
  contractAddress: string;
}

interface WriteConfig extends ReadConfig {
  privateKey: string;
}

// Validates that read-only anchoring is possible and returns the concrete
// values. Requires RP C URL + contract address; does NOT require the signer.
function requireReadConfig(): ReadConfig {
  const rpcUrl = process.env.SEPOLIA_RPC_URL;
  const contractAddress = process.env.EVIDENCE_ANCHOR_CONTRACT_ADDRESS;

  if (!rpcUrl) {
    throw new BlockchainAnchorError(
      "configuration_error",
      "SEPOLIA_RPC_URL is not set",
    );
  }
  if (!contractAddress || !CONTRACT_ADDRESS_PATTERN.test(contractAddress)) {
    throw new BlockchainAnchorError(
      "configuration_error",
      "EVIDENCE_ANCHOR_CONTRACT_ADDRESS is not set or is invalid",
    );
  }
  return { rpcUrl, contractAddress };
}

// Validates write capability: additionally requires the signer private key.
function requireWriteConfig(): WriteConfig {
  const read = requireReadConfig();
  const privateKey = process.env.EVIDENCE_ANCHOR_SIGNER_PRIVATE_KEY;
  if (!privateKey) {
    throw new BlockchainAnchorError(
      "configuration_error",
      "EVIDENCE_ANCHOR_SIGNER_PRIVATE_KEY is not set",
    );
  }
  return { ...read, privateKey };
}

// Only the functions the service needs. Kept trimmed so the module has no
// dependency on Hardhat artifacts or the blockchain workspace.
const EVIDENCE_ANCHOR_ABI = [
  "function anchor(bytes32 evidenceIdHash, bytes32 versionIdHash, bytes32 evidenceSha256)",
  "function getAnchor(bytes32 evidenceIdHash, bytes32 versionIdHash) view returns (bytes32 evidenceSha256, uint256 anchoredAt, uint256 blockNumber, bool exists)",
  "function verify(bytes32 evidenceIdHash, bytes32 versionIdHash, bytes32 expectedHash) view returns (bool)",
] as const;

// ---- Types ------------------------------------------------------------------

export interface AnchorRequest {
  evidenceId: string;
  documentVersionId: string;
  sha256: string;
}

export interface AnchorConfirmation {
  txHash: string;
  blockNumber: bigint;
  anchoredAt: bigint;
  evidenceIdHash: Bytes32Hex;
  versionIdHash: Bytes32Hex;
  evidenceSha256: Bytes32Hex;
}

export interface OnChainAnchor {
  exists: boolean;
  storedSha256: Bytes32Hex;
  anchoredAt: bigint;
  blockNumber: bigint;
  verified: boolean;
}

// ---- Helpers ----------------------------------------------------------------

/**
 * Produces the bytes32 hashes the service sends/reads (single implementation).
 * UUID -> bytes32: remove hyphens, lowercase, left-pad to 64 hex, prepend 0x.
 * SHA-256 -> bytes32: the exact 64 lowercase hex chars prefixed with 0x.
 * Throws EncodingError on invalid input.
 */
export function deriveAnchorHashes(request: AnchorRequest): {
  evidenceIdHash: Bytes32Hex;
  versionIdHash: Bytes32Hex;
  evidenceSha256: Bytes32Hex;
} {
  return {
    evidenceIdHash: uuidToBytes32(request.evidenceId),
    versionIdHash: uuidToBytes32(request.documentVersionId),
    evidenceSha256: sha256ToBytes32(request.sha256),
  };
}

async function readContract(
  config: ReadConfig,
): Promise<{ contract: Contract; provider: JsonRpcProvider }> {
  const provider = new JsonRpcProvider(config.rpcUrl, SEPOLIA_CHAIN_ID, {
    staticNetwork: true,
  });
  const contract = new Contract(
    config.contractAddress,
    EVIDENCE_ANCHOR_ABI,
    provider,
  );
  return { contract, provider };
}

async function writeContract(config: WriteConfig): Promise<{
  contract: Contract;
  provider: JsonRpcProvider;
}> {
  const provider = new JsonRpcProvider(config.rpcUrl, SEPOLIA_CHAIN_ID, {
    staticNetwork: true,
  });
  const wallet = new Wallet(config.privateKey, provider);
  const contract = new Contract(
    config.contractAddress,
    EVIDENCE_ANCHOR_ABI,
    wallet,
  );
  return { contract, provider };
}

async function assertSepolia(provider: Provider): Promise<void> {
  const network = await provider.getNetwork();
  if (network.chainId !== BigInt(SEPOLIA_CHAIN_ID)) {
    throw new BlockchainAnchorError(
      "configuration_error",
      `Connected chain ${network.chainId} is not the configured Sepolia chain ${SEPOLIA_CHAIN_ID}`,
    );
  }
}

// ---- Logging ----------------------------------------------------------------

// Emits only explicitly-allowlisted fields. Never pass private keys, RPC URLs,
// environment values, or raw provider errors into this.
function logSafe(level: "info" | "warn" | "error", event: string, fields: {
  contractAddress?: string;
  txHash?: string;
  blockNumber?: number | bigint;
  category?: AnchorErrorCategory;
}) {
  const msg = `[blockchain-anchor] ${JSON.stringify({ event, ...fields })}`;
  if (level === "error") console.error(msg);
  else if (level === "warn") console.warn(msg);
  else console.info(msg);
}

// ---- Error classification ---------------------------------------------------

// ethers v6 attaches a machine-readable `code` to most errors. We prefer that
// and only fall back to message matching.
function errorCode(raw: unknown): string | undefined {
  if (
    raw &&
    typeof raw === "object" &&
    "code" in raw &&
    typeof (raw as { code?: unknown }).code === "string"
  ) {
    return (raw as { code: string }).code;
  }
  return undefined;
}

function errorMessage(raw: unknown): string {
  if (raw instanceof Error) return `${raw.name}: ${raw.message}`;
  return String(raw);
}

// Maps a raw provider/transaction/verification error into one of the six safe
// public categories. raw is only inspected locally; the returned error carries
// only the safe category (+ generic message), never provider internals.
function classifyError(raw: unknown): BlockchainAnchorError {
  const code = errorCode(raw);
  let message = "";

  if (code) {
    switch (code) {
      case "CALL_EXCEPTION":
      case "UNPREDICTABLE_GAS_LIMIT":
        message = "reverted/execution";
        break;
      case "TIMEOUT":
      case "NONCE_EXPIRED":
      case "REPLACEMENT_UNDERPRICED":
        message = "confirmation";
        break;
      case "NETWORK_ERROR":
      case "SERVER_ERROR":
      case "ECONNREFUSED":
      case "ENOTFOUND":
        message = "network";
        break;
      case "INVALID_ARGUMENT":
      case "BAD_DATA":
        message = "configuration";
        break;
      default:
        message = errorMessage(raw).toLowerCase();
    }
  } else {
    message = errorMessage(raw).toLowerCase();
  }

  if (message.includes("alreadyanchored")) {
    return new BlockchainAnchorError("already_anchored");
  }
  if (
    message.includes("revert") ||
    message.includes("call_exception") ||
    message.includes("cannot estimate gas") ||
    message.includes("execution reverted")
  ) {
    return new BlockchainAnchorError("transaction_reverted");
  }
  if (
    message.includes("timeout") ||
    message.includes("nonce") ||
    message.includes("replacement") ||
    message.includes("confirmation")
  ) {
    return new BlockchainAnchorError("confirmation_error");
  }
  if (
    message.includes("network") ||
    message.includes("econnrefused") ||
    message.includes("enotfound") ||
    message.includes("fetch failed") ||
    message.includes("server error") ||
    message.includes("code: 'server_error'")
  ) {
    return new BlockchainAnchorError("network_error");
  }
  if (
    message.includes("invalid argument") ||
    message.includes("bad data") ||
    message.includes("invalid address")
  ) {
    return new BlockchainAnchorError("configuration_error");
  }

  // Unknown failures on the read/verify path map to verification_error.
  return new BlockchainAnchorError("verification_error");
}

// ---- Public API -------------------------------------------------------------

/**
 * Anchor an evidence version's SHA-256 digest on the EvidenceAnchor contract.
 * Requires the signer private key (write config). Returns authoritative on-chain
 * confirmation data; anchoredAt is the confirmed block's timestamp, never
 * Date.now(). Retry/reconciliation is left to the caller.
 *
 * @throws BlockchainAnchorError
 */
export async function anchorEvidence(
  request: AnchorRequest,
): Promise<AnchorConfirmation> {
  const config = requireWriteConfig();
  const hashes = deriveAnchorHashes(request);
  const { contract, provider } = await writeContract(config);

  await assertSepolia(provider);

  let receipt: ContractTransactionReceipt | null;
  try {
    const tx = await contract.anchor(
      hashes.evidenceIdHash,
      hashes.versionIdHash,
      hashes.evidenceSha256,
    );
    logSafe("info", "anchor_tx_broadcast", {
      contractAddress: config.contractAddress,
      txHash: tx.hash,
    });
    receipt = await tx.wait();
  } catch (raw) {
    throw classifyError(raw);
  }

  if (!receipt || receipt.status !== 1) {
    throw new BlockchainAnchorError("confirmation_error");
  }
  if (!receipt.hash || !TX_HASH_PATTERN.test(receipt.hash)) {
    throw new BlockchainAnchorError("confirmation_error");
  }

  // Authoritative blockchain timestamp from the confirmed block. Never now().
  let block;
  try {
    block = await provider.getBlock(receipt.blockNumber);
  } catch (raw) {
    throw classifyError(raw);
  }
  if (!block) {
    throw new BlockchainAnchorError("confirmation_error");
  }

  logSafe("info", "anchor_tx_confirmed", {
    contractAddress: config.contractAddress,
    txHash: receipt.hash,
    blockNumber: receipt.blockNumber,
  });

  return {
    txHash: receipt.hash,
    blockNumber: BigInt(receipt.blockNumber),
    anchoredAt: BigInt(block.timestamp),
    evidenceIdHash: hashes.evidenceIdHash,
    versionIdHash: hashes.versionIdHash,
    evidenceSha256: hashes.evidenceSha256,
  };
}

/**
 * Read and verify the on-chain anchor for an evidence version. Read-only: does
 * NOT require the signer private key and instantiates the contract against a
 * plain JsonRpcProvider. Calls both getAnchor() and verify().
 *
 * @throws BlockchainAnchorError
 */
export async function getOnChainAnchor(
  request: AnchorRequest,
): Promise<OnChainAnchor> {
  const config = requireReadConfig();
  const hashes = deriveAnchorHashes(request);
  const { contract, provider } = await readContract(config);

  await assertSepolia(provider);

  let result: OnChainAnchor;
  try {
    const [evidenceSha256, anchoredAt, blockNumber, exists] =
      await contract.getAnchor(
        hashes.evidenceIdHash,
        hashes.versionIdHash,
      );
    const verified = await contract.verify(
      hashes.evidenceIdHash,
      hashes.versionIdHash,
      hashes.evidenceSha256,
    );

    if (!exists) {
      result = {
        exists: false,
        storedSha256:
          "0x0000000000000000000000000000000000000000000000000000000000000000",
        anchoredAt: 0n,
        blockNumber: 0n,
        verified: false,
      };
    } else {
      result = {
        exists,
        storedSha256: evidenceSha256 as Bytes32Hex,
        anchoredAt: anchoredAt as bigint,
        blockNumber: blockNumber as bigint,
        verified,
      };
    }
  } catch (raw) {
    throw classifyError(raw);
  }

  return result;
}
