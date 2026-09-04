// Safe, application-level classification of blockchain errors. Never wrap raw
// provider errors into these (they may contain RPC URLs, payloads, or other
// sensitive details). The service maps low-level failures into these bounded
// categories before they escape.

export const ERROR_CATEGORIES = [
  "configuration_error",
  "network_error",
  "transaction_reverted",
  "already_anchored",
  "confirmation_error",
  "verification_error",
] as const;

export type AnchorErrorCategory = (typeof ERROR_CATEGORIES)[number];

export const ERROR_CATEGORY_MESSAGES: Record<AnchorErrorCategory, string> = {
  configuration_error: "Blockchain anchoring is not correctly configured",
  network_error: "Unable to reach the blockchain network",
  transaction_reverted: "The anchor transaction was reverted on-chain",
  already_anchored: "This evidence version is already anchored on-chain",
  confirmation_error: "The anchor transaction was broadcast but could not be confirmed",
  verification_error: "Could not verify the on-chain anchor",
};

export class BlockchainAnchorError extends Error {
  readonly category: AnchorErrorCategory;

  constructor(category: AnchorErrorCategory, message?: string) {
    super(message ?? ERROR_CATEGORY_MESSAGES[category]);
    this.name = "BlockchainAnchorError";
    this.category = category;
  }
}
