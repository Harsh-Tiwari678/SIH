// Slug derivation used by the new-organization dialog. The rules mirror the
// create_organization RPC exactly (20260915000000): lowercase letters and
// digits, single hyphens between segments, at most 63 characters. This is a
// UX convenience only — the SECURITY DEFINER RPC re-validates the slug and is
// the authority on uniqueness and format.

export const SLUG_MAX_LENGTH = 63

// Lowercase, non-alphanumeric runs become single hyphens, then leading and
// trailing hyphens are stripped. Returns the empty string when nothing
// slug-safe remains (so the caller can surface a "required" error).
export function deriveSlug(name: string): string {
  const normalized = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, SLUG_MAX_LENGTH)
    .replace(/-+$/g, "")
  return normalized
}

// True when the slug would be accepted by the RPC: `^[a-z0-9]+(-[a-z0-9]+)*$`
// and at most 63 characters.
export function isValidSlug(slug: string): boolean {
  if (slug.length === 0 || slug.length > SLUG_MAX_LENGTH) return false
  return /^[a-z0-9]+(-[a-z0-9]+)*$/.test(slug)
}