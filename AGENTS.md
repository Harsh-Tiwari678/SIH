<!-- BEGIN:nextjs-agent-rules -->

# This is NOT the Next.js you know

This version has breaking changes — APIs, conventions, and file structure may all differ from your training data. Read the relevant guide in `node_modules/next/dist/docs/` (resolved from this file's directory; in monorepos the `next` package may not be visible from the repo root) before writing any code. Heed deprecation notices.

This block is written and re-added by `next dev` — verify at `node_modules/next/dist/server/lib/generate-agent-files.js`. Removing it from a diff only re-creates the uncommitted change; committing it with your work keeps the tree clean.

<!-- END:nextjs-agent-rules -->

# Project: Secure Evidence — Digital Evidence Management System (SIH 26190)

A security-focused digital evidence management system built for Smart India Hackathon (SIH). Handle everything in this repo with security mindset: it manages sensitive evidentiary documents, chain-of-custody and audit history.

## Architecture

- **Frontend:** Next.js (App Router) + React + TypeScript
- **Styling:** Tailwind CSS
- **Backend/API:** Next.js Route Handlers (`app/**/route.ts`) — no separate backend service
- **Database:** Supabase PostgreSQL
- **Authentication:** Supabase Auth
- **Authorization:** PostgreSQL RLS where appropriate
- **File storage:** MinIO for actual document files
- **Integrity verification:** SHA-256 hashes of evidence documents
- **Encryption:** AES-256-GCM only where genuinely required (not as the default for everything)
- **Future additions:** Python + scikit-learn for AI/anomaly detection; Docker/Docker Compose for packaging
- **Shape:** modular monolith initially — one deployable application

## Development rules

1. This is a security-sensitive application. Default to the most conservative, auditable design. Never route around a security control "just to make it work."
2. Never hardcode secrets (API keys, JWTs, Supabase service-role keys, MinIO credentials, encryption keys, database credentials). Use environment variables (`.env.local` style, committed-free; `.env*` is already gitignored) and never log them.
3. Never invent APIs or pretend a security feature exists when it does not. If a capability (e.g., encryption at rest, tamper detection) is not implemented, say so plainly. Do not write code paths that imply protections that are not actually enforced.
4. Never use frontend checks as the only authorization mechanism. Hiding a button in the UI is not authorization.
5. Authorization must be enforced server-side, on every sensitive operation, regardless of what the UI shows.
6. Do not use AI for authentication, authorization, encryption, hashing, or permission decisions. These must be deterministic, auditable, and under our control.
7. Do not introduce unnecessary dependencies. Before adding a package, justify it: what it does, why it can't be done with what exists, and its maintenance/security implications.
8. Do not introduce microservices, Kubernetes, Kafka, blockchain, Keycloak, or OPA unless explicitly justified first. The system is a modular monolith.
9. Prefer simple, readable code over unnecessary abstractions. Favor explicit, boring implementations over clever indirection.
10. Do not modify unrelated files when implementing a feature. Keep diffs scoped to what the feature needs.
11. Do not implement an entire feature set at once. Work in small, reviewable increments.
12. Before implementing a significant feature, explain:
    - what is being built
    - why it is needed
    - architecture
    - files that will change
    - security implications
13. After implementation, explain:
    - important code
    - data flow
    - security considerations
    - how to test it
14. Database schema changes must use migrations (Supabase `supabase/migrations/`). Never hand-edit the live schema out-of-band.
15. Sensitive operations must perform, in order: authentication, authorization, validation, business logic, and appropriate audit logging. Don't skip or reorder these steps.
16. Never claim the system is "100% secure" or "unhackable." Security claims must be bounded and honest about what is and is not covered.
17. Preserve document versions rather than silently overwriting sensitive evidence. Evidence is versioned; new versions are new records, not clobbering writes.
18. SHA-256 is used for integrity verification only. It must never be described as encryption, and a hash alone is not proof of who modified a file — that comes from audit/chain-of-custody logs.
19. Audit logs and chain-of-custody records are different concepts. Audit logs record what happened operationally; chain-of-custody records who handled a piece of evidence. Design them separately.
20. Keep the application as a modular monolith initially. No separate backend services, no over-engineered distributed architecture before it is justified.

## Security-sensitive files to be careful with

Not yet created — but once added, treat these as high-risk and review carefully:

- Route Handlers touching evidence files, hashes, or auth (`app/**/route.ts`)
- Supabase Auth / RLS policies (SQL migrations)
- MinIO object storage access layer
- Any code handling AES-256-GCM keys or ciphertext
- Audit log and chain-of-custody writers
