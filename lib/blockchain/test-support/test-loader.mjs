// Test-runner resolve hook for the blockchain unit tests AND the evidence
// access route unit tests AND the organization API route unit tests.
// Registered via `--experimental-loader ./lib/blockchain/test-support/test-loader.mjs`
// in the `npm test` script (see package.json). It does the things that the
// Node --experimental-strip-types runner cannot do on its own:
//
//   1. maps the `@/lib/supabase/server` path alias used by lib/blockchain/
//      orchestrator.ts onto the test-only stub module
//      (test-support/supabase-server-stub.ts),
//   2. when the importer is the evidence access route, maps the same alias
//      onto the route-specific stub (lib/evidence-access/test-support/
//      access-server-stub.ts) so the real GET handler can be unit-tested for
//      its fail-closed audit behavior,
//   3. when the importer is an organization API route, maps the same alias
//      onto the org-specific stub (lib/organization-api/test-support/
//      org-server-stub.ts) so the real organization member/audit handlers can
//      be unit-tested,
//   4. maps the other `@/lib/*` aliases used by those routes onto their real
//      sources, and maps `next/server` onto next/server.js (the Next package
//      does not expose the extensionless subpath in its exports map, so plain
//      Node ESM cannot resolve it),
//   5. appends `.ts` to extensionless relative imports (e.g. "./anchor",
//      "./orchestrator-core") so the real orchestrator can be loaded under
//      Node, whose ESM resolver does not add TypeScript extensions.
//
// It is inert for every other specifier, so the remaining existing tests run
// exactly as before. This loader is for tests only; it must never be wired
// into the application.
import { pathToFileURL, fileURLToPath } from "node:url";
import { existsSync } from "node:fs";
import { resolve as resolvePath } from "node:path";

const REPO_ROOT = new URL("../../../", import.meta.url);

const SUPABASE_SERVER_STUB_URL = new URL(
  "./supabase-server-stub.ts",
  import.meta.url,
).href;

const ACCESS_SERVER_STUB_URL = new URL(
  "../../evidence-access-route/test-support/access-server-stub.ts",
  import.meta.url,
).href;

const ORG_SERVER_STUB_URL = new URL(
  "../../organization-api/test-support/org-server-stub.ts",
  import.meta.url,
).href;

const CASE_SERVER_STUB_URL = new URL(
  "../../cases-api/test-support/case-server-stub.ts",
  import.meta.url,
).href;

const NEXT_SERVER_URL = new URL("../../../node_modules/next/server.js", import.meta.url)
  .href;

export async function resolve(specifier, context, nextResolve) {
  if (specifier === "@/lib/supabase/server") {
    const parent = context.parentURL ?? "";
    const isCaseRoute = parent.includes("/app/api/cases/");
    const isOrgRoute = parent.includes("/app/api/organizations/");
    if (isCaseRoute) {
      // The evidence-access route is the ONLY /app/api/cases/ route that needs
      // the signed-URL stub; every other case route (case detail, evidence
      // status, custody, ...) uses the dedicated case-lifecycle stub.
      const isAccessRoute = parent.includes("/access/route.ts");
      return {
        url: isAccessRoute
          ? ACCESS_SERVER_STUB_URL
          : CASE_SERVER_STUB_URL,
        shortCircuit: true,
      };
    }
    if (isOrgRoute) {
      return { url: ORG_SERVER_STUB_URL, shortCircuit: true };
    }
    return {
      url: SUPABASE_SERVER_STUB_URL,
      shortCircuit: true,
    };
  }

  if (specifier === "next/server") {
    return { url: NEXT_SERVER_URL, shortCircuit: true };
  }

  if (specifier.startsWith("@/lib/")) {
    const file = specifier.slice(2) + ".ts";
    const candidate = new URL(file, REPO_ROOT);
    if (existsSync(fileURLToPath(candidate))) {
      return { url: candidate.href, shortCircuit: true };
    }
  }

  if (
    (specifier.startsWith("./") || specifier.startsWith("../")) &&
    context.parentURL
  ) {
    const parentDir = fileURLToPath(new URL(".", context.parentURL));
    const candidate = resolvePath(parentDir, specifier);
    // Prefer a same-named .ts module over a directory that happens to share
    // the name (e.g. lib/evidence-access.ts vs. an evidence-access folder),
    // mirroring how the bundler resolves extensionless imports.
    if (existsSync(candidate + ".ts")) {
      return { url: pathToFileURL(candidate + ".ts").href, shortCircuit: true };
    }
    if (existsSync(candidate) && (await isFile(candidate))) {
      return { url: pathToFileURL(candidate).href, shortCircuit: true };
    }
  }

  return nextResolve(specifier, context);
}

async function isFile(path) {
  return (await import("node:fs/promises")).stat(path).then((s) => s.isFile(), () => false);
}