// Test-runner resolve hook for the blockchain unit tests AND the evidence
// access route unit tests.
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
//   3. maps the other `@/lib/*` aliases used by the access route onto their
//      real sources, and maps `next/server` onto next/server.js (the Next
//      package does not expose the extensionless subpath in its exports map,
//      so plain Node ESM cannot resolve it),
//   4. appends `.ts` to extensionless relative imports (e.g. "./anchor",
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

const NEXT_SERVER_URL = new URL("../../../node_modules/next/server.js", import.meta.url)
  .href;

export async function resolve(specifier, context, nextResolve) {
  if (specifier === "@/lib/supabase/server") {
    const isAccessRoute =
      (context.parentURL ?? "").includes("/app/api/cases/");
    return {
      url: isAccessRoute ? ACCESS_SERVER_STUB_URL : SUPABASE_SERVER_STUB_URL,
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