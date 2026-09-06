// Test-runner resolve hook for the blockchain unit tests only.
// Registered via `--experimental-loader ./lib/blockchain/test-support/test-loader.mjs`
// in the `npm test` script (see package.json). It does two things that the
// Node --experimental-strip-types runner cannot do on its own:
//
//   1. maps the `@/lib/supabase/server` path alias used by lib/blockchain/
//      orchestrator.ts onto the test-only stub module
//      (test-support/supabase-server-stub.ts), and
//   2. appends `.ts` to extensionless relative imports (e.g. "./anchor",
//      "./orchestrator-core") so the real orchestrator can be loaded under
//      Node, whose ESM resolver does not add TypeScript extensions.
//
// It is inert for every other specifier, so the remaining existing tests run
// exactly as before. This loader is for tests only; it must never be wired
// into the application.
import { pathToFileURL, fileURLToPath } from "node:url";
import { existsSync } from "node:fs";
import { resolve as resolvePath } from "node:path";

const SUPABASE_SERVER_STUB_URL = new URL(
  "./supabase-server-stub.ts",
  import.meta.url,
).href;

export async function resolve(specifier, context, nextResolve) {
  if (specifier === "@/lib/supabase/server") {
    return { url: SUPABASE_SERVER_STUB_URL, shortCircuit: true };
  }

  if (
    (specifier.startsWith("./") || specifier.startsWith("../")) &&
    context.parentURL
  ) {
    const parentDir = fileURLToPath(new URL(".", context.parentURL));
    const candidate = resolvePath(parentDir, specifier);
    if (!existsSync(candidate) && existsSync(candidate + ".ts")) {
      return { url: pathToFileURL(candidate + ".ts").href, shortCircuit: true };
    }
  }

  return nextResolve(specifier, context);
}