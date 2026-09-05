// Test-only stand-in for `@/lib/supabase/server`'s createClient().
//
// The orchestrator imports createClient from the `@/` path alias, which the
// Node test runner cannot resolve. lib/blockchain/test-support/test-loader.mjs
// maps that alias to THIS module for tests, so the orchestrator can be
// exercised end-to-end with a scripted DB RPC client while the real Supabase /
// Next request-context code stays untouched. This file must never be imported
// from application code and never ships to a browser bundle.

export interface RpcResult {
  data: unknown;
  error: { message: string } | null;
}

export type RpcHandler = (
  params: Record<string, unknown>,
) => RpcResult | Promise<RpcResult>;

export interface FakeSupabaseClient {
  user: { id: string } | null;
  calls: Array<{ fn: string; params: Record<string, unknown> }>;
  handlers: Map<string, RpcHandler>;
  auth: {
    getUser(): Promise<{ data: { user: { id: string } | null }; error: null }>;
  };
  rpc(fn: string, params: Record<string, unknown>): Promise<RpcResult>;
}

/**
 * The live client installed for the next createClient() call. Tests replace it
 * before each scenario; createClient() throws if none is installed so a test
 * that forgets to configure its client fails loudly instead of silently.
 */
export const clientHolder: { current: FakeSupabaseClient | null } = {
  current: null,
};

export function createClient(): FakeSupabaseClient {
  if (!clientHolder.current) {
    throw new Error("test-client-not-configured");
  }
  return clientHolder.current;
}

/**
 * Build a fresh scripted client: every rpc() call is recorded on `calls` and
 * dispatched to the handler previously installed for that function name. A
 * call to an unregistered function throws so an unexpected RPC in a scenario
 * fails the test instead of passing silently.
 */
export function makeFakeClient(): FakeSupabaseClient {
  const client: FakeSupabaseClient = {
    user: { id: "00000000-0000-4000-8000-000000000001" },
    calls: [],
    handlers: new Map(),
    auth: {
      async getUser() {
        return { data: { user: client.user }, error: null };
      },
    },
    async rpc(fn, params) {
      client.calls.push({ fn, params });
      const handler = client.handlers.get(fn);
      if (!handler) {
        throw new Error(`unexpected rpc call: ${fn}`);
      }
      return handler(params);
    },
  };
  return client;
}