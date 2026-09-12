// Test-only stand-in for `@/lib/supabase/server` used by the organization
// member/audit API route unit tests
// (lib/organization-api/organization-routes.test.ts).
//
// lib/blockchain/test-support/test-loader.mjs maps the `@/lib/supabase/server`
// alias to THIS module when the importer lives under `/app/api/organizations/`,
// so the real route handlers can be exercised under node:test without Next's
// request context or a live Supabase. This file must never be imported from
// application code and never ships to a browser bundle.

export interface OrgRpcResult {
  data: unknown;
  error: { message: string } | null;
}

export type OrgRpcHandler = (
  params: Record<string, unknown>,
) => OrgRpcResult | Promise<OrgRpcResult>;

export interface OrgTableQuery {
  table: string;
  select: string;
  eqColumn: string;
  eqValue: unknown;
  orderColumn: string | null;
  ascending: boolean | null;
}

export type OrgTableHandler = (
  query: OrgTableQuery,
) => OrgRpcResult | Promise<OrgRpcResult>;

export interface OrgTableQueryBuilder {
  select(columns: string): OrgTableQueryBuilder;
  eq(column: string, value: unknown): OrgTableQueryBuilder;
  order(
    column: string,
    options?: { ascending?: boolean; nullsFirst?: boolean },
  ): OrgTableQueryBuilder;
  maybeSingle(): Promise<OrgRpcResult>;
  then<TResult1 = OrgRpcResult, TResult2 = never>(
    onfulfilled?: (value: OrgRpcResult) => TResult1 | PromiseLike<TResult1>,
    onrejected?: (reason: unknown) => TResult2 | PromiseLike<TResult2>,
  ): Promise<TResult1 | TResult2>;
}

export interface OrgFakeSupabaseClient {
  user: { id: string } | null;
  calls: Array<{ fn: string; params: Record<string, unknown> }>;
  rpcHandlers: Map<string, OrgRpcHandler>;
  tableHandlers: Map<string, OrgTableHandler>;
  auth: {
    getUser(): Promise<{ data: { user: { id: string } | null }; error: null }>;
  };
  rpc(fn: string, params: Record<string, unknown>): Promise<OrgRpcResult>;
  from(table: string): OrgTableQueryBuilder;
}

/**
 * The live client installed for the next createClient() call. Tests replace it
 * before each scenario; createClient() throws if none is installed so a test
 * that forgets to configure its client fails loudly instead of silently.
 */
export const orgClientHolder: { current: OrgFakeSupabaseClient | null } = {
  current: null,
};

export function createClient(): OrgFakeSupabaseClient {
  if (!orgClientHolder.current) {
    throw new Error("test-client-not-configured");
  }
  return orgClientHolder.current;
}

/**
 * Build a fresh scripted client: every rpc() call is recorded on `calls` and
 * dispatched to the handler previously installed for that function name. A
 * call to an unregistered function throws so an unexpected RPC in a scenario
 * fails the test instead of passing silently.
 */
export function makeOrgClient(): OrgFakeSupabaseClient {
  const client: OrgFakeSupabaseClient = {
    user: { id: "81000000-0000-0000-0000-000000000001" },
    calls: [],
    rpcHandlers: new Map(),
    tableHandlers: new Map(),
    auth: {
      async getUser() {
        return { data: { user: client.user }, error: null };
      },
    },
    async rpc(fn, params) {
      client.calls.push({ fn, params });
      const handler = client.rpcHandlers.get(fn);
      if (!handler) {
        throw new Error(`unexpected rpc call: ${fn}`);
      }
      return handler(params);
    },
    from(table) {
      const query: OrgTableQuery = {
        table,
        select: "*",
        eqColumn: "",
        eqValue: undefined,
        orderColumn: null,
        ascending: null,
      };
      const run = () => {
        const handler = client.tableHandlers.get(table);
        if (!handler) {
          throw new Error(`unexpected table query: ${table}`);
        }
        return handler(query);
      };
      const builder: OrgTableQueryBuilder = {
        select(columns) {
          query.select = columns;
          return builder;
        },
        eq(column, value) {
          query.eqColumn = column;
          query.eqValue = value;
          return builder;
        },
        order(column, options) {
          query.orderColumn = column;
          query.ascending = options?.ascending ?? true;
          return builder;
        },
        async maybeSingle() {
          return run();
        },
        then(onfulfilled, onrejected) {
          return Promise.resolve(run()).then(onfulfilled, onrejected);
        },
      };
      return builder;
    },
  };
  return client;
}