// Test-only stand-in for `@/lib/supabase/server` used by the case lifecycle
// API route unit tests (lib/cases-api/case-routes.test.ts).
//
// lib/blockchain/test-support/test-loader.mjs maps the `@/lib/supabase/server`
// alias to THIS module when the importer is a non-access route under
// `/app/api/cases/` (case detail PATCH, evidence status, custody), so the real
// route handlers can be exercised under node:test without Next's request
// context or a live Supabase. This file must never be imported from
// application code and never ships to a browser bundle.

export interface CaseRpcResult {
  data: unknown;
  error: { message: string } | null;
}

export type CaseRpcHandler = (
  params: Record<string, unknown>,
) => CaseRpcResult | Promise<CaseRpcResult>;

export interface CaseTableQuery {
  table: string;
  select: string;
  eqColumn: string;
  eqValue: unknown;
}

export type CaseTableHandler = (
  query: CaseTableQuery,
) => CaseRpcResult | Promise<CaseRpcResult>;

export interface CaseTableQueryBuilder {
  select(columns: string): CaseTableQueryBuilder;
  eq(column: string, value: unknown): CaseTableQueryBuilder;
  maybeSingle(): Promise<CaseRpcResult>;
  then<TResult1 = CaseRpcResult, TResult2 = never>(
    onfulfilled?: (value: CaseRpcResult) => TResult1 | PromiseLike<TResult1>,
    onrejected?: (reason: unknown) => TResult2 | PromiseLike<TResult2>,
  ): Promise<TResult1 | TResult2>;
}

export interface CaseFakeSupabaseClient {
  user: { id: string } | null;
  calls: Array<{ fn: string; params: Record<string, unknown> }>;
  queries: Array<CaseTableQuery>;
  rpcHandlers: Map<string, CaseRpcHandler>;
  tableHandlers: Map<string, CaseTableHandler>;
  auth: {
    getUser(): Promise<{ data: { user: { id: string } | null }; error: null }>;
  };
  rpc(fn: string, params: Record<string, unknown>): Promise<CaseRpcResult>;
  from(table: string): CaseTableQueryBuilder;
}

/** The live client installed for the next createClient() call. */
export const caseClientHolder: { current: CaseFakeSupabaseClient | null } = {
  current: null,
};

export function createClient(): CaseFakeSupabaseClient {
  if (!caseClientHolder.current) {
    throw new Error("test-client-not-configured");
  }
  return caseClientHolder.current;
}

/**
 * Build a fresh scripted client: every rpc()/table query is recorded and
 * dispatched to the handler previously installed for that function/table name.
 * A call to an unregistered function/table throws so an unexpected call in a
 * scenario fails the test instead of passing silently.
 */
export function makeCaseClient(): CaseFakeSupabaseClient {
  const client: CaseFakeSupabaseClient = {
    user: { id: "81000000-0000-0000-0000-000000000001" },
    calls: [],
    queries: [],
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
      const query: CaseTableQuery = {
        table,
        select: "*",
        eqColumn: "",
        eqValue: undefined,
      };
      const run = () => {
        const handler = client.tableHandlers.get(table);
        if (!handler) {
          throw new Error(`unexpected table query: ${table}`);
        }
        return handler(query);
      };
      const builder: CaseTableQueryBuilder = {
        select(columns) {
          query.select = columns;
          return builder;
        },
        eq(column, value) {
          query.eqColumn = column;
          query.eqValue = value;
          return builder;
        },
        async maybeSingle() {
          client.queries.push(query);
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