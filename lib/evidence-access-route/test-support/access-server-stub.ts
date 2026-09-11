// Test-only stand-in for `@/lib/supabase/server` used by the evidence access
// route unit test (lib/evidence-access/access-route.test.ts).
//
// lib/blockchain/test-support/test-loader.mjs maps the `@/lib/supabase/server`
// alias to THIS module when the importer is the access route, so the real
// route handler can be exercised under node:test without Next's request
// context or a live Supabase. This file must never be imported from
// application code and never ships to a browser bundle.

export interface AccessRpcResult {
  data: unknown;
  error: { message: string } | null;
}

export interface AccessSignResult {
  data: { signedUrl: string; path: string } | null;
  error: { message: string } | null;
}

export type AccessRpcHandler = (
  params: Record<string, unknown>,
) => AccessRpcResult | Promise<AccessRpcResult>;

export interface AccessTableQuery {
  table: string;
  select: string;
  eqColumn: string;
  eqValue: unknown;
}

export type AccessTableHandler = (
  query: AccessTableQuery,
) => AccessRpcResult | Promise<AccessRpcResult>;

export interface AccessTableQueryBuilder {
  select(columns: string): AccessTableQueryBuilder;
  eq(column: string, value: unknown): AccessTableQueryBuilder;
  maybeSingle(): Promise<AccessRpcResult>;
}

export interface AccessSignRecord {
  path: string;
  expiresIn: number;
  options: { download?: string | boolean } | undefined;
}

export interface AccessStorageBucket {
  createSignedUrl(
    path: string,
    expiresIn: number,
    options?: { download?: string | boolean },
  ): Promise<AccessSignResult>;
}

export interface AccessFakeSupabaseClient {
  user: { id: string } | null;
  calls: Array<{ fn: string; params: Record<string, unknown> }>;
  signs: Array<AccessSignRecord>;
  signUrls: string[];
  rpcHandlers: Map<string, AccessRpcHandler>;
  tableHandlers: Map<string, AccessTableHandler>;
  signHandler: (record: AccessSignRecord) => AccessSignResult;
  auth: {
    getUser(): Promise<{ data: { user: { id: string } | null }; error: null }>;
  };
  rpc(fn: string, params: Record<string, unknown>): Promise<AccessRpcResult>;
  from(table: string): AccessTableQueryBuilder;
  storage: {
    from(bucket: string): AccessStorageBucket;
  };
}

/** The live client installed for the next createClient() call. */
export const accessClientHolder: { current: AccessFakeSupabaseClient | null } =
  { current: null };

export function createClient(): AccessFakeSupabaseClient {
  if (!accessClientHolder.current) {
    throw new Error("test-client-not-configured");
  }
  return accessClientHolder.current;
}

/**
 * Build a fresh scripted client. Every rpc() call is recorded on `calls` and
 * dispatched to the handler previously installed for that function name; an
 * unregistered RPC throws so an unexpected call fails the test loudly.
 * createSignedUrl is recorded on `signs` and handled by `signHandler` (which a
 * test replaces to simulate sign failures).
 */
export function makeAccessClient(): AccessFakeSupabaseClient {
  const client: AccessFakeSupabaseClient = {
    user: { id: "00000000-0000-4000-8000-000000000001" },
    calls: [],
    signs: [],
    signUrls: [],
    rpcHandlers: new Map(),
    tableHandlers: new Map(),
    signHandler: (record) => ({
      data: {
        signedUrl: `https://storage.example/object/sign/evidence-files/${record.path}?token=sig&expires=${record.expiresIn}${
          record.options?.download
            ? `&download=${encodeURIComponent(String(record.options.download))}`
            : ""
        }`,
        path: record.path,
      },
      error: null,
    }),
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
      const query: AccessTableQuery = {
        table,
        select: "*",
        eqColumn: "",
        eqValue: undefined,
      };
      const builder: AccessTableQueryBuilder = {
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
          const handler = client.tableHandlers.get(table);
          if (!handler) {
            throw new Error(`unexpected table query: ${table}`);
          }
          return handler(query);
        },
      };
      return builder;
    },
    storage: {
      from() {
        return {
          async createSignedUrl(path, expiresIn, options) {
            client.signs.push({ path, expiresIn, options });
            const result = await client.signHandler({ path, expiresIn, options });
            if (result.data) {
              client.signUrls.push(result.data.signedUrl);
            } else {
              client.signUrls.push("");
            }
            return result;
          },
        };
      },
    },
  };
  return client;
}