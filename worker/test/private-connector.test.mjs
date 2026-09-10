// Tests for the private (single-owner) deployment additions: the YNAB user
// allowlist enforced at the OAuth callback and the /register rate limit.

import assert from "node:assert/strict";
import test from "node:test";

import { YnabHandler } from "../src/ynab-handler.js";
import { isAllowedYnabUser } from "../src/private-access.js";
import { rateLimitRegistration } from "../src/register-rate-limit.js";
import { tokenRecordKey } from "../src/ynab-oauth.js";

const ORIGIN = "https://ynab-mcp.example.workers.dev";
const DATA_KEY = "test-only-data-encryption-key-with-enough-entropy";
const COOKIE_KEY = "test-only-cookie-signing-key-with-enough-entropy";

class MemoryKV {
  constructor() {
    this.values = new Map();
  }

  async get(key) {
    return this.values.get(key) ?? null;
  }

  async put(key, value) {
    this.values.set(key, value);
  }

  async delete(key) {
    this.values.delete(key);
  }
}

class MemoryTransientNamespace {
  constructor() {
    this.records = new Map();
  }

  getByName(name) {
    return {
      fetch: async (input, init) => {
        const request = new Request(input, init);
        const url = new URL(request.url);
        if (request.method === "PUT" && url.pathname === "/record") {
          this.records.set(name, await request.json());
          return new Response(null, { status: 204 });
        }
        if (request.method === "POST" && url.pathname === "/consume") {
          const record = this.records.get(name);
          this.records.delete(name);
          if (!record) return new Response(null, { status: 404 });
          return Response.json(record.value);
        }
        return new Response(null, { status: 404 });
      },
    };
  }
}

function hiddenValue(html, name) {
  const match = html.match(new RegExp(`name="${name}" value="([^"]+)"`));
  assert.ok(match, `missing hidden input ${name}`);
  return match[1];
}

function connectorEnv(overrides = {}) {
  const kv = new MemoryKV();
  const transient = new MemoryTransientNamespace();
  let completed = 0;
  const env = {
    COOKIE_ENCRYPTION_KEY: COOKIE_KEY,
    DATA_ENCRYPTION_KEY: DATA_KEY,
    CONNECTOR_BASE_URL: ORIGIN,
    YNAB_CLIENT_ID: "ynab-client-id",
    YNAB_CLIENT_SECRET: "ynab-client-secret",
    OAUTH_KV: kv,
    OAUTH_STATE: transient,
    OAUTH_PROVIDER: {
      async parseAuthRequest() {
        return {
          responseType: "code",
          clientId: "chatgpt-client",
          redirectUri: "https://chatgpt.com/connector_platform_oauth_redirect",
          scope: [],
          state: "client-state",
          codeChallenge: "client-pkce",
          codeChallengeMethod: "S256",
          resource: `${ORIGIN}/mcp`,
        };
      },
      async lookupClient() { return { clientName: "ChatGPT" }; },
      async completeAuthorization() {
        completed += 1;
        return { redirectTo: "https://chatgpt.com/connector_platform_oauth_redirect?code=c" };
      },
    },
    ...overrides,
  };
  return { env, kv, transient, completions: () => completed };
}

function stubYnab(t, ynabUserId) {
  const originalFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = originalFetch; });
  globalThis.fetch = async (url) => {
    if (String(url) === "https://app.ynab.com/oauth/token") {
      return Response.json({
        access_token: "pending-access-token",
        refresh_token: "pending-refresh-token",
        expires_in: 7200,
      });
    }
    if (String(url) === "https://api.ynab.com/v1/user") {
      return Response.json({ data: { user: { id: ynabUserId } } });
    }
    throw new Error(`Unexpected fetch: ${url}`);
  };
}

async function signInThroughYnab(env) {
  const page = await YnabHandler.request(`${ORIGIN}/authorize`, {}, env);
  const consentBody = await page.text();
  const approval = await YnabHandler.request(`${ORIGIN}/authorize`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", Origin: ORIGIN },
    body: new URLSearchParams({
      consent: hiddenValue(consentBody, "consent"),
      csrf: hiddenValue(consentBody, "csrf"),
    }),
  }, env);
  const state = new URL(approval.headers.get("location")).searchParams.get("state");
  return YnabHandler.request(
    `${ORIGIN}/callback?code=ynab-code&state=${encodeURIComponent(state)}`,
    {},
    env
  );
}

test("callback refuses YNAB accounts outside ALLOWED_YNAB_USER_IDS before storing anything", async (t) => {
  const { env, kv, transient, completions } = connectorEnv({ ALLOWED_YNAB_USER_IDS: "owner-id" });
  stubYnab(t, "stranger-id");

  const callback = await signInThroughYnab(env);

  assert.equal(callback.status, 403);
  assert.match(await callback.text(), /not permitted/i);
  assert.equal(completions(), 0);
  assert.equal(await kv.get(tokenRecordKey("stranger-id")), null);
  assert.deepEqual([...transient.records.keys()].filter((key) => key.startsWith("final:")), []);
  assert.doesNotMatch(JSON.stringify([...transient.records.values()]), /pending-access-token|pending-refresh-token/);
});

test("callback continues to final confirmation for an allowlisted YNAB account", async (t) => {
  const { env } = connectorEnv({ ALLOWED_YNAB_USER_IDS: "someone-else, owner-id" });
  stubYnab(t, "owner-id");

  const callback = await signInThroughYnab(env);

  assert.equal(callback.status, 200);
  assert.ok(hiddenValue(await callback.text(), "finalize"));
});

test("isAllowedYnabUser keeps upstream behavior when no allowlist is configured", () => {
  assert.equal(isAllowedYnabUser({}, "anyone"), true);
  assert.equal(isAllowedYnabUser({ ALLOWED_YNAB_USER_IDS: "  " }, "anyone"), true);
});

test("isAllowedYnabUser matches trimmed comma-separated ids exactly", () => {
  const env = { ALLOWED_YNAB_USER_IDS: " owner-id ,second-id," };
  assert.equal(isAllowedYnabUser(env, "owner-id"), true);
  assert.equal(isAllowedYnabUser(env, "second-id"), true);
  assert.equal(isAllowedYnabUser(env, "owner"), false);
  assert.equal(isAllowedYnabUser(env, ""), false);
  assert.equal(isAllowedYnabUser(env, undefined), false);
});

function recordingLimiter(success) {
  const calls = [];
  return {
    calls,
    async limit(options) {
      calls.push(options);
      return { success };
    },
  };
}

test("client registration is rate limited per connecting IP", async () => {
  const limiter = recordingLimiter(false);
  const response = await rateLimitRegistration(
    new Request(`${ORIGIN}/register`, { method: "POST", headers: { "CF-Connecting-IP": "203.0.113.9" } }),
    { REGISTER_RATE_LIMITER: limiter }
  );

  assert.equal(response.status, 429);
  assert.equal(response.headers.get("Retry-After"), "60");
  assert.equal((await response.json()).error, "rate_limited");
  assert.deepEqual(limiter.calls, [{ key: "register:203.0.113.9" }]);
});

test("client registration under the limit passes through", async () => {
  const limiter = recordingLimiter(true);
  const response = await rateLimitRegistration(
    new Request(`${ORIGIN}/register`, { method: "POST", headers: { "CF-Connecting-IP": "203.0.113.9" } }),
    { REGISTER_RATE_LIMITER: limiter }
  );

  assert.equal(response, null);
  assert.equal(limiter.calls.length, 1);
});

test("rate limiting ignores other routes, non-POST requests, and missing bindings", async () => {
  const limiter = recordingLimiter(false);
  const env = { REGISTER_RATE_LIMITER: limiter };

  assert.equal(await rateLimitRegistration(new Request(`${ORIGIN}/token`, { method: "POST" }), env), null);
  assert.equal(await rateLimitRegistration(new Request(`${ORIGIN}/register`), env), null);
  assert.equal(limiter.calls.length, 0);
  assert.equal(await rateLimitRegistration(new Request(`${ORIGIN}/register`, { method: "POST" }), {}), null);
});
