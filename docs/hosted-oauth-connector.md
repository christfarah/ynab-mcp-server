# Hosted OAuth Connector Pattern

This repository includes both the local stdio MCP server and a hosted connector at `https://ynab.amesvt.com/mcp`. The hosted connector does not ask users for a YNAB personal access token. It uses YNAB's authorization-code flow, stores encrypted per-user tokens server-side, and exposes MCP over HTTPS.

## Architecture

The Cloudflare Worker in `worker/` uses these routes:

| Route | Purpose |
|---|---|
| `/mcp` | MCP endpoint served by the hosted connector. Requires a valid connector grant. |
| `/authorize` | Starts the connector OAuth flow and renders consent. |
| `/callback` | Receives the YNAB authorization code and completes the connector authorization. |
| `/token` | Issues connector access tokens to MCP hosts. |
| `/register` | Dynamic client registration, if the host supports it. |
| `/privacy` | Public privacy policy. |
| `/delete` | User-facing data deletion and grant revocation flow. |

The Smirnovlabs-style Cloudflare pattern is a good fit: wrap the MCP handler in an OAuth provider, use a stateful MCP agent for authenticated sessions, and keep the YNAB OAuth token refresh path separate from tool registration. Composio-style hosted connectors use the same core shape: hosted OAuth, per-user token vaulting, and a remote MCP endpoint instead of user-supplied PATs.

## YNAB OAuth Requirements

Use YNAB OAuth instead of personal access tokens:

- Authorization URL: `https://app.ynab.com/oauth/authorize`
- Token URL: `https://app.ynab.com/oauth/token`
- Response type: `code`
- PKCE: `S256` code challenge and verifier
- Scope: use the minimum viable scope. Prefer read-only unless the hosted connector explicitly offers write tools.

Required Worker values:

| Variable | Purpose |
|---|---|
| `YNAB_CLIENT_ID` | YNAB OAuth application client ID (Worker secret). |
| `YNAB_CLIENT_SECRET` | YNAB OAuth application secret (Worker secret). |
| `COOKIE_ENCRYPTION_KEY` | HMAC key for one-time consent and callback state, plus the deletion-form CSRF cookie (Worker secret). |
| `DATA_ENCRYPTION_KEY` | AES-GCM key material for YNAB tokens and undo journals (Worker secret). |
| `CONNECTOR_BASE_URL` | Public connector origin used to build the exact callback URI. |
| `OAUTH_KV` | KV binding for connector grants, OAuth state, encrypted YNAB tokens, and encrypted undo journals. |

## Safety Model

Carry the local safety model into the hosted connector:

1. Register read tools by default.
2. Register write tools only when the connector grant, deployment config, and requested YNAB scope all allow writes.
3. Annotate read tools with `readOnlyHint: true`.
4. Annotate write tools with `readOnlyHint: false`, and use `destructiveHint: true` for delete tools.
5. Pin outbound YNAB HTTP traffic to `https://api.ynab.com`; reject redirects and non-YNAB hosts.
6. Redact `Authorization`, bearer tokens, access tokens, and refresh tokens from logs and MCP errors.
7. Add a delete-data flow that revokes connector grants and removes stored YNAB tokens.

## OAuth State Handling

Embedded OAuth browsers do not reliably preserve first-party cookies between
the connector consent page and its form submission. The hosted authorization
flow therefore keeps consent and callback state server-side:

1. Generate separate 192-bit opaque values for the consent record, hidden CSRF token, and YNAB OAuth `state`.
2. Store the parsed MCP authorization request with a keyed hash bound to the consent ID and hidden CSRF token. Use a 10-minute TTL.
3. On consent submission, fetch and delete the record before validation, then verify the submitted hidden token with the stored keyed hash.
4. Generate a PKCE verifier and `S256` challenge for YNAB.
5. Store the MCP authorization request, verifier, access choice, and keyed state hash under the opaque OAuth state. Use a 10-minute TTL.
6. On `/callback`, fetch and delete the state record before validation, then verify its keyed hash before exchanging the YNAB code.

The one-time records prevent sequential replay and keep concurrent client flows
separate without depending on browser cookies. Cloudflare KV does not provide a
compare-and-swap primitive, so the design also relies on unguessable 192-bit
record identifiers and the short TTL rather than claiming transactional
consumption.

## Token Lifecycle

The hosted connector should store tokens by connector user or YNAB user ID:

- On callback, exchange the code for YNAB access and refresh tokens.
- Fetch the YNAB user profile immediately and persist the YNAB user ID with the token record.
- Refresh tokens before expiry, with a small safety window such as 60 seconds.
- If refresh fails, preserve the record and require reauthorization. Re-read first so a concurrent successful refresh is not discarded.
- Never expose YNAB access or refresh tokens to the MCP host or model context.

## Deployment Checklist

- Create and verify a YNAB OAuth application with the production redirect URI.
- Decide whether the hosted connector offers read-only only, read/write, or separate read-only and write-enabled variants.
- Publish privacy, support, and deletion pages before public distribution.
- Include a public support contact for account, deletion, and security questions.
- Configure the OAuth app with a privacy policy URL and display that URL clearly in the connector interface.
- Use public names and DNS names that follow the "for YNAB" pattern and do not imply sponsorship, endorsement, or official YNAB support.
- Add non-affiliation language; this connector is not an official YNAB product.
- Configure the edge before smoke testing: add the Browser Integrity Check skip rule and the
  `/register` rate limit, and list every browser client origin in `MCP_ALLOWED_ORIGINS`.
  See "Edge configuration (Cloudflare)" below.
- Run read-only smoke tests through `/mcp`.
- If writes are enabled, run the batch category+approval smoke against a dedicated test budget and assert post-write refetch verification.
- Require `confirmed: true` for destructive direct tools, bulk-filter write tools, and any generic write executor.

## Edge configuration (Cloudflare)

The Worker runs behind the zone's security settings, which are evaluated before
any Worker code. Two zone-level facts decide whether a client can connect at all.

**Browser Integrity Check bans scripted HTTP libraries.** It returns `error code:
1010` (HTTP 403) to any request whose `User-Agent` matches a known automation
signature — `Python-urllib/*` is one. The check is zone-wide and method-agnostic,
so it blocks discovery, registration, token exchange, and `/mcp` alike, and no
Worker change can see or fix it. Clients using `curl`, `python-requests`, or a
browser UA are unaffected, which makes the failure look client-specific. Diagnose
any endpoint by comparing two requests that differ only in `User-Agent`:

```bash
curl -s -o /dev/null -w 'urllib: %{http_code}\n' -A 'Python-urllib/3.11' https://HOST/mcp
curl -s -o /dev/null -w 'curl:   %{http_code}\n' -A 'curl/8.7.1'        https://HOST/mcp
```

Fix it with a WAF custom rule whose action is Skip and whose only skipped
component is Browser Integrity Check. Scope it to the machine-to-machine paths so
the browser consent flow keeps the check:

```
(http.host eq "HOST" and (http.request.uri.path in {"/mcp" "/sse" "/register" "/token"} or starts_with(http.request.uri.path, "/.well-known/") or starts_with(http.request.uri.path, "/register/")))
```

Do not disable Browser Integrity Check for the whole zone, and do not tick the
broad skip options (all managed rules, Super Bot Fight Mode, Security Level) —
they skip far more than this needs. Skipping the check on the protected paths
costs little, since `/mcp` and `/sse` require a valid bearer token and `/token`
requires a valid code plus PKCE verifier.

The skip does expose `/register`, which is unauthenticated by design under
dynamic client registration, so pair it with a rate-limiting rule keyed on IP
against that path. Verify any such rule behaviourally with rapid requests rather
than trusting the dashboard — Cloudflare's rule forms are React-controlled, and a
save can silently discard a programmatically set field.

**Keep `MCP_ALLOWED_ORIGINS` current.** Browser-based clients are rejected with
403 `invalid_origin` unless their web origin is listed. Claude serves from both
`https://claude.ai` and `https://claude.com`, and both must be present. Native
and server-to-server clients send no `Origin` header and are allowed through
unchanged, per the MCP transport specification.

## Read-only vs write grants (client troubleshooting)

Because writes are gated at consent time, a connection authorized without the
write box checked receives a read-only YNAB token and never registers write
tools — the MCP client correctly lists only read tools. This is the expected
outcome, not a fault. Make the state self-diagnosing:

- Keep `ynab_auth_status` a read tool so it is reachable from a read-only
  session. It reports `writes_enabled` and a host-aware `write_enablement` hint.
- Word the write-disabled guidance for the actual host. A hosted OAuth user
  cannot restart the process or set an env var; the correct remediation is to
  reconnect and check "Allow write access." The shared factory derives this from
  `runtime.tokenSource.source === "ynab_oauth"`.
- Remember the client-enablement caveat: some clients require a developer/beta
  mode or workspace-admin approval before they expose or invoke custom-connector
  write tools, independent of the YNAB grant. Prove the server independently
  (MCP Inspector / direct `tools/call`) before treating a missing write action
  as a connector defect.
