// Dynamic client registration writes a KV record per call, so an open
// /register endpoint lets anyone burn the free-plan KV write quota. A Worker
// on workers.dev has no zone WAF to rate limit it, so the limit lives here,
// backed by the rate-limiting binding in wrangler.jsonc. No binding, no limit.

const REGISTER_PATH = "/register";

export async function rateLimitRegistration(request, env) {
  if (!env.REGISTER_RATE_LIMITER) return null;
  if (request.method !== "POST") return null;
  if (new URL(request.url).pathname !== REGISTER_PATH) return null;

  const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
  const { success } = await env.REGISTER_RATE_LIMITER.limit({ key: `register:${ip}` });
  if (success) return null;

  return Response.json(
    {
      error: "rate_limited",
      error_description: "Too many client registrations. Try again in a minute.",
    },
    {
      status: 429,
      headers: {
        "Cache-Control": "no-store",
        "Retry-After": "60",
      },
    }
  );
}
