// Private deployments restrict which YNAB accounts may complete the connector
// OAuth flow. ALLOWED_YNAB_USER_IDS is a comma-separated list of YNAB user ids;
// when it is unset or blank, any YNAB account may connect (upstream behavior).

export function isAllowedYnabUser(env, ynabUserId) {
  const allowed = (env.ALLOWED_YNAB_USER_IDS ?? "")
    .split(",")
    .map((id) => id.trim())
    .filter(Boolean);
  if (allowed.length === 0) return true;
  return typeof ynabUserId === "string" && allowed.includes(ynabUserId);
}
