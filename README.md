# AgentAdmit SDK for PHP (Laravel)

User-mediated AI agent authorization. Plug-and-play for any Laravel app.

> **Get started:** Sign up at [agentadmit.com](https://agentadmit.com) → Get your test keys → Install the SDK → Build.
> Test keys are available immediately after signup. Live keys become available when you subscribe an app.

## Quick Start

```bash
composer require agentadmit/laravel
php artisan vendor:publish --tag=agentadmit-config
```

Add your credentials to `.env`:

```env
AGENTADMIT_APP_ID=app_yourappid
AGENTADMIT_API_KEY=aa_test_yourkey
```

Add scope enforcement to any route:

```php
// routes/api.php
Route::middleware('agentadmit.scope:read:orders')->get('/orders', [OrderController::class, 'index']);
```

Your app now supports AI agent connections with:
- Scoped access control (you define the scopes)
- User-controlled connection duration
- Token generation and exchange
- Mandatory introspection (every agent request validated through AgentAdmit)
- Revocation and remote audit logging (via the AgentAdmit hosted service)

## How It Works

1. User clicks "AgentAdmit" in your app
2. Selects scopes and connection duration
3. Gets a token to give to their AI agent
4. Agent exchanges the token for scoped API access
5. User revokes anytime

The token goes to the human, not the agent. No automated delivery = no prompt injection surface.

## Important

**Mandatory introspection.** All token validation goes through api.agentadmit.com. There is no self-hosted mode. No local JWT validation. No bypass. This is required for security, audit logging, and scope enforcement.

**Admin revocation.** As the app operator, you can revoke any user's agent connection by calling `TokensClient::revoke($connectionId)` from your backend (requires your operator API key).

**Embeddable admin panel.** Drop the `<AgentAdmitAdminPanel>` React component into your admin section to view all agent connections, usage metrics, billing status, and revoke any connection without leaving your app. See the React SDK for details.

**In-app AI scopes.** If your app has built-in AI features (analysis, plan generation, photo recognition), do not expose those as agent scopes. The user's AI agent can read the raw data and do the analysis itself. Exposing in-app AI endpoints to agents creates double cost.

## Consent Ledger (Caller-Identity Consent)

AgentAdmit can host per-user consent switches for three independent caller classes: `human_session`, `in_app_ai`, and `external_agent`. No class's setting implies another's.

**External agents:** the verify result already carries the verdict:

```php
$result = $introspectionClient->verify($token);
if (!$result->consentGranted()) {
    abort(403, 'The data owner has not enabled external agent access.');
}
```

`consentGranted()` fails closed when the verdict is absent (the hosted service omits it while its consent store is unreadable). To keep serving during that degraded mode, resolve an absent verdict authoritatively with `ConsentClient::checkConsent($result->userId, 'external_agent')` — the `CallerConsent` middleware does this for you.

**Human sessions and in-app AI** never hold AgentAdmit tokens, so ask directly:

```php
use AgentAdmit\ConsentClient;

$consent = new ConsentClient(config('agentadmit'));
$verdict = $consent->checkConsent('user_8842', ConsentClient::CALLER_CLASS_IN_APP_AI);
if (!$verdict['granted']) {
    // do not run AI over this user's data
}
```

Consent is orthogonal to revocation: a denied verdict means your app returns its own 403; the connection and token stay valid so the user can flip consent back on without re-connecting. Write switches through `PUT /api/v1/consent/settings` from your backend; export the audit trail with `GET /api/v1/consent/export` (every plan).

**One-middleware drop-in.** Instead of wiring the three paths by hand, the `agentadmit.caller_consent` middleware classifies the caller from the credential and evaluates the right independent path:

```php
// config/agentadmit.php
'caller_consent' => [
    // derive the class from your own credential structure, never caller input
    'classify_non_agent' => fn ($request) => $request->headers->get('x-internal-ai') === env('INTERNAL_AI_SECRET')
        ? 'in_app_ai' : 'human_session',
    'resolve_data_owner_id' => fn ($request) => $request->route('owner_id'),
],

// routes: the middleware parameter is the required scope for external agents
Route::middleware('agentadmit.caller_consent:read:records')
    ->get('/api/records/{owner_id}', ...);
// Downstream: $request->attributes->get('agentadmit.caller_class' / 'agentadmit.consent')
```

External agents are checked via hosted introspection (consent verdict plus scope); in-app AI via the Consent Ledger (fail closed); the human path defers to your own permission model unless `caller_consent.gate_human` is true. It is a consent gate, not an authenticator, so register it after your own authentication.

## Presence Verification (WebAuthn Step-Up)

AgentAdmit can require the human behind a connection to complete a WebAuthn presence ceremony on the consent page. The verify result carries the outcome as an additive `presence` block, and the SDK surfaces it next to the consent verdict:

```php
$result = $introspectionClient->verify($token);
if (!$result->presenceVerified()) {
    abort(403, 'This action requires a connection authorized with human presence verification.');
}
```

Or enforce it per route with the fail-closed middleware:

```php
// routes/api.php
Route::middleware('agentadmit.presence')->post('/orders', [OrderController::class, 'store']);
```

`presenceVerified()` is strict: it returns `true` only when the platform reports `verified: true`. Connections minted without a ceremony, malformed blocks, and older servers that omit the block entirely all count as not verified, so guarded routes return a 403 with `error: presence_required`. Unlike consent, absence does not mean allowed: presence fails closed because a missing block means no ceremony was ever proven.

## Declared Purpose

Declared purpose: the user-facing reason recorded on the grant at the consent moment. Review-time record only, never an enforcement input; authorization decisions ride scopes, connection status, and consent.

Pass an optional `purpose` (max 300 characters) when issuing a connection token. AgentAdmit shows it to the human on the consent page ("Declared purpose: …"), records it on the grant, stamps it into every audit log row, and returns it from `/verify` introspection:

```php
$issued = $tokens->issueToken(
    'user_42',
    ['read:orders'],
    purpose: 'Reorder the usual weekly groceries',
);
```

The SDK rejects purposes longer than 300 characters client-side with an `InvalidArgumentException`; when you pass no purpose, the field is omitted from the request entirely.

On the verify side, the result carries the nullable purpose for display and review:

```php
$result = $introspectionClient->verify($token);
$result->purpose; // 'Reorder the usual weekly groceries', or null when none was declared
```

`purpose` is `null` for connections minted without one and on older servers that omit the field. Do not branch authorization on it  -  `/verify` never gates on the purpose, and neither should your app.

## User-Declared Intent

User-declared intent: the user's own words, typed by the human at the consent moment. It is distinct from `purpose`  -  `purpose` is the app's words, `user_intent` is the user's. Like the declared purpose, it is a review-time record only, never an enforcement input; authorization decisions ride scopes, connection status, and consent.

Pass an optional `user_intent` (1-300 characters) when issuing a connection token. It flows exactly like the declared purpose: recorded on the grant, returned from `/verify` introspection, stamped into audit log rows, and carried on ledger events. When the hosted presence ceremony runs, the user-declared intent is included in the verifiable-consent-evidence commitment.

```php
$issued = $tokens->issueToken(
    'user_42',
    ['read:orders'],
    purpose: 'Reorder the usual weekly groceries', // the app's words
    userIntent: 'get my usual Tuesday order',      // the user's own words
);
```

Outbound validation mirrors `purpose`: a `user_intent` longer than 300 characters, or any non-string, non-null value, throws `InvalidArgumentException` client-side before any request is sent  -  the user's own typed words are never silently discarded. `null` and the empty string are simply omitted from the request. (Verify-side parsing stays tolerant: a malformed `user_intent` in the `/verify` response is normalized to `null`, never a failure.)

On the verify side, the result carries the nullable user-declared intent for display and review:

```php
$result = $introspectionClient->verify($token);
$result->userIntent; // 'get my usual Tuesday order', or null when none was declared
```

`userIntent` is `null` for connections minted without one and on older servers that omit the field. Do not branch authorization on it  -  like the purpose, `/verify` never gates on it, and neither should your app.

## App-Attested Presence

If your app gates token minting behind its own embedded passkey/WebAuthn ceremony, AgentAdmit never witnesses that ceremony (it is origin-bound), so by default the hosted service reports `presence.verified: false` for those connections. Attest the ceremony fact at issuance to close that gap  -  AFTER verifying and consuming your own fresh, purpose-bound attestation:

```php
use AgentAdmit\AppAttestedPresence;

$issued = $tokensClient->issueToken(
    'user_42',
    ['read:orders'],
    presence: new AppAttestedPresence('my_webauthn', $attestation->createdAt)
);
```

The SDK sends it as `presence: {verified: true, uv: true, method, verified_at}`  -  `verified`/`uv` are literal true by construction and the class cannot represent anything else. The hosted service validates freshness (10-minute window, 60 s future clock-skew slack) and stores the method provenance-marked `app:<method>` so app-attested facts stay distinct from ceremonies AgentAdmit witnessed itself. Introspection, the grant-event ledger, and the evidence API then carry `presence.verified: true` for the connection.

Honesty ceiling: this is your app's attestation, recorded and provenance-marked. It is not witnessed by AgentAdmit and not independently verifiable. Only attest a ceremony that verified the user with UV (biometric or PIN user verification); a ceremony without UV carries no presence fact, so pass `null` (the default). An out-of-contract method (`^[a-z0-9_]+$`, 1-60) throws `InvalidArgumentException` at construction, before any request; `verified_at` serializes RFC 3339 with an explicit offset because `DateTimeInterface` always carries a timezone.

## Rate Limiting

The AgentAdmit introspection endpoint enforces rate limits. The PHP SDK handles HTTP 429 responses **automatically** with exponential backoff and jitter  -  no changes needed in your middleware code.

### Retry behavior

| Parameter | Default | Description |
|-----------|---------|-------------|
| Initial delay | 1 second | First retry wait |
| Backoff multiplier | 2× | Doubles each retry |
| Cap | 30 seconds | Maximum wait per retry |
| Jitter | 0–500 ms | Random addition to each delay |
| Max retries | **3** | Configurable |

The SDK also respects the `Retry-After` response header  -  if present, it overrides the computed backoff delay.

### Configuring max retries

In `config/agentadmit.php` or `.env`:

```php
// config/agentadmit.php
'max_retries' => 5, // default: 3
```

```env
AGENTADMIT_MAX_RETRIES=5
```

### Handling exhausted retries

When all retries are exhausted, `IntrospectionClient::verify()` throws `RateLimitException`:

```php
use AgentAdmit\RateLimitException;

try {
    $result = $client->verify($token);
} catch (RateLimitException $e) {
    return response()->json(['error' => 'rate_limited'], 429)
        ->header('Retry-After', $e->getRetryAfter() ?? 60);
}
```

`RateLimitException` methods:
- `getRetryAfter()`  -  seconds from `Retry-After` header (`null` if absent)
- `getLimit()`  -  `X-RateLimit-Limit` header value (`null` if absent)
- `getRemaining()`  -  `X-RateLimit-Remaining` header value (`null` if absent)
- `getReset()`  -  `X-RateLimit-Reset` Unix timestamp (`null` if absent)

## Documentation

Full integration guide: https://agentadmit.com/docs/app-owner-guide


## Data Collection & Privacy

The AgentAdmit PHP SDK runs server-side and does not interact with app stores or end-user devices directly.

### What the SDK does
- Validates AgentAdmit tokens by calling AgentAdmit's hosted introspection endpoint (`https://api.agentadmit.com/api/v1/verify`) on every agent request  -  this is mandatory introspection; there is no local or offline validation mode
- Enforces scope-based access control on your API routes
- Manages connection lifecycle (issue, exchange, revoke) via the AgentAdmit hosted service

### What the SDK does NOT do
- Does not transmit raw end-user PII (such as name, email, or device identifiers)  -  each introspection request sends the opaque access token and your API key
- Does not perform passive background telemetry or analytics  -  network calls occur only during active token validation
- Does not maintain its own persistent storage; connection state and audit logs are held by the AgentAdmit hosted service

### What the AgentAdmit hosted service records
On every token validation, AgentAdmit's `/api/v1/verify` endpoint receives the access token and API key, resolves the token to its `user_id`, `connection_id`, granted `scopes`, and `agent_label`, and records per-call metadata (including the endpoint and timestamp) for billing, audit logging, the security alerts engine, and usage metering. This is integral to how AgentAdmit works and applies to both test and live keys. See the "Mandatory introspection" notes above and the [compliance guide](https://agentadmit.com/docs/compliance) for the full data-handling description.

### Privacy impact
Since this SDK runs on your server, it has no direct App Store or Play Store compliance surface. Your client-side integration (e.g., the AgentAdmit React SDK) handles privacy manifest and data safety requirements.

For complete compliance guidance, see our [compliance guide](https://agentadmit.com/docs/compliance).

## License

All rights reserved. Patent pending.

## Security Alerts

```php
use AgentAdmit\AlertsClient;
$alerts = new AlertsClient(config('agentadmit'));
```

Six alert type constants on `AlertsClient`. 

### Configure

```php
$alerts->configureAlerts('app_abc123', AlertsClient::ALERT_TYPE_VOLUME_SPIKE, [
    'enabled' => true, 'threshold_value' => 100, 'threshold_window_minutes' => 5,
    'kill_switch_enabled' => true,
]);
```

### List Events

```php
$events = $alerts->listAlerts(appId: 'app_abc123', alertType: AlertsClient::ALERT_TYPE_VOLUME_SPIKE);
```

### Get Config

```php
$config = $alerts->getAlertConfig(appId: 'app_abc123');
```


### Notifying Your Users

AgentAdmit detects anomalies, fires alerts, and (with kill switch) auto-revokes connections. **How you notify your own users is up to you.** AgentAdmit provides the data  -  you deliver it through your own system (in-app notifications, email, push, etc.).

- **Poll alerts**  -  Use the SDK methods above from your backend to check for new events, then notify users through your existing system.
- **Webhook delivery**  -  Configure a webhook URL in your AgentAdmit dashboard. When an alert fires, AgentAdmit POSTs the payload to your server, signed with your `whsec_…` secret. The payload carries `alert_id`, `alert_type`, `severity`, the connection's `agent_label`, and the grant's declared `purpose`; the full shape is documented in the Webhook Delivery section of the MCP guide at https://agentadmit.com/docs/mcp-guide. Always verify the signature against the raw request body before trusting the payload:

  ```php
  use AgentAdmit\Webhook;
  use AgentAdmit\AgentAdmitException;

  Route::post('/agentadmit/alerts', function (Request $request) {
      try {
          Webhook::verifySignature(
              $request->getContent(),
              $request->header('X-AgentAdmit-Signature', ''),
              config('agentadmit.webhook_secret'), // whsec_… from AGENTADMIT_WEBHOOK_SECRET
          );
      } catch (AgentAdmitException $e) {
          return response()->json(['error' => 'invalid_signature'], 400);
      }
      $event = $request->json()->all();
      // ...
  });
  ```

  The header format is `t=<unix_ts>,v1=<hex>`  -  an HMAC-SHA256 of `{t}.{rawBody}` keyed with your signing secret. Verification uses `hash_equals()` (constant time) and rejects timestamps more than 5 minutes off (replay protection).
- **React SDK**  -  Embed the `<AlertsPanel>` component so users can view their own alert history and tighten thresholds.

### Issuing & Exchanging Tokens

```php
use AgentAdmit\TokensClient;

$tokens = app(TokensClient::class);

// Duration is tri-state:
//   omit the argument                     → AgentAdmit default (30 days)
//   null                                  → until the user revokes
//   int seconds (60–31536000)             → explicit duration
// The optional purpose (max 300 chars) is shown to the human at the consent
// moment and recorded on the grant — see "Declared Purpose" above. The
// optional userIntent (1-300 chars) is the user's own words — see
// "User-Declared Intent" above.
$issued = $tokens->issueToken(
    'user_42',
    ['read:orders'],
    role: 'user',
    durationSeconds: null,
    purpose: 'Reorder the usual weekly groceries',
    userIntent: 'get my usual Tuesday order',
);
$connectionToken = $issued['token']; // ag_ct_…

// Agent side  -  no API key needed; the connection token is the credential.
$granted = $tokens->exchange($connectionToken, agentLabel: 'MyAssistant');

// Revoke when the user disconnects the agent.
$tokens->revoke($granted['connection_id'], reason: 'user_requested');
```
