# AgentAdmit SDK for PHP (Laravel)

User-mediated AI agent authorization. Plug-and-play for any Laravel app.

> **Get started:** Sign up at [agentadmit.com](https://agentadmit.com) → Get your test keys → Install the SDK → Build.
> Test keys are available immediately after signup. Live keys become available when you subscribe an app.

## Quick Start

```bash
composer require agentadmit/laravel
php artisan vendor:publish --tag=agentadmit
```

Add your credentials to `.env`:

```env
AGENTADMIT_APP_ID=app_yourappid
AGENTADMIT_API_KEY=aa_test_yourkey
```

Add scope enforcement to any route:

```php
// routes/api.php
Route::middleware('agentadmit:read:orders')->get('/orders', [OrderController::class, 'index']);
```

Your app now supports AI agent connections with:
- Scoped access control (you define the scopes)
- User-controlled connection duration
- Token generation and exchange
- Mandatory introspection (every agent request validated through AgentAdmit)
- Revocation and audit logging
- Discovery endpoint at `/.well-known/agentadmit`

## How It Works

1. User clicks "AgentAdmit" in your app
2. Selects scopes and connection duration
3. Gets a token to give to their AI agent
4. Agent exchanges the token for scoped API access
5. User revokes anytime

The token goes to the human, not the agent. No automated delivery = no prompt injection surface.

## Important

**Mandatory introspection.** All token validation goes through api.agentadmit.com. There is no self-hosted mode. No local JWT validation. No bypass. This is required for security, audit logging, and scope enforcement.

**Admin revocation.** As the app operator, you can revoke any user's agent connection via `DELETE /agentadmit/admin/connections/{connection_id}` (requires admin role or `manage:connections` scope).

**Embeddable admin panel.** Drop the `<AgentAdmitAdminPanel>` React component into your admin section to view all agent connections, usage metrics, billing status, and revoke any connection without leaving your app. See the React SDK for details.

**In-app AI scopes.** If your app has built-in AI features (analysis, plan generation, photo recognition), do not expose those as agent scopes. The user's AI agent can read the raw data and do the analysis itself. Exposing in-app AI endpoints to agents creates double cost.

## Rate Limiting

The AgentAdmit introspection endpoint enforces rate limits. The PHP SDK handles HTTP 429 responses **automatically** with exponential backoff and jitter — no changes needed in your middleware code.

### Retry behavior

| Parameter | Default | Description |
|-----------|---------|-------------|
| Initial delay | 1 second | First retry wait |
| Backoff multiplier | 2× | Doubles each retry |
| Cap | 30 seconds | Maximum wait per retry |
| Jitter | 0–500 ms | Random addition to each delay |
| Max retries | **3** | Configurable |

The SDK also respects the `Retry-After` response header — if present, it overrides the computed backoff delay.

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
- `getRetryAfter()` — seconds from `Retry-After` header (`null` if absent)
- `getLimit()` — `X-RateLimit-Limit` header value (`null` if absent)
- `getRemaining()` — `X-RateLimit-Remaining` header value (`null` if absent)
- `getReset()` — `X-RateLimit-Reset` Unix timestamp (`null` if absent)

## Documentation

Full integration guide: https://agentadmit.com/docs/app-owner-guide


## Data Collection & Privacy

The AgentAdmit PHP SDK runs server-side and does not interact with app stores or end-user devices directly.

### What the SDK does
- Validates AgentAdmit tokens by calling AgentAdmit's hosted introspection endpoint (`https://api.agentadmit.com/api/v1/verify`) on every agent request — this is mandatory introspection; there is no local or offline validation mode
- Enforces scope-based access control on your API routes
- Manages connection lifecycle (create, revoke, audit) using your configured storage backend

### What the SDK does NOT do
- Does not transmit raw end-user PII (such as name, email, or device identifiers) — each introspection request sends the opaque access token and your API key
- Does not perform passive background telemetry or analytics — network calls occur only during active token validation
- Does not maintain its own persistent storage — local state (connections, audit log) lives in the storage backend you configure

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

AgentAdmit detects anomalies, fires alerts, and (with kill switch) auto-revokes connections. **How you notify your own users is up to you.** AgentAdmit provides the data — you deliver it through your own system (in-app notifications, email, push, etc.).

- **Poll alerts** — Use the SDK methods above from your backend to check for new events, then notify users through your existing system.
- **Webhook delivery** — Configure a webhook URL in your AgentAdmit dashboard. When an alert fires, AgentAdmit POSTs the payload to your server, signed with your `whsec_…` secret. Always verify the signature against the raw request body before trusting the payload:

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

  The header format is `t=<unix_ts>,v1=<hex>` — an HMAC-SHA256 of `{t}.{rawBody}` keyed with your signing secret. Verification uses `hash_equals()` (constant time) and rejects timestamps more than 5 minutes off (replay protection).
- **React SDK** — Embed the `<AlertsPanel>` component so users can view their own alert history and tighten thresholds.

### Issuing & Exchanging Tokens

```php
use AgentAdmit\TokensClient;

$tokens = app(TokensClient::class);

// Duration is tri-state:
//   omit the argument                     → AgentAdmit default (30 days)
//   null                                  → until the user revokes
//   int seconds (60–31536000)             → explicit duration
$issued = $tokens->issueToken('user_42', ['read:orders'], role: 'user', durationSeconds: null);
$connectionToken = $issued['token']; // ag_ct_…

// Agent side — no API key needed; the connection token is the credential.
$granted = $tokens->exchange($connectionToken, agentLabel: 'MyAssistant');

// Revoke when the user disconnects the agent.
$tokens->revoke($granted['connection_id'], reason: 'user_requested');
```
