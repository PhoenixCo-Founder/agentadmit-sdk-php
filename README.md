# AgentAdmit SDK for PHP (Laravel)

User-mediated AI agent authorization. Plug-and-play for any Laravel app.

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

## License

All rights reserved. Patent pending.
