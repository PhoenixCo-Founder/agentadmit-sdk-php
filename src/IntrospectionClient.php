<?php

namespace AgentAdmit;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

/**
 * Mandatory introspection client — validates tokens via AgentAdmit hosted service.
 * No local JWT decode. Every verification call goes through AgentAdmit.
 */
class IntrospectionClient
{
    /** Hard cap (ms) on any single retry wait — including a server-supplied Retry-After. */
    public const MAX_RETRY_WAIT_MS = 30000;

    /** Hard cap (ms) on cumulative wait across all retries of a single verify call. */
    public const MAX_RETRY_BUDGET_MS = 120000;

    /**
     * Error codes /api/v1/verify returns with HTTP 200 and active: false
     * (insufficient_scope arrives with active: true — token valid, scope not
     * granted). Unknown codes pass through unchanged.
     */
    public const ERROR_INVALID_TOKEN        = 'invalid_token';
    public const ERROR_TOKEN_EXPIRED        = 'token_expired';
    public const ERROR_TOKEN_REVOKED        = 'token_revoked';
    public const ERROR_CONNECTION_REVOKED   = 'connection_revoked';
    public const ERROR_CONNECTION_EXPIRED   = 'connection_expired';
    public const ERROR_ENVIRONMENT_MISMATCH = 'environment_mismatch';
    public const ERROR_INSUFFICIENT_SCOPE   = 'insufficient_scope';

    /** Hosted cap on the reported endpoint path (chars). */
    public const MAX_ENDPOINT_LENGTH = 500;

    /** Hosted cap on the reported HTTP method (chars). */
    public const MAX_METHOD_LENGTH = 20;

    private array $config;

    public function __construct(array $config)
    {
        $this->config = $config;

        // Validate the key prefix without ever echoing the key itself.
        $apiKey = $config['api_key'] ?? '';
        if ($apiKey !== '' && !str_starts_with($apiKey, 'aa_test_') && !str_starts_with($apiKey, 'aa_live_')) {
            throw new AgentAdmitException("api_key must start with 'aa_test_' or 'aa_live_'", 401);
        }

        // M4: Require HTTPS on configurable URLs (HTTP allowed only on loopback).
        $verifyUrl = $config['verify_url'] ?? 'https://api.agentadmit.com/api/v1/verify';
        AgentAdmitException::assertHttpsUrl($verifyUrl, 'verify_url');
    }

    /**
     * Validate an ag_at_ token via introspection.
     *
     * Automatically retries on HTTP 429 with exponential backoff + jitter.
     * Throws {@see RateLimitException} when retries are exhausted.
     *
     * SDK 1.10 per-call audit telemetry: the three optional parameters ride in
     * the verify body so the hosted audit log records what each call actually
     * exercised. Each is sent when known and omitted entirely when not (never
     * null / empty string):
     *
     *  - $scopeUsed: the single scope the integration point enforces for THIS
     *    call (the scope-middleware parameter). Omit for presence-only gates
     *    and bare auth resolution. Never a joined list.
     *  - $endpoint:  the inbound request path. The client strips any query
     *    string (queries can carry PII) and truncates to 500 chars.
     *  - $method:    the HTTP method; uppercased, capped at 20 chars.
     *
     * @param string      $token     The full token including ag_at_ prefix
     * @param string|null $scopeUsed Single scope enforced for this call, when known
     * @param string|null $endpoint  Inbound request path (query stripped client-side)
     * @param string|null $method    Inbound HTTP method
     * @return IntrospectionResult
     * @throws VerificationDeniedException When the hosted service refuses an
     *                                     otherwise-active call (active: true
     *                                     with a string error field)
     * @throws AgentAdmitException
     * @throws RateLimitException
     */
    public function verify(
        string $token,
        ?string $scopeUsed = null,
        ?string $endpoint = null,
        ?string $method = null
    ): IntrospectionResult {
        $prefix = $this->config['token_prefix_access'] ?? 'ag_at_';

        if (!str_starts_with($token, $prefix)) {
            throw new AgentAdmitException('Not an AgentAdmit access token', 401);
        }

        $maxRetries = (int) ($this->config['max_retries'] ?? 3);
        $verifyUrl  = $this->config['verify_url'] ?? 'https://api.agentadmit.com/api/v1/verify';
        $delayMs    = 1000; // initial backoff: 1 second (in ms)
        $waitedMs   = 0;    // cumulative wait across retries
        $body       = $this->buildVerifyBody($token, $scopeUsed, $endpoint, $method);

        for ($attempt = 0; $attempt <= $maxRetries; $attempt++) {
            try {
                $response = Http::timeout(5)
                    ->withHeaders([
                        'Authorization' => 'Bearer ' . ($this->config['api_key'] ?? ''),
                        'Content-Type' => 'application/json',
                    ])
                    ->post($verifyUrl, $body);
            } catch (\Exception $e) {
                Log::error('AgentAdmit introspection failed: ' . $e->getMessage());
                throw new AgentAdmitException('Introspection failed: ' . $e->getMessage(), 502);
            }

            $status = $response->status();

            if ($status === 429) {
                // Parse rate-limit headers
                $retryAfter = $this->parseFloatHeader($response, 'Retry-After');
                $rlLimit    = $this->parseIntHeader($response, 'X-RateLimit-Limit');
                $rlRemaining = $this->parseIntHeader($response, 'X-RateLimit-Remaining');
                $rlReset    = $this->parseIntHeader($response, 'X-RateLimit-Reset');

                if ($attempt >= $maxRetries) {
                    throw new RateLimitException(
                        "AgentAdmit rate limit exceeded. Max retries ({$maxRetries}) exhausted.",
                        $retryAfter,
                        $rlLimit,
                        $rlRemaining,
                        $rlReset
                    );
                }

                // Compute wait: Retry-After beats exponential backoff, but both
                // are capped — Retry-After is untrusted server input and must
                // not pin the caller.
                $requestedMs = $retryAfter !== null ? (int)($retryAfter * 1000) : $delayMs;
                $waitMs  = min(max(0, $requestedMs), self::MAX_RETRY_WAIT_MS);
                $jitterMs = random_int(0, 500);
                $totalMs  = $waitMs + $jitterMs;

                if ($waitedMs + $totalMs > self::MAX_RETRY_BUDGET_MS) {
                    throw new RateLimitException(
                        'AgentAdmit rate limit retry budget (' . (self::MAX_RETRY_BUDGET_MS / 1000) . 's) exhausted.',
                        $retryAfter,
                        $rlLimit,
                        $rlRemaining,
                        $rlReset
                    );
                }
                $waitedMs += $totalMs;

                Log::warning(
                    "AgentAdmit introspection rate-limited (attempt " . ($attempt + 1) . "/{$maxRetries}). " .
                    "Retrying in {$totalMs}ms."
                );

                $this->waitBeforeRetry($totalMs);
                $delayMs = min($delayMs * 2, 30000);
                continue;
            }

            // Non-429 response
            try {
                if ($status === 401) {
                    $data = $response->json();
                    throw new AgentAdmitException(
                        $data['error_description'] ?? 'Token validation failed',
                        401
                    );
                }

                // M5: Treat any non-2xx response as a service error.
                if ($status < 200 || $status > 299) {
                    throw new AgentAdmitException(
                        'Verification service returned ' . $status,
                        502
                    );
                }

                $data = $response->json();

                // M5: Require active to be strictly the boolean true (RFC 7662).
                // Any other value — false, 1, "true", null, missing — means invalid.
                if (($data['active'] ?? null) !== true) {
                    $reason = $data['error'] ?? self::ERROR_INVALID_TOKEN;
                    throw new AgentAdmitException('Token is not active: ' . $reason, 401, $reason);
                }

                // SDK 1.10 fail-closed: an active response that carries a
                // string error field is a DENIAL, never a pass-through. The
                // token is valid but the hosted service refused THIS call -
                // insufficient_scope (scope not granted), bound_exceeded
                // (bounded capability exhausted), or any refusal class this
                // SDK version does not know yet. Generalizes the previous
                // insufficient_scope-only special case: 1.9.0 checked only
                // `active` and allowed bound-exceeded calls through.
                $activeError = $data['error'] ?? null;
                if (is_string($activeError) && $activeError !== '') {
                    throw VerificationDeniedException::fromActiveError($activeError, $data, $scopeUsed);
                }

                // M5: Validate consumed string fields and scopes type.
                $this->assertValidIntrospectionPayload($data);

                return new IntrospectionResult(
                    userId: $data['user_id'],
                    connectionId: isset($data['connection_id']) ? (string) $data['connection_id'] : null,
                    scopes: $data['scopes'] ?? [],
                    agentLabel: $data['agent_label'] ?? 'Unknown Agent',
                    sub: $data['sub'] ?? null,
                    role: $data['role'] ?? null,
                    appId: $data['app_id'] ?? null,
                    jti: $data['jti'] ?? null,
                    exp: isset($data['exp']) ? (int) $data['exp'] : null,
                    // Absent (or explicit null) consent stays null - the
                    // hosted service omits the block when its consent-store
                    // read fails (designed degraded mode), so null means
                    // UNRESOLVED, never granted; the CallerConsent middleware
                    // resolves it through the Consent Ledger. A present
                    // consent block is passed through so consentGranted() can
                    // fail closed on a missing or non-boolean 'granted'; a
                    // present non-array block is normalized to [] which is
                    // also denied.
                    consent: isset($data['consent'])
                        ? (is_array($data['consent']) ? $data['consent'] : [])
                        : null,
                    // Human-presence fact rides along when the platform
                    // returns it (additive; absent on older servers). Same
                    // strictness as 'active': the block must be an array and
                    // 'verified' must be strictly boolean, never coerced.
                    // Anything else is treated as absent, so
                    // presenceVerified() fails closed.
                    presence: isset($data['presence'])
                        && is_array($data['presence'])
                        && is_bool($data['presence']['verified'] ?? null)
                        ? $data['presence']
                        : null,
                    // Declared purpose rides along when the platform returns
                    // it (additive; nullable). Review-time record only, never
                    // an enforcement input, so a malformed (non-string) value
                    // is treated as absent rather than failing the verify.
                    purpose: isset($data['purpose']) && is_string($data['purpose'])
                        ? $data['purpose']
                        : null,
                    // User-declared intent rides along when the platform
                    // returns it (additive; nullable) — the USER's own words,
                    // distinct from purpose (the app's words). Same tolerance
                    // as purpose: a malformed (non-string) value is treated
                    // as absent rather than failing the verify.
                    userIntent: isset($data['user_intent']) && is_string($data['user_intent'])
                        ? $data['user_intent']
                        : null,
                );
            } catch (AgentAdmitException $e) {
                throw $e;
            } catch (\Exception $e) {
                Log::error('AgentAdmit introspection failed: ' . $e->getMessage());
                throw new AgentAdmitException('Introspection failed: ' . $e->getMessage(), 502);
            }
        }

        // Should never be reached
        throw new AgentAdmitException('Unexpected exit from retry loop', 500);
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * SDK 1.10: build the verify POST body - the token plus the optional
     * per-call audit telemetry. Every telemetry field is sent only when known
     * and omitted entirely otherwise (never null / empty string):
     *
     *  - scope_used: passed through as given (the single enforced scope).
     *  - endpoint:   path only - everything from the first '?' or '#' on is
     *    stripped client-side (query strings can carry PII), then truncated
     *    to {@see MAX_ENDPOINT_LENGTH} chars.
     *  - method:     uppercased, truncated to {@see MAX_METHOD_LENGTH} chars.
     */
    private function buildVerifyBody(
        string $token,
        ?string $scopeUsed,
        ?string $endpoint,
        ?string $method
    ): array {
        $body = ['token' => $token];

        if ($scopeUsed !== null && $scopeUsed !== '') {
            $body['scope_used'] = $scopeUsed;
        }

        if ($endpoint !== null && $endpoint !== '') {
            $path = $endpoint;
            foreach (['?', '#'] as $sep) {
                $pos = strpos($path, $sep);
                if ($pos !== false) {
                    $path = substr($path, 0, $pos);
                }
            }
            $path = substr($path, 0, self::MAX_ENDPOINT_LENGTH);
            if ($path !== '') {
                $body['endpoint'] = $path;
            }
        }

        if ($method !== null && $method !== '') {
            $body['method'] = substr(strtoupper($method), 0, self::MAX_METHOD_LENGTH);
        }

        return $body;
    }

    /**
     * M5: Validate the introspection payload structure.
     *
     * Throws AgentAdmitException if required fields are missing or have the
     * wrong type. Only called after active === true has been confirmed.
     *
     * Rules:
     *  - user_id must be present and a non-empty string
     *  - agent_id, connection_id must be strings when present
     *  - scopes must be an array of strings when present
     *
     * @throws AgentAdmitException
     */
    private function assertValidIntrospectionPayload(array $data): void
    {
        // user_id is required and must be a non-empty string.
        if (!isset($data['user_id']) || !is_string($data['user_id']) || $data['user_id'] === '') {
            throw new AgentAdmitException('Introspection returned no user', 401);
        }

        // agent_id must be a string when present.
        if (isset($data['agent_id']) && !is_string($data['agent_id'])) {
            throw new AgentAdmitException('Introspection response malformed: agent_id must be a string', 502);
        }

        // connection_id must be a string when present.
        if (isset($data['connection_id']) && !is_string($data['connection_id'])) {
            throw new AgentAdmitException('Introspection response malformed: connection_id must be a string', 502);
        }

        // scopes must be an array of strings when present.
        if (isset($data['scopes'])) {
            if (!is_array($data['scopes'])) {
                throw new AgentAdmitException('Introspection response malformed: scopes must be an array', 502);
            }
            foreach ($data['scopes'] as $scope) {
                if (!is_string($scope)) {
                    throw new AgentAdmitException('Introspection response malformed: each scope must be a string', 502);
                }
            }
        }
    }

    /** Sleep before the next retry. Protected so tests can record instead of sleeping. */
    protected function waitBeforeRetry(int $totalMs): void
    {
        usleep($totalMs * 1000); // usleep takes microseconds
    }

    /** Parse a float response header, returning null if absent or non-numeric. */
    private function parseFloatHeader(\Illuminate\Http\Client\Response $response, string $name): ?float
    {
        $val = $response->header($name);
        if ($val === null || $val === '') {
            return null;
        }
        return is_numeric($val) ? (float) $val : null;
    }

    /** Parse an int response header, returning null if absent or non-numeric. */
    private function parseIntHeader(\Illuminate\Http\Client\Response $response, string $name): ?int
    {
        $val = $response->header($name);
        if ($val === null || $val === '') {
            return null;
        }
        return is_numeric($val) ? (int) $val : null;
    }
}
