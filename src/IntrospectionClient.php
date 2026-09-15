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

    /**
     * SDK 1.11 confirm-each-time: the token and scope are fine, but THIS call
     * needs a fresh human confirmation. Arrives with active: true, so it is a
     * refusal like insufficient_scope. See ConfirmationRequiredException.
     */
    public const ERROR_CONFIRMATION_REQUIRED = 'confirmation_required';

    /** Hosted defaults; a non-default api_url derives verify_url (see __construct). */
    public const DEFAULT_API_URL    = 'https://api.agentadmit.com';
    public const DEFAULT_VERIFY_URL = 'https://api.agentadmit.com/api/v1/verify';

    /** Hosted cap on the reported endpoint path (chars). */
    public const MAX_ENDPOINT_LENGTH = 500;

    /** Hosted cap on the reported HTTP method (chars). */
    public const MAX_METHOD_LENGTH = 20;

    /** Hosted cap on the confirm-each-time attestation id (chars). */
    public const MAX_ATTESTATION_LENGTH = 120;

    /** Hosted cap on the request digest (chars). */
    public const MAX_DIGEST_LENGTH = 128;

    /** Hosted cap on the app-supplied action summary (chars). */
    public const MAX_SUMMARY_LENGTH = 200;

    /**
     * Request header an agent sets on its retry after the human confirmed.
     * Read case-insensitively from the inbound request; the SDK forwards it
     * as action_attestation_id on the verify call.
     */
    public const ACTION_ATTESTATION_HEADER = 'X-AgentAdmit-Action-Attestation';

    private array $config;

    public function __construct(array $config)
    {
        $this->config = $config;

        // Validate the key prefix without ever echoing the key itself.
        $apiKey = $config['api_key'] ?? '';
        if ($apiKey !== '' && !str_starts_with($apiKey, 'aa_test_') && !str_starts_with($apiKey, 'aa_live_')) {
            throw new AgentAdmitException("api_key must start with 'aa_test_' or 'aa_live_'", 401);
        }

        // One hosted-service origin, not two (1.11). An operator who points
        // api_url somewhere else (staging, a local rig) and leaves verify_url
        // at its default expects verify to follow - otherwise every per-call
        // verify silently goes to production while the rest of the SDK talks
        // to the other service (caught on the TT dogfood rig, Sep 3, 2026).
        // An explicitly set verify_url always wins.
        $verifyUrl = $config['verify_url'] ?? self::DEFAULT_VERIFY_URL;
        $apiUrl    = $config['api_url'] ?? null;
        if (
            is_string($verifyUrl)
            && rtrim($verifyUrl, '/') === self::DEFAULT_VERIFY_URL
            && is_string($apiUrl)
            && $apiUrl !== ''
            && rtrim($apiUrl, '/') !== self::DEFAULT_API_URL
        ) {
            $verifyUrl = rtrim($apiUrl, '/') . '/api/v1/verify';
        }

        // M4: Require HTTPS on configurable URLs (HTTP allowed only on loopback).
        AgentAdmitException::assertHttpsUrl($verifyUrl, 'verify_url');
        $this->config['verify_url'] = $verifyUrl;
    }

    /**
     * The verify endpoint this client actually calls, after a non-default
     * api_url has been allowed to derive it.
     */
    public function getVerifyUrl(): string
    {
        return $this->config['verify_url'];
    }

    /**
     * SDK 1.11: the agent's X-AgentAdmit-Action-Attestation header, trimmed
     * and capped, or null when absent/blank. Laravel's HeaderBag lookup is
     * case-insensitive and returns the first value.
     */
    public static function attestationFromRequest(\Illuminate\Http\Request $request): ?string
    {
        $value = $request->headers->get(self::ACTION_ATTESTATION_HEADER);
        if (!is_string($value) || trim($value) === '') {
            return null;
        }

        return substr(trim($value), 0, self::MAX_ATTESTATION_LENGTH);
    }

    /**
     * SDK 1.11: "sha256:<hex>" over the RAW request body bytes, so the human's
     * confirmation covers the exact payload and not merely the route. Null for
     * an empty body (GET and friends).
     */
    public static function requestDigestFor(?string $rawBody): ?string
    {
        if ($rawBody === null || $rawBody === '') {
            return null;
        }

        return 'sha256:' . hash('sha256', $rawBody);
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
     * @param bool        $consentFirst Resolve caller-class consent before scope evaluation
     *
     * SDK 1.11 confirm-each-time telemetry (all optional, all omitted when
     * unknown):
     *
     *  - $actionAttestationId: the single-use id from a completed hosted
     *    confirmation ceremony, presented by the agent on its retry via the
     *    X-AgentAdmit-Action-Attestation header (cap 120).
     *  - $requestDigest: "sha256:<hex>" over the raw request body, so the
     *    confirmation covers the exact payload, not just the route (cap 128).
     *  - $actionSummary: the app's plain-language description of THIS action,
     *    shown to the human on the hosted confirmation page and committed into
     *    the signature (cap 200). AgentAdmit does not verify the summary
     *    against the request; it proves what the human was shown.
     *
     * @param string|null $actionAttestationId Attestation id from the agent's retry header
     * @param string|null $requestDigest       sha256: digest of the raw request body
     * @param string|null $actionSummary       Plain-language description of this action
     * @return IntrospectionResult
     * @throws VerificationDeniedException When the hosted service refuses an
     *                                     otherwise-active call (active: true
     *                                     with a string error field); the
     *                                     ConfirmationRequiredException
     *                                     subclass carries the staged
     *                                     confirmation ceremony (1.11)
     * @throws AgentAdmitException
     * @throws RateLimitException
     */
    public function verify(
        string $token,
        ?string $scopeUsed = null,
        ?string $endpoint = null,
        ?string $method = null,
        bool $consentFirst = false,
        ?string $actionAttestationId = null,
        ?string $requestDigest = null,
        ?string $actionSummary = null
    ): IntrospectionResult {
        $prefix = $this->config['token_prefix_access'] ?? 'ag_at_';

        if (!str_starts_with($token, $prefix)) {
            throw new AgentAdmitException('Not an AgentAdmit access token', 401);
        }

        $maxRetries = (int) ($this->config['max_retries'] ?? 3);
        $verifyUrl  = $this->config['verify_url'] ?? self::DEFAULT_VERIFY_URL;
        $delayMs    = 1000; // initial backoff: 1 second (in ms)
        $waitedMs   = 0;    // cumulative wait across retries
        $body       = $this->buildVerifyBody(
            $token,
            $scopeUsed,
            $endpoint,
            $method,
            $consentFirst,
            $actionAttestationId,
            $requestDigest,
            $actionSummary
        );

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
                    // SDK 1.11 confirm-each-time: present only when THIS call
                    // was accepted because the hosted service consumed a human
                    // confirmation for exactly this action. Strict: a string
                    // session id AND consumed === true, or it is dropped -
                    // an app that treats this as its own transaction step-up
                    // must never see a half-formed block.
                    actionConfirmation: is_array($data['action_confirmation'] ?? null)
                        && is_string($data['action_confirmation']['action_session_id'] ?? null)
                        && ($data['action_confirmation']['consumed'] ?? null) === true
                        ? [
                            'action_session_id' => $data['action_confirmation']['action_session_id'],
                            'consumed' => true,
                        ]
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
     *
     * SDK 1.11 adds the confirm-each-time trio on the same terms: trimmed,
     * capped ({@see MAX_ATTESTATION_LENGTH}, {@see MAX_DIGEST_LENGTH},
     * {@see MAX_SUMMARY_LENGTH}), and omitted entirely when empty.
     */
    private function buildVerifyBody(
        string $token,
        ?string $scopeUsed,
        ?string $endpoint,
        ?string $method,
        bool $consentFirst = false,
        ?string $actionAttestationId = null,
        ?string $requestDigest = null,
        ?string $actionSummary = null
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

        if ($consentFirst) {
            $body['consent_first'] = true;
        }

        // SDK 1.11 confirm-each-time: each field is trimmed, capped at the
        // hosted BodySchema limit, and omitted entirely when empty.
        foreach ([
            'action_attestation_id' => [$actionAttestationId, self::MAX_ATTESTATION_LENGTH],
            'request_digest'        => [$requestDigest, self::MAX_DIGEST_LENGTH],
            'action_summary'        => [$actionSummary, self::MAX_SUMMARY_LENGTH],
        ] as $key => [$value, $max]) {
            if (!is_string($value)) {
                continue;
            }
            $value = substr(trim($value), 0, $max);
            if ($value !== '') {
                $body[$key] = $value;
            }
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
