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

    private array $config;

    public function __construct(array $config)
    {
        $this->config = $config;

        // Validate the key prefix without ever echoing the key itself.
        $apiKey = $config['api_key'] ?? '';
        if ($apiKey !== '' && !str_starts_with($apiKey, 'aa_test_') && !str_starts_with($apiKey, 'aa_live_')) {
            throw new AgentAdmitException("api_key must start with 'aa_test_' or 'aa_live_'", 401);
        }
    }

    /**
     * Validate an ag_at_ token via introspection.
     *
     * Automatically retries on HTTP 429 with exponential backoff + jitter.
     * Throws {@see RateLimitException} when retries are exhausted.
     *
     * @param string $token The full token including ag_at_ prefix
     * @return IntrospectionResult
     * @throws AgentAdmitException
     * @throws RateLimitException
     */
    public function verify(string $token): IntrospectionResult
    {
        $prefix = $this->config['token_prefix_access'] ?? 'ag_at_';

        if (!str_starts_with($token, $prefix)) {
            throw new AgentAdmitException('Not an AgentAdmit access token', 401);
        }

        $maxRetries = (int) ($this->config['max_retries'] ?? 3);
        $verifyUrl  = $this->config['verify_url'] ?? 'https://api.agentadmit.com/api/v1/verify';
        $delayMs    = 1000; // initial backoff: 1 second (in ms)

        for ($attempt = 0; $attempt <= $maxRetries; $attempt++) {
            try {
                $response = Http::timeout(5)
                    ->withHeaders([
                        'Authorization' => 'Bearer ' . ($this->config['api_key'] ?? ''),
                        'Content-Type' => 'application/json',
                    ])
                    ->post($verifyUrl, ['token' => $token]);
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

                // Compute wait: honor Retry-After or use exponential backoff (cap 30s)
                $waitMs  = $retryAfter !== null ? (int)($retryAfter * 1000) : min($delayMs, 30000);
                $jitterMs = random_int(0, 500);
                $totalMs  = $waitMs + $jitterMs;

                Log::warning(
                    "AgentAdmit introspection rate-limited (attempt " . ($attempt + 1) . "/{$maxRetries}). " .
                    "Retrying in {$totalMs}ms."
                );

                usleep($totalMs * 1000); // usleep takes microseconds
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

                if ($status !== 200) {
                    throw new AgentAdmitException(
                        'Verification service returned ' . $status,
                        502
                    );
                }

                $data = $response->json();

                // Check active flag (RFC 7662 introspection pattern).
                // The verify endpoint returns {active: false} with HTTP 200 for
                // invalid/expired/revoked tokens; the error code is one of the
                // ERROR_* constants (e.g. token_expired, connection_expired,
                // environment_mismatch). Without this check, we'd read empty scopes.
                if (empty($data['active'])) {
                    $reason = $data['error'] ?? self::ERROR_INVALID_TOKEN;
                    throw new AgentAdmitException('Token is not active: ' . $reason, 401, $reason);
                }

                // insufficient_scope arrives with active: true (token valid,
                // requested scope not granted) — treat it as a 403.
                if (($data['error'] ?? null) === self::ERROR_INSUFFICIENT_SCOPE) {
                    throw new AgentAdmitException(
                        $data['error_description'] ?? 'Scope not granted',
                        403,
                        self::ERROR_INSUFFICIENT_SCOPE
                    );
                }

                if (empty($data['user_id'])) {
                    throw new AgentAdmitException('Introspection returned no user', 401);
                }

                return new IntrospectionResult(
                    userId: $data['user_id'],
                    connectionId: $data['connection_id'] ?? null,
                    scopes: $data['scopes'] ?? [],
                    agentLabel: $data['agent_label'] ?? 'Unknown Agent',
                    sub: $data['sub'] ?? null,
                    role: $data['role'] ?? null,
                    appId: $data['app_id'] ?? null,
                    jti: $data['jti'] ?? null,
                    exp: isset($data['exp']) ? (int) $data['exp'] : null,
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
