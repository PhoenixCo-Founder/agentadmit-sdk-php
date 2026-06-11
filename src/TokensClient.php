<?php

namespace AgentAdmit;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

/**
 * TokensClient — issue, exchange, and revoke connection tokens via the
 * AgentAdmit hosted service.
 */
class TokensClient
{
    /**
     * Sentinel for issueToken()'s $durationSeconds: leave the field out of
     * the request entirely, so AgentAdmit applies its default (30 days).
     * Pass null instead for an until-revoked connection (explicit JSON null).
     */
    public const DURATION_DEFAULT = 'aa_duration_default';

    private array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    /**
     * Issue a connection token for one of your users.
     * Calls POST /api/v1/apps/{app_id}/token.
     *
     * The duration is tri-state:
     *  - self::DURATION_DEFAULT (the default) — field omitted; AgentAdmit
     *    applies its default (30 days)
     *  - null — explicit JSON null; the connection lasts until revoked
     *  - int — explicit duration in seconds (60–31536000)
     *
     * @param string      $userId          Your app's identifier for the user
     * @param array       $scopes          Scopes the connection grants
     * @param string|null $role            The user's role on the connection
     * @param int|string|null $durationSeconds See above
     * @return array The issue response — ['token' => 'ag_ct_…', 'expires_in' => …, …]
     * @throws AgentAdmitException
     */
    public function issueToken(
        string $userId,
        array $scopes,
        ?string $role = null,
        int|string|null $durationSeconds = self::DURATION_DEFAULT
    ): array {
        $appId = $this->config['app_id'] ?? '';
        $url = rtrim($this->config['api_url'] ?? 'https://api.agentadmit.com', '/')
            . "/api/v1/apps/{$appId}/token";

        $body = [
            'user_id' => $userId,
            'scopes' => $scopes,
        ];
        if ($role !== null) {
            $body['role'] = $role;
        }
        // Tri-state: the sentinel omits the key entirely; null survives
        // json_encode as explicit JSON null (no array_filter anywhere).
        if ($durationSeconds !== self::DURATION_DEFAULT) {
            $body['duration_seconds'] = $durationSeconds;
        }

        return $this->post($url, $body, 'issueToken', authenticated: true);
    }

    /**
     * Exchange a single-use connection token for an access token.
     * Calls POST /api/v1/exchange — unauthenticated by design: the connection
     * token itself is the credential, so the operator API key is NOT sent.
     *
     * @param string      $connectionToken The ag_ct_… connection token
     * @param string|null $agentLabel      Human-readable agent name
     * @param string|null $agentId         Agent identifier
     * @return array The exchange response — ['access_token' => 'ag_at_…', …]
     * @throws AgentAdmitException
     */
    public function exchange(string $connectionToken, ?string $agentLabel = null, ?string $agentId = null): array
    {
        $url = rtrim($this->config['api_url'] ?? 'https://api.agentadmit.com', '/') . '/api/v1/exchange';

        $body = ['token' => $connectionToken];
        if ($agentLabel !== null) {
            $body['agent_label'] = $agentLabel;
        }
        if ($agentId !== null) {
            $body['agent_id'] = $agentId;
        }

        return $this->post($url, $body, 'exchange', authenticated: false);
    }

    /**
     * Revoke a connection (and its access tokens).
     * Calls POST /api/v1/revoke.
     *
     * @param string      $connectionId The connection to revoke
     * @param string|null $reason       Optional human-readable reason
     * @return array The revoke response — ['ok' => true, 'connection_id' => …, …]
     * @throws AgentAdmitException
     */
    public function revoke(string $connectionId, ?string $reason = null): array
    {
        $url = rtrim($this->config['api_url'] ?? 'https://api.agentadmit.com', '/') . '/api/v1/revoke';

        $body = ['connection_id' => $connectionId];
        if ($reason !== null) {
            $body['reason'] = $reason;
        }

        return $this->post($url, $body, 'revoke', authenticated: true);
    }

    private function post(string $url, array $body, string $op, bool $authenticated): array
    {
        $headers = ['Content-Type' => 'application/json'];
        if ($authenticated) {
            $headers['Authorization'] = 'Bearer ' . ($this->config['api_key'] ?? '');
            $headers['X-App-Id'] = $this->config['app_id'] ?? '';
        }

        try {
            $response = Http::timeout(10)->withHeaders($headers)->post($url, $body);
        } catch (\Exception $e) {
            Log::error("AgentAdmit {$op} failed: " . $e->getMessage());
            throw new AgentAdmitException("{$op} failed", 502);
        }

        if ($response->status() >= 400) {
            Log::error("AgentAdmit {$op} returned " . $response->status());
            throw new AgentAdmitException("{$op} failed", $response->status());
        }

        return $response->json() ?? [];
    }
}
