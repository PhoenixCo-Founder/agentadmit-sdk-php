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

    /** Maximum length (characters) of a declared purpose. */
    public const PURPOSE_MAX_LENGTH = 300;

    /** Maximum length (characters) of a user-declared intent. */
    public const USER_INTENT_MAX_LENGTH = 300;

    private array $config;

    public function __construct(array $config)
    {
        $this->config = $config;

        // M4: Require HTTPS on configurable URLs (HTTP allowed only on loopback).
        $apiUrl = rtrim($config['api_url'] ?? 'https://api.agentadmit.com', '/');
        AgentAdmitException::assertHttpsUrl($apiUrl, 'api_url');
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
     * The declared purpose is the user-facing reason recorded on the grant at
     * the consent moment (shown to the human on the consent page). It is a
     * review-time record only, never an enforcement input; authorization
     * decisions ride scopes, connection status, and consent.
     *
     * The user-declared intent is the USER's own words, typed by the human at
     * the consent moment (distinct from the declared purpose, which is the
     * app's words). Same semantics: a review-time record only, never an
     * enforcement input. Metadata tolerance, never a rejection: a malformed
     * user intent (non-string, empty, or longer than 300 characters) is
     * normalized to absent and the key is omitted from the request.
     *
     * @param string      $userId          Your app's identifier for the user
     * @param array       $scopes          Scopes the connection grants
     * @param string|null $role            The user's role on the connection
     * @param int|string|null $durationSeconds See above
     * @param string|null $purpose         Declared purpose (max 300 characters);
     *                                     omitted from the request when null
     * @param mixed       $userIntent      User-declared intent (string, 1–300
     *                                     characters); malformed values are
     *                                     normalized to absent, and the key is
     *                                     omitted from the request when absent
     * @return array The issue response — ['token' => 'ag_ct_…', 'expires_in' => …, …]
     * @throws \InvalidArgumentException When $purpose exceeds 300 characters
     * @throws AgentAdmitException
     */
    public function issueToken(
        string $userId,
        array $scopes,
        ?string $role = null,
        int|string|null $durationSeconds = self::DURATION_DEFAULT,
        ?string $purpose = null,
        mixed $userIntent = null
    ): array {
        if ($purpose !== null && mb_strlen($purpose) > self::PURPOSE_MAX_LENGTH) {
            throw new \InvalidArgumentException(
                'purpose must be ' . self::PURPOSE_MAX_LENGTH . ' characters or fewer'
            );
        }

        // User-declared intent is metadata: tolerance, never a rejection (the
        // cross-SDK parity convention). Anything that is not a string of 1–300
        // characters normalizes to absent.
        if (!is_string($userIntent)
            || $userIntent === ''
            || mb_strlen($userIntent) > self::USER_INTENT_MAX_LENGTH
        ) {
            $userIntent = null;
        }

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
        if ($purpose !== null) {
            $body['purpose'] = $purpose;
        }
        if ($userIntent !== null) {
            $body['user_intent'] = $userIntent;
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
