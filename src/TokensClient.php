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
     * enforcement input. Outbound validation mirrors purpose: a non-string,
     * non-null value or a value longer than 300 characters throws
     * InvalidArgumentException before any request is sent (silently dropping
     * the user's typed words would be data loss). null and the empty string
     * are omitted from the request.
     *
     * @param string      $userId          Your app's identifier for the user
     * @param array       $scopes          Scopes the connection grants
     * @param string|null $role            The user's role on the connection
     * @param int|string|null $durationSeconds See above
     * @param string|null $purpose         Declared purpose (max 300 characters);
     *                                     omitted from the request when null
     * @param mixed       $userIntent      User-declared intent (string, max 300
     *                                     characters); omitted from the request
     *                                     when null or empty
     * @param AppAttestedPresence|null $presence App-attested ceremony fact: set it
     *                                     AFTER verifying and consuming your app's
     *                                     own fresh, purpose-bound WebAuthn/passkey
     *                                     attestation for this mint. Forwarded as
     *                                     presence {verified: true, uv: true,
     *                                     method, verified_at} and stored
     *                                     provenance-marked "app:<method>";
     *                                     omitted when null (omitting the field is
     *                                     the only way to say "no ceremony")
     * @return array The issue response — ['token' => 'ag_ct_…', 'expires_in' => …, …]
     * @throws \InvalidArgumentException When $purpose exceeds 300 characters, or
     *                                   when $userIntent is a non-string,
     *                                   non-null value or exceeds 300 characters
     * @throws AgentAdmitException
     */
    public function issueToken(
        string $userId,
        array $scopes,
        ?string $role = null,
        int|string|null $durationSeconds = self::DURATION_DEFAULT,
        ?string $purpose = null,
        mixed $userIntent = null,
        ?AppAttestedPresence $presence = null
    ): array {
        if ($purpose !== null && mb_strlen($purpose) > self::PURPOSE_MAX_LENGTH) {
            throw new \InvalidArgumentException(
                'purpose must be ' . self::PURPOSE_MAX_LENGTH . ' characters or fewer'
            );
        }

        // Outbound user-declared intent validates like purpose (the cross-SDK
        // parity convention): reject before any request rather than silently
        // discarding the user's typed words. null / '' stay omitted.
        if ($userIntent !== null) {
            if (!is_string($userIntent)) {
                throw new \InvalidArgumentException('user_intent must be a string');
            }
            if (mb_strlen($userIntent) > self::USER_INTENT_MAX_LENGTH) {
                throw new \InvalidArgumentException(
                    'user_intent must be ' . self::USER_INTENT_MAX_LENGTH . ' characters or fewer'
                );
            }
            if ($userIntent === '') {
                $userIntent = null;
            }
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
        // App-attested presence: verified/uv literal true and verified_at
        // offset-carrying by construction (the typed class owns the contract).
        if ($presence !== null) {
            $body['presence'] = $presence->toWire();
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
     * @param string|null $agentPlatform   The agent app or runtime the agent
     *                                     says it runs in (reported by the
     *                                     agent, unverified)
     * @param array|null  $agentModel      The AI model the agent says it runs
     *                                     on: ['id' => string, 'version' =>
     *                                     string (optional)] (reported by the
     *                                     agent, unverified). The hosted
     *                                     service records both and never lets
     *                                     them decide the outcome of the
     *                                     exchange.
     * @return array The exchange response — ['access_token' => 'ag_at_…', …]
     * @throws AgentAdmitException
     */
    public function exchange(
        string $connectionToken,
        ?string $agentLabel = null,
        ?string $agentId = null,
        ?string $agentPlatform = null,
        ?array $agentModel = null,
    ): array {
        $url = rtrim($this->config['api_url'] ?? 'https://api.agentadmit.com', '/') . '/api/v1/exchange';

        $body = ['token' => $connectionToken];
        if ($agentLabel !== null) {
            $body['agent_label'] = $agentLabel;
        }
        if ($agentId !== null) {
            $body['agent_id'] = $agentId;
        }
        if ($agentPlatform !== null) {
            $body['agent_platform'] = $agentPlatform;
        }
        if ($agentModel !== null) {
            $body['agent_model'] = $agentModel;
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

    /** Shortest action session id the owner-link call accepts (characters). */
    public const OWNER_LINK_MIN_SESSION_ID_LENGTH = 20;

    /** Longest app user id the owner-link call accepts (characters). */
    public const OWNER_LINK_MAX_USER_ID_LENGTH = 255;

    /**
     * SDK 1.15: open a pending confirm-each-time request for the app's own
     * signed-in user. Calls POST /api/v1/action-sessions/{id}/owner-link with
     * the app's API key and body {"app_user_id": $appUserId}.
     *
     * Use it when a confirmation_required refusal says
     * `enrollment_required: true` ({@see ConfirmationRequiredException::isEnrollmentRequired()}):
     * the user has no passkey on file for the app yet, so the link the agent
     * holds cannot be used. The user creates a passkey and confirms on the page
     * the returned link opens; on a computer that page can show a QR code to
     * continue on the user's phone.
     *
     * Two rules:
     *  - Call it only from a route your signed-in human uses, passing that
     *    user's own id. The hosted service answers 404 when the session
     *    belongs to a different user than the one named.
     *  - Do not return $ownerSessionUrl to an agent. Send it to the signed-in
     *    user's browser only.
     *
     * It is not registered on any middleware or route. This call logs the path
     * and the status only, never the response. Calling it again for the same
     * session is safe: a new link replaces the previous one.
     *
     * @param string $actionSessionId The asess_ id from the refusal (at least 20 characters)
     * @param string $appUserId       Your signed-in user's id (1 to 255 characters)
     * @throws \InvalidArgumentException before any request when an argument is invalid
     * @throws AgentAdmitException on a hosted HTTP error (status and hosted `error` code:
     *         401 invalid_api_key, 403 api_key_not_app_linked, 404 not_found,
     *         409 already_consumed / already_verified, 410 session_expired, 429, 5xx;
     *         not retried), or with status 502 on a network failure or a malformed 2xx body
     */
    public function createOwnerLink(string $actionSessionId, string $appUserId): OwnerLink
    {
        if (!str_starts_with($actionSessionId, 'asess_')
            || strlen($actionSessionId) < self::OWNER_LINK_MIN_SESSION_ID_LENGTH) {
            throw new \InvalidArgumentException(
                'actionSessionId must be an asess_ id of at least '
                . self::OWNER_LINK_MIN_SESSION_ID_LENGTH . ' characters'
            );
        }
        if ($appUserId === '' || mb_strlen($appUserId) > self::OWNER_LINK_MAX_USER_ID_LENGTH) {
            throw new \InvalidArgumentException(
                'appUserId must be 1 to ' . self::OWNER_LINK_MAX_USER_ID_LENGTH . ' characters'
            );
        }

        $path = '/api/v1/action-sessions/' . rawurlencode($actionSessionId) . '/owner-link';
        $url = rtrim($this->config['api_url'] ?? 'https://api.agentadmit.com', '/') . $path;
        $headers = [
            'Content-Type' => 'application/json',
            'Authorization' => 'Bearer ' . ($this->config['api_key'] ?? ''),
            'X-App-Id' => $this->config['app_id'] ?? '',
        ];

        try {
            $response = Http::timeout(10)->withHeaders($headers)->post($url, ['app_user_id' => $appUserId]);
        } catch (\Exception $e) {
            Log::error("AgentAdmit createOwnerLink POST {$path} failed");
            throw new AgentAdmitException('createOwnerLink failed', 502);
        }

        $status = $response->status();
        if ($status >= 400) {
            Log::error("AgentAdmit createOwnerLink POST {$path} returned {$status}");
            $data = json_decode($response->body(), true);
            $code = is_array($data) && is_string($data['error'] ?? null) ? $data['error'] : null;
            throw new AgentAdmitException(
                'createOwnerLink failed: ' . $status . ($code !== null ? " {$code}" : ''),
                $status,
                $code
            );
        }

        $data = json_decode($response->body(), true);
        if (!is_array($data)
            || !is_string($data['owner_session_url'] ?? null)
            || !is_bool($data['enrollment_required'] ?? null)) {
            Log::error("AgentAdmit createOwnerLink POST {$path} returned {$status} with a malformed body");
            throw new AgentAdmitException('createOwnerLink returned a malformed response', 502);
        }

        return new OwnerLink(
            actionSessionId: is_string($data['action_session_id'] ?? null) ? $data['action_session_id'] : null,
            ownerSessionUrl: $data['owner_session_url'],
            enrollmentRequired: $data['enrollment_required'],
            enrollmentReason: is_string($data['enrollment_reason'] ?? null) ? $data['enrollment_reason'] : null,
            expiresAt: is_string($data['expires_at'] ?? null) ? $data['expires_at'] : null,
        );
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
