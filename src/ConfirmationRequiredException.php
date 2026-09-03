<?php

namespace AgentAdmit;

/**
 * SDK 1.11: `confirmation_required` — the scope is granted, but THIS call
 * needs a fresh human confirmation before it may run (confirm-each-time).
 *
 * The hosted service answers HTTP 200 with `active: true` and
 * `error: "confirmation_required"`, plus a `confirmation` block describing the
 * one-time ceremony it staged for exactly this action. The agent hands
 * `action_session_url` to the human; only a user-verified passkey on that page
 * produces an attestation. The agent then retries the same request with the
 * header `X-AgentAdmit-Action-Attestation: <action_session_id>`, which the SDK
 * forwards on the next verify call.
 *
 * A {@see VerificationDeniedException} subclass, so every middleware's existing
 * fail-closed handler already returns the correct 403; this type exists so a
 * custom gate can relay the link without re-parsing the denial body.
 */
class ConfirmationRequiredException extends VerificationDeniedException
{
    public const ERROR_CONFIRMATION_REQUIRED = 'confirmation_required';

    /** The 403 error_description used when the hosted service sends none. */
    public const DEFAULT_DESCRIPTION = 'This action requires a fresh human confirmation. '
        . 'Give the confirmation link to the user, then retry with the '
        . 'X-AgentAdmit-Action-Attestation header.';

    /** @var array The strictly typed hosted confirmation block. */
    private array $confirmation;

    /** @var string|null Why a presented attestation was not accepted, when one was. */
    private ?string $attestationStatus;

    public function __construct(string $message, array $denialBody, array $confirmation, ?string $attestationStatus = null)
    {
        parent::__construct($message, self::ERROR_CONFIRMATION_REQUIRED, $denialBody);
        $this->confirmation = $confirmation;
        $this->attestationStatus = $attestationStatus;
    }

    /**
     * The staged ceremony: {action_session_id, action_session_url, expires_at,
     * scope, method, endpoint, request_digest, summary}. The last four are
     * nullable strings; the first four are always strings.
     */
    public function getConfirmation(): array
    {
        return $this->confirmation;
    }

    /** The confirmation URL to give the human. */
    public function getActionSessionUrl(): string
    {
        return $this->confirmation['action_session_url'];
    }

    /** The id the agent presents on its retry in the attestation header. */
    public function getActionSessionId(): string
    {
        return $this->confirmation['action_session_id'];
    }

    /**
     * Hosted explanation of why a presented attestation was not accepted
     * (e.g. `already_consumed`, `action_mismatch`, `expired`, `not_confirmed`),
     * or null when none was presented / the service sent none.
     */
    public function getAttestationStatus(): ?string
    {
        return $this->attestationStatus;
    }

    /**
     * Strictly typed copy of the wire `confirmation` block, or null when the
     * block is missing or malformed.
     *
     * Strict on purpose: `action_session_id`, `action_session_url`,
     * `expires_at` and `scope` must all be strings, or the whole block is
     * dropped and the caller falls back to a generic fail-closed refusal —
     * a half-parsed confirmation would send the human to a broken link.
     *
     * @param mixed $raw
     */
    public static function parseConfirmation($raw): ?array
    {
        if (!is_array($raw)) {
            return null;
        }

        foreach (['action_session_id', 'action_session_url', 'expires_at', 'scope'] as $key) {
            if (!is_string($raw[$key] ?? null)) {
                return null;
            }
        }

        $nullable = static fn ($value): ?string => is_string($value) ? $value : null;

        return [
            'action_session_id'  => $raw['action_session_id'],
            'action_session_url' => $raw['action_session_url'],
            'expires_at'         => $raw['expires_at'],
            'scope'              => $raw['scope'],
            'method'             => $nullable($raw['method'] ?? null),
            'endpoint'           => $nullable($raw['endpoint'] ?? null),
            'request_digest'     => $nullable($raw['request_digest'] ?? null),
            'summary'            => $nullable($raw['summary'] ?? null),
        ];
    }
}
