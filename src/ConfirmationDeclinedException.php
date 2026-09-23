<?php

namespace AgentAdmit;

/**
 * SDK 1.12: `confirmation_declined` — the user declined exactly this action on
 * the hosted confirmation page, and the hosted service holds that answer
 * until `hold_until` (confirm-each-time).
 *
 * The hosted service answers HTTP 200 with `active: true` and
 * `error: "confirmation_declined"`, plus a `declined` block naming the
 * declined session, when it was declined, how long the hold runs, and the
 * exact action. No new ceremony is staged and the user is not notified again
 * while the hold runs. Agents should relay the decline to the user and not
 * retry unless the user asks; only the user can lift a decline. After the
 * hold ends, a retry stages a fresh confirmation.
 *
 * A {@see VerificationDeniedException} subclass, so every middleware's existing
 * fail-closed handler already returns the correct 403; this type exists so a
 * custom gate can relay the decline without re-parsing the denial body.
 */
class ConfirmationDeclinedException extends VerificationDeniedException
{
    public const ERROR_CONFIRMATION_DECLINED = 'confirmation_declined';

    /** The 403 error_description used when the hosted service sends none. */
    public const DEFAULT_DESCRIPTION = 'The user declined this action on the hosted confirmation page. '
        . 'Do not retry it unless the user asks you to.';

    /** @var array The strictly typed hosted decline block. */
    private array $declined;

    /** @var string|null Why a presented attestation was not accepted, when one was. */
    private ?string $attestationStatus;

    public function __construct(string $message, array $denialBody, array $declined, ?string $attestationStatus = null)
    {
        parent::__construct($message, self::ERROR_CONFIRMATION_DECLINED, $denialBody);
        $this->declined = $declined;
        $this->attestationStatus = $attestationStatus;
    }

    /**
     * The decline: {action_session_id, declined_at, hold_until, scope, method,
     * endpoint, request_digest, summary}. The last four are nullable strings;
     * the first four are always strings.
     */
    public function getDeclined(): array
    {
        return $this->declined;
    }

    /** The declined session's id. */
    public function getActionSessionId(): string
    {
        return $this->declined['action_session_id'];
    }

    /** ISO-8601 instant until which no new confirmation can be staged for this action. */
    public function getHoldUntil(): string
    {
        return $this->declined['hold_until'];
    }

    /**
     * Hosted explanation of why a presented attestation was not accepted
     * (e.g. `declined`), or null when none was presented / the service sent none.
     */
    public function getAttestationStatus(): ?string
    {
        return $this->attestationStatus;
    }

    /**
     * Strictly typed copy of the wire `declined` block, or null when the block
     * is missing or malformed.
     *
     * Strict on purpose: `action_session_id`, `declined_at`, `hold_until` and
     * `scope` must all be strings, or the whole block is dropped and the
     * caller falls back to a generic fail-closed refusal.
     *
     * @param mixed $raw
     */
    public static function parseDeclined($raw): ?array
    {
        if (!is_array($raw)) {
            return null;
        }

        foreach (['action_session_id', 'declined_at', 'hold_until', 'scope'] as $key) {
            if (!is_string($raw[$key] ?? null)) {
                return null;
            }
        }

        $nullable = static fn ($value): ?string => is_string($value) ? $value : null;

        return [
            'action_session_id' => $raw['action_session_id'],
            'declined_at'       => $raw['declined_at'],
            'hold_until'        => $raw['hold_until'],
            'scope'             => $raw['scope'],
            'method'            => $nullable($raw['method'] ?? null),
            'endpoint'          => $nullable($raw['endpoint'] ?? null),
            'request_digest'    => $nullable($raw['request_digest'] ?? null),
            'summary'           => $nullable($raw['summary'] ?? null),
        ];
    }
}
