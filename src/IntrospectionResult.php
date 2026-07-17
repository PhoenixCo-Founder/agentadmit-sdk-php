<?php

namespace AgentAdmit;

class IntrospectionResult
{
    public function __construct(
        public readonly string $userId,
        public readonly ?string $connectionId,
        public readonly array $scopes,
        public readonly string $agentLabel,
        public readonly ?string $sub = null,
        public readonly ?string $role = null,
        public readonly ?string $appId = null,
        public readonly ?string $jti = null,
        public readonly ?int $exp = null,
        public readonly ?array $consent = null,
        public readonly ?array $presence = null,
    ) {}

    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }

    /**
     * Consent Ledger verdict for the external-agent path (additive; may be
     * null). A denied verdict means the app returns its own 403 -- the token
     * itself stays valid (consent is orthogonal to revocation).
     *
     * SECURITY: an absent consent block (null $consent) is NOT a grant. The
     * hosted service deliberately omits the block when its consent-store read
     * fails (designed degraded mode), so this helper fails closed on absence.
     * This helper cannot consult the ledger itself; callers who need an
     * authoritative answer for a null $consent resolve it through
     * ConsentClient::checkConsent() - the CallerConsent middleware does
     * exactly that (fail closed: 503 when the ledger is unavailable). When a
     * consent block is present, only a strict boolean true in 'granted'
     * reports granted; a missing or non-boolean 'granted' reports denied.
     * (Through 1.5.0 this helper returned true on absence - same fail-open
     * class the 1.5.1 release removes across every SDK.)
     */
    public function consentGranted(): bool
    {
        return $this->consent !== null && ($this->consent['granted'] ?? null) === true;
    }

    /**
     * Human-presence fact from the WebAuthn step-up (additive; may be null):
     * whether the human who authorized this connection completed a presence
     * ceremony on the consent page. Absent on older servers, and
     * 'verified' => false for connections minted without a ceremony
     * (direct-API tokens, presence-off sessions, pre-presence connections).
     *
     * Semantics are strict and fail closed: only a strict boolean true in
     * 'verified' counts. An absent block (null, i.e. an older server or a
     * malformed block dropped by the client) is NOT verified.
     */
    public function presenceVerified(): bool
    {
        return ($this->presence['verified'] ?? null) === true;
    }
}
