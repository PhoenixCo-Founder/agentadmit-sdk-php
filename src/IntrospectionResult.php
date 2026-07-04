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
     * Semantics are fail-closed for malformed data: an absent consent block
     * (null) means a legacy server that predates the Consent Ledger, so
     * access is allowed. When a consent block is present, only a strict
     * boolean true in 'granted' allows access; a missing or non-boolean
     * 'granted' is treated as denied.
     */
    public function consentGranted(): bool
    {
        if ($this->consent === null) {
            return true; // Legacy server: no consent block at all.
        }

        return ($this->consent['granted'] ?? null) === true;
    }
}
