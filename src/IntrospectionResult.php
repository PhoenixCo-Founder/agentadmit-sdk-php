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
    ) {}

    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }
}
