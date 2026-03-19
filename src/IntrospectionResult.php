<?php

namespace AgentAdmit;

class IntrospectionResult
{
    public function __construct(
        public readonly string $userId,
        public readonly ?string $connectionId,
        public readonly array $scopes,
        public readonly string $agentLabel,
    ) {}

    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }
}
