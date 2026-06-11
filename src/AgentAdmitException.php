<?php

namespace AgentAdmit;

class AgentAdmitException extends \RuntimeException
{
    private int $statusCode;
    private ?string $errorCode;

    public function __construct(string $message, int $statusCode = 500, ?string $errorCode = null)
    {
        parent::__construct($message);
        $this->statusCode = $statusCode;
        $this->errorCode = $errorCode;
    }

    public function getStatusCode(): int
    {
        return $this->statusCode;
    }

    /**
     * Machine-readable error code from the API, when available — one of the
     * IntrospectionClient::ERROR_* constants (e.g. token_expired,
     * connection_expired, environment_mismatch), or null.
     */
    public function getErrorCode(): ?string
    {
        return $this->errorCode;
    }
}
