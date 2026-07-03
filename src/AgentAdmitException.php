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
     * Machine-readable error code from the API, when available - one of the
     * IntrospectionClient::ERROR_* constants (e.g. token_expired,
     * connection_expired, environment_mismatch), or null.
     */
    public function getErrorCode(): ?string
    {
        return $this->errorCode;
    }

    /**
     * Assert that a URL uses HTTPS (or HTTP on loopback for local dev).
     *
     * Throws AgentAdmitException if the URL is non-HTTPS and the host is not
     * localhost / 127.0.0.1 / [::1]. Call from every client constructor with
     * each configurable URL.
     *
     * @throws AgentAdmitException
     */
    public static function assertHttpsUrl(string $url, string $configKey): void
    {
        $parsed = parse_url($url);
        $scheme = strtolower($parsed['scheme'] ?? '');
        $host   = strtolower($parsed['host'] ?? '');

        if ($scheme === 'https') {
            return;
        }

        if ($scheme === 'http') {
            $loopback = ['localhost', '127.0.0.1', '[::1]'];
            if (in_array($host, $loopback, true)) {
                return;
            }
        }

        throw new self(
            "AgentAdmit configuration error: '{$configKey}' must use HTTPS (got '{$url}'). " .
            "HTTP is only allowed for localhost / 127.0.0.1 / [::1] in local development.",
            500
        );
    }
}
