<?php

namespace AgentAdmit;

class AgentAdmitException extends \RuntimeException
{
    private int $statusCode;

    public function __construct(string $message, int $statusCode = 500)
    {
        parent::__construct($message);
        $this->statusCode = $statusCode;
    }

    public function getStatusCode(): int
    {
        return $this->statusCode;
    }
}

/**
 * Thrown when the AgentAdmit introspection endpoint returns HTTP 429 and
 * all retry attempts (with exponential backoff + jitter) are exhausted.
 *
 * @example
 * ```php
 * try {
 *     $client->verify($token);
 * } catch (\AgentAdmit\RateLimitException $e) {
 *     return response()->json(['error' => 'rate_limited'], 429)
 *         ->header('Retry-After', $e->getRetryAfter());
 * }
 * ```
 */
class RateLimitException extends AgentAdmitException
{
    /** @var float|null Seconds to wait before retrying (Retry-After header), or null. */
    private ?float $retryAfter;
    /** @var int|null X-RateLimit-Limit value, or null. */
    private ?int $limit;
    /** @var int|null X-RateLimit-Remaining value, or null. */
    private ?int $remaining;
    /** @var int|null X-RateLimit-Reset value (Unix timestamp), or null. */
    private ?int $reset;

    public function __construct(
        string $message,
        ?float $retryAfter = null,
        ?int $limit = null,
        ?int $remaining = null,
        ?int $reset = null
    ) {
        parent::__construct($message, 429);
        $this->retryAfter = $retryAfter;
        $this->limit = $limit;
        $this->remaining = $remaining;
        $this->reset = $reset;
    }

    /** Seconds to wait before retrying (from Retry-After header), or null if absent. */
    public function getRetryAfter(): ?float
    {
        return $this->retryAfter;
    }

    /** X-RateLimit-Limit, or null if header was absent. */
    public function getLimit(): ?int
    {
        return $this->limit;
    }

    /** X-RateLimit-Remaining, or null if header was absent. */
    public function getRemaining(): ?int
    {
        return $this->remaining;
    }

    /** X-RateLimit-Reset (Unix timestamp), or null if header was absent. */
    public function getReset(): ?int
    {
        return $this->reset;
    }
}
