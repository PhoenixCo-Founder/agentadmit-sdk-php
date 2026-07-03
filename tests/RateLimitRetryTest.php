<?php

namespace AgentAdmit\Tests;

use AgentAdmit\IntrospectionClient;
use AgentAdmit\RateLimitException;
use Illuminate\Http\Client\Factory;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use PHPUnit\Framework\TestCase;

/**
 * Regression tests for 429 retry handling in IntrospectionClient::verify().
 *
 * A server-supplied Retry-After header is untrusted input: a compromised or
 * misconfigured endpoint could send `Retry-After: 3600` and pin the caller's
 * request thread for an hour. Every wait must be capped at 30 seconds, and
 * cumulative wait across retries of one verify call must be capped at 120
 * seconds.
 */
class RateLimitRetryTest extends TestCase
{
    /** @var array<int> recorded waits (ms) instead of real sleeps */
    private array $sleeps = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->sleeps = [];
        Http::swap(new Factory());
        Log::swap(new class {
            public function __call($method, $args)
            {
                return null;
            }
        });
    }

    private function client(int $maxRetries = 3): IntrospectionClient
    {
        $sleeps = &$this->sleeps;
        return new class(['api_key' => 'aa_test_dummy', 'max_retries' => $maxRetries], $sleeps) extends IntrospectionClient {
            /** @var array<int> */
            private $sleepLog;

            public function __construct(array $config, array &$sleepLog)
            {
                parent::__construct($config);
                $this->sleepLog = &$sleepLog;
            }

            protected function waitBeforeRetry(int $totalMs): void
            {
                $this->sleepLog[] = $totalMs;
            }
        };
    }

    public function testHugeRetryAfterIsCappedAt30s(): void
    {
        Http::fake([
            '*' => Http::response(['error' => 'rate_limited'], 429, ['Retry-After' => '3600']),
        ]);

        try {
            $this->client()->verify('ag_at_dummy');
            $this->fail('Expected RateLimitException');
        } catch (RateLimitException $e) {
            $this->assertStringContainsString('Max retries', $e->getMessage());
        }

        $this->assertCount(3, $this->sleeps);
        foreach ($this->sleeps as $ms) {
            $this->assertLessThanOrEqual(
                30500,
                $ms,
                "wait must be capped at 30s + jitter, got {$ms}ms — Retry-After was not capped"
            );
        }
    }

    public function testCumulativeBudgetExhausted(): void
    {
        Http::fake([
            '*' => Http::response(['error' => 'rate_limited'], 429, ['Retry-After' => '30']),
        ]);

        // High max_retries so the 120s budget, not the retry count, is the limiter.
        try {
            $this->client(99)->verify('ag_at_dummy');
            $this->fail('Expected RateLimitException');
        } catch (RateLimitException $e) {
            $this->assertStringContainsString('budget', $e->getMessage());
        }

        // ~30s + jitter per wait -> at most 3 sleeps before the 4th would
        // blow the 120s budget.
        $this->assertLessThanOrEqual(3, count($this->sleeps));
        $this->assertGreaterThanOrEqual(3, count($this->sleeps));
    }

    public function testRecoversWhenServerStopsRateLimiting(): void
    {
        Http::fakeSequence()
            ->push(['error' => 'rate_limited'], 429, ['Retry-After' => '2'])
            ->push([
                'active' => true,
                'user_id' => 'user_1',
                'connection_id' => 'conn_1',
                'scopes' => ['read:things'],
                'agent_label' => 'Test Agent',
            ], 200);

        $result = $this->client()->verify('ag_at_dummy');

        $this->assertSame('conn_1', $result->connectionId);
        $this->assertCount(1, $this->sleeps);
        $this->assertLessThanOrEqual(2500, $this->sleeps[0]);
    }
}
