<?php

namespace AgentAdmit\Tests;

use AgentAdmit\AgentAdmitException;
use AgentAdmit\IntrospectionClient;
use AgentAdmit\RateLimitException;
use Illuminate\Http\Client\Factory;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use PHPUnit\Framework\TestCase;

/**
 * Tests for M5 — strict introspection response validation.
 *
 * A token is valid only when:
 *  - HTTP status is 2xx
 *  - active is strictly the boolean true
 *  - user_id is a non-empty string
 *  - agent_id and connection_id are strings when present
 *  - scopes is an array of strings when present
 */
class IntrospectionValidationTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Http::swap(new Factory());
        Log::swap(new class {
            public function __call($method, $args) { return null; }
        });
    }

    private function client(): IntrospectionClient
    {
        return new class(['api_key' => 'aa_test_dummy']) extends IntrospectionClient {
            protected function waitBeforeRetry(int $totalMs): void {}
        };
    }

    /** Minimal valid payload used as a baseline across tests. */
    private function validPayload(array $overrides = []): array
    {
        return array_merge([
            'active'        => true,
            'user_id'       => 'user_42',
            'connection_id' => 'conn_abc',
            'scopes'        => ['read:orders'],
            'agent_label'   => 'Test Agent',
        ], $overrides);
    }

    // -------------------------------------------------------------------------
    // Happy path
    // -------------------------------------------------------------------------

    public function testValidResponseSucceeds(): void
    {
        Http::fake(['*' => Http::response($this->validPayload(), 200)]);
        $result = $this->client()->verify('ag_at_dummy');
        $this->assertSame('user_42', $result->userId);
        $this->assertSame('conn_abc', $result->connectionId);
        $this->assertSame(['read:orders'], $result->scopes);
    }

    // -------------------------------------------------------------------------
    // M5: active must be strictly boolean true
    // -------------------------------------------------------------------------

    public function testActiveFalseIsInvalid(): void
    {
        $this->expectException(AgentAdmitException::class);
        Http::fake(['*' => Http::response($this->validPayload(['active' => false]), 200)]);
        $this->client()->verify('ag_at_dummy');
    }

    public function testActiveIntOneIsInvalid(): void
    {
        $this->expectException(AgentAdmitException::class);
        // active: 1 must NOT pass strict === true check
        Http::fake(['*' => Http::response($this->validPayload(['active' => 1]), 200)]);
        $this->client()->verify('ag_at_dummy');
    }

    public function testActiveStringTrueIsInvalid(): void
    {
        $this->expectException(AgentAdmitException::class);
        Http::fake(['*' => Http::response($this->validPayload(['active' => 'true']), 200)]);
        $this->client()->verify('ag_at_dummy');
    }

    public function testActiveMissingIsInvalid(): void
    {
        $this->expectException(AgentAdmitException::class);
        $payload = $this->validPayload();
        unset($payload['active']);
        Http::fake(['*' => Http::response($payload, 200)]);
        $this->client()->verify('ag_at_dummy');
    }

    public function testActiveNullIsInvalid(): void
    {
        $this->expectException(AgentAdmitException::class);
        Http::fake(['*' => Http::response($this->validPayload(['active' => null]), 200)]);
        $this->client()->verify('ag_at_dummy');
    }

    // -------------------------------------------------------------------------
    // M5: non-2xx HTTP status -> invalid (except 429 which goes to retry path)
    // -------------------------------------------------------------------------

    public function testHttp201IsAccepted(): void
    {
        Http::fake(['*' => Http::response($this->validPayload(), 201)]);
        $result = $this->client()->verify('ag_at_dummy');
        $this->assertSame('user_42', $result->userId);
    }

    public function testHttp400IsInvalid(): void
    {
        $this->expectException(AgentAdmitException::class);
        Http::fake(['*' => Http::response(['error' => 'bad_request'], 400)]);
        $this->client()->verify('ag_at_dummy');
    }

    public function testHttp500IsInvalid(): void
    {
        $this->expectException(AgentAdmitException::class);
        Http::fake(['*' => Http::response(['error' => 'server_error'], 500)]);
        $this->client()->verify('ag_at_dummy');
    }

    // -------------------------------------------------------------------------
    // M5: field type validation
    // -------------------------------------------------------------------------

    public function testUserIdMissingThrows(): void
    {
        $this->expectException(AgentAdmitException::class);
        $payload = $this->validPayload();
        unset($payload['user_id']);
        Http::fake(['*' => Http::response($payload, 200)]);
        $this->client()->verify('ag_at_dummy');
    }

    public function testUserIdEmptyStringThrows(): void
    {
        $this->expectException(AgentAdmitException::class);
        Http::fake(['*' => Http::response($this->validPayload(['user_id' => '']), 200)]);
        $this->client()->verify('ag_at_dummy');
    }

    public function testUserIdNonStringThrows(): void
    {
        $this->expectException(AgentAdmitException::class);
        Http::fake(['*' => Http::response($this->validPayload(['user_id' => 42]), 200)]);
        $this->client()->verify('ag_at_dummy');
    }

    public function testConnectionIdNonStringThrows(): void
    {
        $this->expectException(AgentAdmitException::class);
        Http::fake(['*' => Http::response($this->validPayload(['connection_id' => 99]), 200)]);
        $this->client()->verify('ag_at_dummy');
    }

    public function testConnectionIdMissingIsAllowed(): void
    {
        $payload = $this->validPayload();
        unset($payload['connection_id']);
        Http::fake(['*' => Http::response($payload, 200)]);
        $result = $this->client()->verify('ag_at_dummy');
        $this->assertNull($result->connectionId);
    }

    public function testAgentIdNonStringThrows(): void
    {
        $this->expectException(AgentAdmitException::class);
        Http::fake(['*' => Http::response($this->validPayload(['agent_id' => true]), 200)]);
        $this->client()->verify('ag_at_dummy');
    }

    public function testScopesNotArrayThrows(): void
    {
        $this->expectException(AgentAdmitException::class);
        Http::fake(['*' => Http::response($this->validPayload(['scopes' => 'read:orders']), 200)]);
        $this->client()->verify('ag_at_dummy');
    }

    public function testScopesWithNonStringElementThrows(): void
    {
        $this->expectException(AgentAdmitException::class);
        Http::fake(['*' => Http::response($this->validPayload(['scopes' => ['read:orders', 42]]), 200)]);
        $this->client()->verify('ag_at_dummy');
    }

    public function testScopesMissingIsAllowed(): void
    {
        $payload = $this->validPayload();
        unset($payload['scopes']);
        Http::fake(['*' => Http::response($payload, 200)]);
        $result = $this->client()->verify('ag_at_dummy');
        $this->assertSame([], $result->scopes);
    }

    // -------------------------------------------------------------------------
    // M5: 429/5xx retry path still works (H1 regression guard)
    // -------------------------------------------------------------------------

    public function testRateLimitStillRetries(): void
    {
        Http::fakeSequence()
            ->push(['error' => 'rate_limited'], 429, ['Retry-After' => '1'])
            ->push($this->validPayload(), 200);

        $result = $this->client()->verify('ag_at_dummy');
        $this->assertSame('user_42', $result->userId);
    }
}
