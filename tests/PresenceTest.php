<?php

namespace AgentAdmit\Tests;

use AgentAdmit\IntrospectionClient;
use AgentAdmit\IntrospectionResult;
use Illuminate\Http\Client\Factory;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use PHPUnit\Framework\TestCase;

/**
 * Tests for the presence block (WebAuthn human-presence step-up, server
 * Phase 2).
 *
 * IntrospectionClient::verify() must:
 *  - attach 'presence' when the platform returns a well-formed block
 *  - treat it as absent (null) when the server omits it (older servers) or
 *    when it is malformed: strictness mirrors 'active', so 'verified' must
 *    be strictly boolean and never coerced
 *
 * IntrospectionResult::presenceVerified() must be strict:
 *  - verified === true              => true
 *  - verified === false             => false
 *  - absent block (null)            => false (fail closed, unlike consent)
 *  - verified missing/non-boolean   => false
 */
class PresenceTest extends TestCase
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

    /** A well-formed verified presence block as the platform returns it. */
    private function verifiedPresenceBlock(): array
    {
        return [
            'verified'    => true,
            'method'      => 'webauthn',
            'uv'          => true,
            'verified_at' => '2026-07-05T00:00:00Z',
        ];
    }

    private function introspectionResult(?array $presence): IntrospectionResult
    {
        return new IntrospectionResult(
            userId: 'user_42',
            connectionId: 'conn_abc',
            scopes: ['read:orders'],
            agentLabel: 'Test Agent',
            presence: $presence,
        );
    }

    // -------------------------------------------------------------------------
    // IntrospectionClient::verify() - presence block parsing
    // -------------------------------------------------------------------------

    public function testVerifyAttachesVerifiedPresenceBlock(): void
    {
        Http::fake(['*' => Http::response(
            $this->validPayload(['presence' => $this->verifiedPresenceBlock()]),
            200
        )]);
        $result = $this->client()->verify('ag_at_dummy');
        $this->assertSame($this->verifiedPresenceBlock(), $result->presence);
        $this->assertTrue($result->presenceVerified());
    }

    public function testVerifyAttachesUnverifiedPresenceBlock(): void
    {
        // Presence-off connection: block present, verified false.
        Http::fake(['*' => Http::response(
            $this->validPayload(['presence' => [
                'verified' => false, 'method' => null, 'uv' => null, 'verified_at' => null,
            ]]),
            200
        )]);
        $result = $this->client()->verify('ag_at_dummy');
        $this->assertFalse($result->presence['verified']);
        $this->assertFalse($result->presenceVerified());
    }

    public function testVerifyOmitsPresenceWhenServerDoesNotSendIt(): void
    {
        // Older servers: no presence block at all.
        Http::fake(['*' => Http::response($this->validPayload(), 200)]);
        $result = $this->client()->verify('ag_at_dummy');
        $this->assertNull($result->presence);
        $this->assertFalse($result->presenceVerified());
    }

    public function testVerifyTreatsCoercedVerifiedFlagAsAbsent(): void
    {
        // verified must be strictly boolean, like 'active'. Coerced or
        // missing values mean the whole block is treated as absent.
        foreach (['true', 1, null, ['nested' => true]] as $bad) {
            Http::fake(['*' => Http::response(
                $this->validPayload(['presence' => ['verified' => $bad]]),
                200
            )]);
            $result = $this->client()->verify('ag_at_dummy');
            $this->assertNull($result->presence);
            $this->assertFalse($result->presenceVerified());
        }
    }

    public function testVerifyTreatsPresenceBlockWithoutVerifiedAsAbsent(): void
    {
        Http::fake(['*' => Http::response(
            $this->validPayload(['presence' => ['method' => 'webauthn']]),
            200
        )]);
        $result = $this->client()->verify('ag_at_dummy');
        $this->assertNull($result->presence);
        $this->assertFalse($result->presenceVerified());
    }

    public function testVerifyTreatsNonObjectPresenceValueAsAbsent(): void
    {
        Http::fake(['*' => Http::response(
            $this->validPayload(['presence' => 'verified']),
            200
        )]);
        $result = $this->client()->verify('ag_at_dummy');
        $this->assertNull($result->presence);
        $this->assertFalse($result->presenceVerified());
    }

    // -------------------------------------------------------------------------
    // IntrospectionResult::presenceVerified() matrix
    // -------------------------------------------------------------------------

    public function testPresenceVerifiedFalseWhenBlockAbsent(): void
    {
        // Unlike consentGranted(), absence fails closed: no ceremony proven.
        $this->assertFalse($this->introspectionResult(null)->presenceVerified());
    }

    public function testPresenceVerifiedTrueWhenVerifiedIsBooleanTrue(): void
    {
        $this->assertTrue($this->introspectionResult(['verified' => true])->presenceVerified());
    }

    public function testPresenceVerifiedFalseWhenVerifiedIsBooleanFalse(): void
    {
        $this->assertFalse($this->introspectionResult(['verified' => false])->presenceVerified());
    }

    public function testPresenceVerifiedFalseWhenVerifiedMissing(): void
    {
        $this->assertFalse($this->introspectionResult([])->presenceVerified());
        $this->assertFalse($this->introspectionResult(['method' => 'webauthn'])->presenceVerified());
    }

    public function testPresenceVerifiedFalseWhenVerifiedIsStringTrue(): void
    {
        $this->assertFalse($this->introspectionResult(['verified' => 'true'])->presenceVerified());
    }

    public function testPresenceVerifiedFalseWhenVerifiedIsIntOne(): void
    {
        $this->assertFalse($this->introspectionResult(['verified' => 1])->presenceVerified());
    }

    public function testPresenceVerifiedFalseWhenVerifiedIsNull(): void
    {
        $this->assertFalse($this->introspectionResult(['verified' => null])->presenceVerified());
    }

    public function testPresenceVerifiedFalseWhenVerifiedIsArray(): void
    {
        $this->assertFalse($this->introspectionResult(['verified' => ['nested' => true]])->presenceVerified());
    }
}
