<?php

namespace AgentAdmit\Tests;

use AgentAdmit\AppAttestedPresence;
use AgentAdmit\TokensClient;
use Illuminate\Http\Client\Factory;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use PHPUnit\Framework\TestCase;

/**
 * Tests for app-attested presence: typed forwarding at token issuance (v1.9.0).
 *
 * TokensClient::issueToken() must:
 *  - include the full literal-true wire object
 *    presence {verified: true, uv: true, method, verified_at} when an
 *    AppAttestedPresence is provided, with verified_at RFC 3339 with explicit
 *    offset (the hosted contract; offset-less timestamps are rejected 400)
 *  - omit the key entirely when null (omitting the field is the only way to
 *    say "no ceremony")
 *
 * AppAttestedPresence must reject an out-of-contract method
 * (^[a-z0-9_]+$, 1-60) at construction, before any request. verified/uv are
 * literal true by construction and the class cannot represent anything else.
 * PHP DateTimeInterface always carries a timezone, so the offset-less
 * timestamp outage class is unrepresentable here.
 */
class AppAttestedPresenceTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Http::swap(new Factory());
        Log::swap(new class {
            public function __call($method, $args) { return null; }
        });
    }

    private function tokensClient(): TokensClient
    {
        return new TokensClient([
            'app_id'  => 'app_test123',
            'api_key' => 'aa_test_dummy',
            'api_url' => 'https://api.agentadmit.com',
        ]);
    }

    private function fakeIssueResponse(): void
    {
        Http::fake(['*' => Http::response(['token' => 'ag_ct_dummy', 'expires_in' => 900], 200)]);
    }

    private function ceremonyAt(): \DateTimeImmutable
    {
        return new \DateTimeImmutable('2026-08-13T17:00:00+00:00');
    }

    // -------------------------------------------------------------------------
    // issueToken() - outbound body
    // -------------------------------------------------------------------------

    public function testIssueTokenIncludesLiteralTrueWireObject(): void
    {
        $this->fakeIssueResponse();

        $this->tokensClient()->issueToken(
            'user_42',
            ['read:orders'],
            presence: new AppAttestedPresence('my_webauthn', $this->ceremonyAt())
        );

        Http::assertSent(function ($req) {
            $presence = $req['presence'] ?? null;
            return str_contains($req->url(), '/api/v1/apps/app_test123/token')
                && is_array($presence)
                && $presence['verified'] === true
                && $presence['uv'] === true
                && $presence['method'] === 'my_webauthn'
                && $presence['verified_at'] === '2026-08-13T17:00:00+00:00';
        });
    }

    public function testIssueTokenPreservesNonUtcOffset(): void
    {
        $this->fakeIssueResponse();

        $this->tokensClient()->issueToken(
            'user_42',
            ['read:orders'],
            presence: new AppAttestedPresence(
                'my_webauthn',
                new \DateTimeImmutable('2026-08-13T10:00:00-07:00')
            )
        );

        Http::assertSent(fn ($req) => $req['presence']['verified_at'] === '2026-08-13T10:00:00-07:00');
    }

    public function testIssueTokenAcceptsMutableDateTime(): void
    {
        $this->fakeIssueResponse();

        $this->tokensClient()->issueToken(
            'user_42',
            ['read:orders'],
            presence: new AppAttestedPresence(
                'my_webauthn',
                new \DateTime('2026-08-13T17:00:00+00:00')
            )
        );

        Http::assertSent(fn ($req) => $req['presence']['verified_at'] === '2026-08-13T17:00:00+00:00');
    }

    public function testIssueTokenOmitsPresenceKeyWhenNotProvided(): void
    {
        $this->fakeIssueResponse();

        $this->tokensClient()->issueToken('user_42', ['read:orders']);

        Http::assertSent(function ($req) {
            return str_contains($req->url(), '/api/v1/apps/app_test123/token')
                && !array_key_exists('presence', $req->data());
        });
    }

    public function testIssueTokenCarriesPresenceAlongsidePurposeAndIntent(): void
    {
        $this->fakeIssueResponse();

        $this->tokensClient()->issueToken(
            'user_42',
            ['read:orders'],
            purpose: 'Rebook my Tuesday class',
            userIntent: 'just rebook tuesday, nothing else',
            presence: new AppAttestedPresence('my_webauthn', $this->ceremonyAt())
        );

        Http::assertSent(function ($req) {
            return $req['purpose'] === 'Rebook my Tuesday class'
                && $req['user_intent'] === 'just rebook tuesday, nothing else'
                && $req['presence']['verified'] === true;
        });
    }

    // -------------------------------------------------------------------------
    // AppAttestedPresence - construction-time contract
    // -------------------------------------------------------------------------

    /** @dataProvider outOfContractMethods */
    public function testConstructionRejectsOutOfContractMethod(string $method): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/method must be/');

        new AppAttestedPresence($method, $this->ceremonyAt());
    }

    public static function outOfContractMethods(): array
    {
        return [
            'uppercase' => ['My_WebAuthn'],
            'space'     => ['my webauthn'],
            'hyphen'    => ['my-webauthn'],
            'empty'     => [''],
            '61 chars'  => [str_repeat('m', 61)],
        ];
    }

    public function testToWireIsTheExactHostedContractShape(): void
    {
        $wire = (new AppAttestedPresence('my_webauthn', $this->ceremonyAt()))->toWire();

        $this->assertSame(
            ['verified' => true, 'uv' => true, 'method' => 'my_webauthn', 'verified_at' => '2026-08-13T17:00:00+00:00'],
            $wire
        );
    }
}
