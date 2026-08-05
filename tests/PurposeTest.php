<?php

namespace AgentAdmit\Tests;

use AgentAdmit\IntrospectionClient;
use AgentAdmit\TokensClient;
use Illuminate\Http\Client\Factory;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use PHPUnit\Framework\TestCase;

/**
 * Tests for the declared purpose (v1.7.0).
 *
 * Declared purpose: the user-facing reason recorded on the grant at the
 * consent moment. Review-time record only, never an enforcement input;
 * authorization decisions ride scopes, connection status, and consent.
 *
 * TokensClient::issueToken() must:
 *  - include 'purpose' in the POST body when provided
 *  - omit the key entirely when not provided
 *  - reject purposes longer than 300 characters client-side
 *    (InvalidArgumentException, no request sent)
 *
 * IntrospectionClient::verify() must pass the nullable 'purpose' the hosted
 * /verify returns through to IntrospectionResult unchanged.
 */
class PurposeTest extends TestCase
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

    private function introspectionClient(): IntrospectionClient
    {
        return new class(['api_key' => 'aa_test_dummy']) extends IntrospectionClient {
            protected function waitBeforeRetry(int $totalMs): void {}
        };
    }

    /** Minimal valid verify payload used as a baseline across tests. */
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

    private function fakeIssueResponse(): void
    {
        Http::fake(['*' => Http::response(['token' => 'ag_ct_dummy', 'expires_in' => 900], 200)]);
    }

    // -------------------------------------------------------------------------
    // issueToken() - outbound body
    // -------------------------------------------------------------------------

    public function testIssueTokenIncludesPurposeInBody(): void
    {
        $this->fakeIssueResponse();

        $this->tokensClient()->issueToken(
            'user_42',
            ['read:orders'],
            purpose: 'Reorder the usual weekly groceries'
        );

        Http::assertSent(function ($req) {
            return str_contains($req->url(), '/api/v1/apps/app_test123/token')
                && $req['user_id'] === 'user_42'
                && $req['scopes'] === ['read:orders']
                && $req['purpose'] === 'Reorder the usual weekly groceries';
        });
    }

    public function testIssueTokenOmitsPurposeKeyWhenNotProvided(): void
    {
        $this->fakeIssueResponse();

        $this->tokensClient()->issueToken('user_42', ['read:orders']);

        Http::assertSent(function ($req) {
            return str_contains($req->url(), '/api/v1/apps/app_test123/token')
                && !array_key_exists('purpose', $req->data());
        });
    }

    public function testIssueTokenAcceptsPurposeAtExactly300Characters(): void
    {
        $this->fakeIssueResponse();

        $purpose = str_repeat('a', 300);
        $this->tokensClient()->issueToken('user_42', ['read:orders'], purpose: $purpose);

        Http::assertSent(fn ($req) => $req['purpose'] === $purpose);
    }

    // -------------------------------------------------------------------------
    // issueToken() - >300 character rejection
    // -------------------------------------------------------------------------

    public function testIssueTokenRejectsPurposeOver300Characters(): void
    {
        $this->fakeIssueResponse();

        try {
            $this->tokensClient()->issueToken(
                'user_42',
                ['read:orders'],
                purpose: str_repeat('a', 301)
            );
            $this->fail('Expected InvalidArgumentException for a 301-character purpose');
        } catch (\InvalidArgumentException $e) {
            $this->assertStringContainsString('300', $e->getMessage());
        }

        // Rejected client-side: nothing goes over the wire.
        Http::assertNothingSent();
    }

    // -------------------------------------------------------------------------
    // verify() - purpose pass-through from the hosted /verify
    // -------------------------------------------------------------------------

    public function testVerifyPassesPurposeThroughToResult(): void
    {
        Http::fake(['*' => Http::response(
            $this->validPayload(['purpose' => 'Reorder the usual weekly groceries']),
            200
        )]);

        $result = $this->introspectionClient()->verify('ag_at_dummy');

        $this->assertSame('Reorder the usual weekly groceries', $result->purpose);
    }

    public function testVerifyPurposeIsNullWhenServerOmitsIt(): void
    {
        Http::fake(['*' => Http::response($this->validPayload(), 200)]);
        $result = $this->introspectionClient()->verify('ag_at_dummy');
        $this->assertNull($result->purpose);
    }

    public function testVerifyPurposeIsNullWhenServerSendsExplicitNull(): void
    {
        // Hosted /verify declares purpose nullable; explicit null stays null.
        Http::fake(['*' => Http::response($this->validPayload(['purpose' => null]), 200)]);
        $result = $this->introspectionClient()->verify('ag_at_dummy');
        $this->assertNull($result->purpose);
    }

    public function testVerifyTreatsNonStringPurposeAsAbsent(): void
    {
        // Review-time record only: a malformed value never fails the verify,
        // it is simply treated as absent.
        foreach ([42, true, ['nested' => 'x']] as $bad) {
            Http::fake(['*' => Http::response($this->validPayload(['purpose' => $bad]), 200)]);
            $result = $this->introspectionClient()->verify('ag_at_dummy');
            $this->assertNull($result->purpose);
        }
    }
}
