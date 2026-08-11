<?php

namespace AgentAdmit\Tests;

use AgentAdmit\IntrospectionClient;
use AgentAdmit\TokensClient;
use Illuminate\Http\Client\Factory;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use PHPUnit\Framework\TestCase;

/**
 * Tests for the user-declared intent (v1.8.0).
 *
 * User-declared intent: the USER's own words, typed by the human at the
 * consent moment (distinct from the declared purpose, which is the app's
 * words). Review-time record only, never an enforcement input; authorization
 * decisions ride scopes, connection status, and consent.
 *
 * TokensClient::issueToken() must:
 *  - include 'user_intent' in the POST body when a valid string is provided
 *  - omit the key entirely when not provided
 *  - normalize malformed values to absent (metadata tolerance, never a
 *    rejection - the cross-SDK parity convention): non-string, empty string,
 *    and >300-character values all mean the key is omitted while the request
 *    still goes out
 *
 * IntrospectionClient::verify() must pass the nullable 'user_intent' the
 * hosted /verify returns through to IntrospectionResult unchanged.
 */
class UserIntentTest extends TestCase
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

    public function testIssueTokenIncludesUserIntentInBody(): void
    {
        $this->fakeIssueResponse();

        $this->tokensClient()->issueToken(
            'user_42',
            ['read:orders'],
            userIntent: 'get my usual Tuesday order'
        );

        Http::assertSent(function ($req) {
            return str_contains($req->url(), '/api/v1/apps/app_test123/token')
                && $req['user_id'] === 'user_42'
                && $req['scopes'] === ['read:orders']
                && $req['user_intent'] === 'get my usual Tuesday order';
        });
    }

    public function testIssueTokenOmitsUserIntentKeyWhenNotProvided(): void
    {
        $this->fakeIssueResponse();

        $this->tokensClient()->issueToken('user_42', ['read:orders']);

        Http::assertSent(function ($req) {
            return str_contains($req->url(), '/api/v1/apps/app_test123/token')
                && !array_key_exists('user_intent', $req->data());
        });
    }

    public function testIssueTokenAcceptsUserIntentAtExactly300Characters(): void
    {
        $this->fakeIssueResponse();

        $userIntent = str_repeat('a', 300);
        $this->tokensClient()->issueToken('user_42', ['read:orders'], userIntent: $userIntent);

        Http::assertSent(fn ($req) => $req['user_intent'] === $userIntent);
    }

    public function testIssueTokenCarriesPurposeAndUserIntentTogether(): void
    {
        // Distinct fields, distinct words: the app's purpose and the user's
        // own intent ride the same request side by side.
        $this->fakeIssueResponse();

        $this->tokensClient()->issueToken(
            'user_42',
            ['read:orders'],
            purpose: 'Reorder the usual weekly groceries',
            userIntent: 'get my usual Tuesday order'
        );

        Http::assertSent(function ($req) {
            return $req['purpose'] === 'Reorder the usual weekly groceries'
                && $req['user_intent'] === 'get my usual Tuesday order';
        });
    }

    // -------------------------------------------------------------------------
    // issueToken() - malformed values normalize to absent (never a rejection)
    // -------------------------------------------------------------------------

    public function testIssueTokenNormalizesUserIntentOver300CharactersToAbsent(): void
    {
        // Unlike purpose (client-side InvalidArgumentException), a too-long
        // user intent is metadata tolerance: the request still goes out, the
        // key is simply omitted.
        $this->fakeIssueResponse();

        $this->tokensClient()->issueToken(
            'user_42',
            ['read:orders'],
            userIntent: str_repeat('a', 301)
        );

        Http::assertSent(function ($req) {
            return str_contains($req->url(), '/api/v1/apps/app_test123/token')
                && !array_key_exists('user_intent', $req->data());
        });
    }

    public function testIssueTokenNormalizesEmptyStringUserIntentToAbsent(): void
    {
        $this->fakeIssueResponse();

        $this->tokensClient()->issueToken('user_42', ['read:orders'], userIntent: '');

        Http::assertSent(fn ($req) => !array_key_exists('user_intent', $req->data()));
    }

    public function testIssueTokenNormalizesNonStringUserIntentToAbsent(): void
    {
        // Metadata tolerance, never a rejection: malformed values are treated
        // as absent, and the request itself still succeeds.
        foreach ([42, true, ['nested' => 'x'], 3.14] as $bad) {
            Http::swap(new Factory());
            $this->fakeIssueResponse();

            $this->tokensClient()->issueToken('user_42', ['read:orders'], userIntent: $bad);

            Http::assertSent(function ($req) {
                return str_contains($req->url(), '/api/v1/apps/app_test123/token')
                    && !array_key_exists('user_intent', $req->data());
            });
        }
    }

    // -------------------------------------------------------------------------
    // verify() - user_intent pass-through from the hosted /verify
    // -------------------------------------------------------------------------

    public function testVerifyPassesUserIntentThroughToResult(): void
    {
        Http::fake(['*' => Http::response(
            $this->validPayload(['user_intent' => 'get my usual Tuesday order']),
            200
        )]);

        $result = $this->introspectionClient()->verify('ag_at_dummy');

        $this->assertSame('get my usual Tuesday order', $result->userIntent);
    }

    public function testVerifyCarriesPurposeAndUserIntentIndependently(): void
    {
        Http::fake(['*' => Http::response(
            $this->validPayload([
                'purpose'     => 'Reorder the usual weekly groceries',
                'user_intent' => 'get my usual Tuesday order',
            ]),
            200
        )]);

        $result = $this->introspectionClient()->verify('ag_at_dummy');

        $this->assertSame('Reorder the usual weekly groceries', $result->purpose);
        $this->assertSame('get my usual Tuesday order', $result->userIntent);
    }

    public function testVerifyUserIntentIsNullWhenServerOmitsIt(): void
    {
        Http::fake(['*' => Http::response($this->validPayload(), 200)]);
        $result = $this->introspectionClient()->verify('ag_at_dummy');
        $this->assertNull($result->userIntent);
    }

    public function testVerifyUserIntentIsNullWhenServerSendsExplicitNull(): void
    {
        // Hosted /verify declares user_intent nullable; explicit null stays null.
        Http::fake(['*' => Http::response($this->validPayload(['user_intent' => null]), 200)]);
        $result = $this->introspectionClient()->verify('ag_at_dummy');
        $this->assertNull($result->userIntent);
    }

    public function testVerifyTreatsNonStringUserIntentAsAbsent(): void
    {
        // Review-time record only: a malformed value never fails the verify,
        // it is simply treated as absent.
        foreach ([42, true, ['nested' => 'x']] as $bad) {
            Http::fake(['*' => Http::response($this->validPayload(['user_intent' => $bad]), 200)]);
            $result = $this->introspectionClient()->verify('ag_at_dummy');
            $this->assertNull($result->userIntent);
        }
    }
}
