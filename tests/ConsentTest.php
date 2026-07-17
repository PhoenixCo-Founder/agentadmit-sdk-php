<?php

namespace AgentAdmit\Tests;

use AgentAdmit\AgentAdmitException;
use AgentAdmit\ConsentClient;
use AgentAdmit\IntrospectionResult;
use Illuminate\Http\Client\Factory;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use PHPUnit\Framework\TestCase;

/**
 * Tests for Consent Ledger fail-closed semantics.
 *
 * ConsentClient::checkConsent():
 *  - parses granted and denied verdicts on HTTP 200
 *  - throws on non-200 responses
 *  - throws on a 200 with a malformed (non-JSON or non-boolean granted) body
 *
 * IntrospectionResult::consentGranted():
 *  - absent consent block (null) => true, but absence is UNRESOLVED, not a
 *    grant: the hosted service omits the block when its consent-store read
 *    fails, and the CallerConsent middleware resolves a null block through
 *    the Consent Ledger instead of calling this helper
 *  - granted === true            => true
 *  - granted === false           => false
 *  - granted missing/non-boolean => false (malformed = deny)
 */
class ConsentTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Http::swap(new Factory());
        Log::swap(new class {
            public function __call($method, $args) { return null; }
        });
    }

    private function client(): ConsentClient
    {
        return new ConsentClient([
            'api_key' => 'aa_test_dummy',
            'app_id'  => 'app_test',
        ]);
    }

    /** Minimal valid verdict payload used as a baseline across tests. */
    private function verdictPayload(array $overrides = []): array
    {
        return array_merge([
            'granted'      => true,
            'caller_class' => ConsentClient::CALLER_CLASS_IN_APP_AI,
            'scope_group'  => null,
            'source'       => 'default',
            'evaluated_at' => '2026-07-03T00:00:00Z',
        ], $overrides);
    }

    private function introspectionResult(?array $consent): IntrospectionResult
    {
        return new IntrospectionResult(
            userId: 'user_42',
            connectionId: 'conn_abc',
            scopes: ['read:orders'],
            agentLabel: 'Test Agent',
            consent: $consent,
        );
    }

    // -------------------------------------------------------------------------
    // ConsentClient::checkConsent() - verdict parsing on 200
    // -------------------------------------------------------------------------

    public function testCheckConsentParsesGrantedVerdict(): void
    {
        Http::fake(['*' => Http::response($this->verdictPayload(['granted' => true]), 200)]);
        $verdict = $this->client()->checkConsent('user_42', ConsentClient::CALLER_CLASS_IN_APP_AI);
        $this->assertTrue($verdict['granted']);
        $this->assertSame(ConsentClient::CALLER_CLASS_IN_APP_AI, $verdict['caller_class']);
    }

    public function testCheckConsentParsesDeniedVerdict(): void
    {
        Http::fake(['*' => Http::response($this->verdictPayload(['granted' => false]), 200)]);
        $verdict = $this->client()->checkConsent('user_42', ConsentClient::CALLER_CLASS_HUMAN_SESSION);
        $this->assertFalse($verdict['granted']);
    }

    // -------------------------------------------------------------------------
    // ConsentClient::checkConsent() - error paths must throw (fail closed)
    // -------------------------------------------------------------------------

    public function testCheckConsentThrowsOnNon200Response(): void
    {
        $this->expectException(AgentAdmitException::class);
        Http::fake(['*' => Http::response(['error' => 'server_error'], 500)]);
        $this->client()->checkConsent('user_42', ConsentClient::CALLER_CLASS_IN_APP_AI);
    }

    public function testCheckConsentThrowsOn401Response(): void
    {
        $this->expectException(AgentAdmitException::class);
        Http::fake(['*' => Http::response(['error' => 'unauthorized'], 401)]);
        $this->client()->checkConsent('user_42', ConsentClient::CALLER_CLASS_IN_APP_AI);
    }

    public function testCheckConsentThrowsOnMalformedJson200Body(): void
    {
        $this->expectException(AgentAdmitException::class);
        Http::fake(['*' => Http::response('{not-valid-json', 200)]);
        $this->client()->checkConsent('user_42', ConsentClient::CALLER_CLASS_IN_APP_AI);
    }

    public function testCheckConsentThrowsOnNonBooleanGrantedIn200Body(): void
    {
        $this->expectException(AgentAdmitException::class);
        Http::fake(['*' => Http::response($this->verdictPayload(['granted' => 'true']), 200)]);
        $this->client()->checkConsent('user_42', ConsentClient::CALLER_CLASS_IN_APP_AI);
    }

    public function testCheckConsentRejectsUnknownCallerClass(): void
    {
        $this->expectException(AgentAdmitException::class);
        $this->client()->checkConsent('user_42', 'not_a_class');
    }

    // -------------------------------------------------------------------------
    // IntrospectionResult::consentGranted() matrix
    // -------------------------------------------------------------------------

    public function testConsentGrantedTrueWhenConsentBlockAbsent(): void
    {
        // Absent block: the helper alone cannot consult the ledger, so it
        // reports true — but absence is NOT a grant. Enforcement paths must
        // resolve a null block via ConsentClient::checkConsent(); the
        // CallerConsent middleware pins that in CallerConsentMiddlewareTest.
        $this->assertTrue($this->introspectionResult(null)->consentGranted());
    }

    public function testConsentGrantedTrueWhenGrantedIsBooleanTrue(): void
    {
        $this->assertTrue($this->introspectionResult(['granted' => true])->consentGranted());
    }

    public function testConsentGrantedFalseWhenGrantedIsBooleanFalse(): void
    {
        $this->assertFalse($this->introspectionResult(['granted' => false])->consentGranted());
    }

    public function testConsentGrantedFalseWhenGrantedMissing(): void
    {
        // Present consent block with no granted key: malformed = deny.
        $this->assertFalse($this->introspectionResult([])->consentGranted());
        $this->assertFalse($this->introspectionResult(['caller_class' => 'external_agent'])->consentGranted());
    }

    public function testConsentGrantedFalseWhenGrantedIsStringTrue(): void
    {
        $this->assertFalse($this->introspectionResult(['granted' => 'true'])->consentGranted());
    }

    public function testConsentGrantedFalseWhenGrantedIsIntOne(): void
    {
        $this->assertFalse($this->introspectionResult(['granted' => 1])->consentGranted());
    }

    public function testConsentGrantedFalseWhenGrantedIsNull(): void
    {
        $this->assertFalse($this->introspectionResult(['granted' => null])->consentGranted());
    }

    public function testConsentGrantedFalseWhenGrantedIsArray(): void
    {
        $this->assertFalse($this->introspectionResult(['granted' => ['nested' => true]])->consentGranted());
    }
}
