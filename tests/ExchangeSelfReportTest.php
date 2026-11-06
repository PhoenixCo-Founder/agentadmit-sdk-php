<?php

namespace AgentAdmit\Tests;

use AgentAdmit\TokensClient;
use Illuminate\Http\Client\Factory;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use PHPUnit\Framework\TestCase;

/**
 * TokensClient::exchange() (v1.14.1): what the agent says it runs on
 * (agent_platform, agent_model) is passed along to the hosted exchange when
 * given and omitted when not. The exchange never sends the operator API key.
 */
class ExchangeSelfReportTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Http::swap(new Factory());
        Log::swap(new class {
            public function __call($method, $args) { return null; }
        });
        Http::fake(['*' => Http::response(['access_token' => 'ag_at_x', 'scopes' => ['read:orders']], 200)]);
    }

    private function tokensClient(): TokensClient
    {
        return new TokensClient([
            'app_id'  => 'app_test123',
            'api_key' => 'aa_test_dummy',
            'api_url' => 'https://api.agentadmit.com',
        ]);
    }

    public function testBareExchangeSendsOnlyTheTokenAndNoApiKey(): void
    {
        $result = $this->tokensClient()->exchange('ag_ct_abc');

        $this->assertSame('ag_at_x', $result['access_token']);
        $recorded = Http::recorded();
        $this->assertCount(1, $recorded);
        $request = $recorded[0][0];
        $this->assertSame('https://api.agentadmit.com/api/v1/exchange', $request->url());
        $this->assertSame(['token' => 'ag_ct_abc'], $request->data());
        $this->assertFalse($request->hasHeader('Authorization'));
    }

    public function testForwardsWhatTheAgentSaysItRunsOn(): void
    {
        $this->tokensClient()->exchange(
            'ag_ct_abc',
            agentLabel: 'My Agent',
            agentPlatform: 'ExampleAgent 2.1',
            agentModel: ['id' => 'example-model', 'version' => '2026-01'],
        );

        $this->assertSame([
            'token' => 'ag_ct_abc',
            'agent_label' => 'My Agent',
            'agent_platform' => 'ExampleAgent 2.1',
            'agent_model' => ['id' => 'example-model', 'version' => '2026-01'],
        ], Http::recorded()[0][0]->data());
    }

    public function testNullSelfReportIsOmitted(): void
    {
        $this->tokensClient()->exchange('ag_ct_abc', null, 'agent_1', null, null);

        $this->assertSame(
            ['token' => 'ag_ct_abc', 'agent_id' => 'agent_1'],
            Http::recorded()[0][0]->data()
        );
    }

    public function testPositionalCallFromBefore1141StillWorks(): void
    {
        $this->tokensClient()->exchange('ag_ct_abc', 'My Agent', 'agent_1');

        $this->assertSame(
            ['token' => 'ag_ct_abc', 'agent_label' => 'My Agent', 'agent_id' => 'agent_1'],
            Http::recorded()[0][0]->data()
        );
    }
}
