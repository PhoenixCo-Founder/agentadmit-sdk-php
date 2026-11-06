<?php

/**
 * Tests for agent designation (v1.14.0).
 *
 * The hosted /verify response carries what the USER said a connection is for
 * (designated_agent) and what the AGENT reported about itself
 * (agent_reported). IntrospectionClient::verify() must pass both through to
 * IntrospectionResult, and the middleware must set them as request
 * attributes. Review-time records only: a malformed block is dropped and
 * never fails the verify.
 */

namespace {
    if (!function_exists('config')) {
        function config(?string $key = null, $default = null)
        {
            return $GLOBALS['__agentadmit_test_config'][$key] ?? $default;
        }
    }

    if (!function_exists('response')) {
        function response()
        {
            return new class {
                public function json(array $data = [], int $status = 200): \Illuminate\Http\JsonResponse
                {
                    return new \Illuminate\Http\JsonResponse($data, $status);
                }
            };
        }
    }
}

namespace AgentAdmit\Tests {

    use AgentAdmit\IntrospectionClient;
    use AgentAdmit\Middleware\RequireScope;
    use Illuminate\Http\Client\Factory;
    use Illuminate\Http\JsonResponse;
    use Illuminate\Http\Request;
    use Illuminate\Support\Facades\Http;
    use Illuminate\Support\Facades\Log;
    use PHPUnit\Framework\TestCase;
    use Symfony\Component\HttpFoundation\Response;

    class AgentDesignationTest extends TestCase
    {
        private const LISTED = [
            'agent_id' => 'agt_openclaw',
            'name'     => 'OpenClaw',
            'source'   => 'user_declared',
            'model'    => ['model_id' => 'mdl_claude', 'name' => 'Claude (Anthropic)'],
        ];

        protected function setUp(): void
        {
            parent::setUp();
            Http::swap(new Factory());
            Log::swap(new class {
                public function __call($method, $args) { return null; }
            });
            $GLOBALS['__agentadmit_test_config'] = [];
        }

        private function client(): IntrospectionClient
        {
            return new class([
                'api_key' => 'aa_test_dummy',
                'api_url' => 'http://127.0.0.1:3003',
            ]) extends IntrospectionClient {
                protected function waitBeforeRetry(int $totalMs): void {}
            };
        }

        private function validPayload(array $overrides = []): array
        {
            return array_merge([
                'active'        => true,
                'user_id'       => 'user_42',
                'connection_id' => 'conn_abc',
                'scopes'        => ['read:orders'],
                'agent_label'   => 'my-agent',
            ], $overrides);
        }

        private function verifyWith(array $overrides)
        {
            Http::fake(['*' => Http::response($this->validPayload($overrides), 200)]);

            return $this->client()->verify('ag_at_dummy');
        }

        // ── verify pass-through ─────────────────────────────────────────

        public function testUserDesignationReachesTheResult(): void
        {
            $result = $this->verifyWith(['designated_agent' => self::LISTED]);
            $this->assertSame(self::LISTED, $result->designatedAgent);
        }

        public function testAgentLabelStaysSeparateFromTheDesignation(): void
        {
            $result = $this->verifyWith(['designated_agent' => self::LISTED]);
            $this->assertSame('my-agent', $result->agentLabel);
            $this->assertSame('OpenClaw', $result->designatedAgent['name']);
        }

        public function testTypedNameHasNullAgentIdAndNoModelIsNull(): void
        {
            $result = $this->verifyWith(['designated_agent' => [
                'agent_id' => null, 'name' => 'My Home Agent', 'source' => 'user_declared', 'model' => null,
            ]]);
            $this->assertNull($result->designatedAgent['agent_id']);
            $this->assertSame('My Home Agent', $result->designatedAgent['name']);
            $this->assertNull($result->designatedAgent['model']);
        }

        public function testWireNullIsNoDesignation(): void
        {
            $result = $this->verifyWith(['designated_agent' => null, 'agent_reported' => null]);
            $this->assertNull($result->designatedAgent);
            $this->assertNull($result->agentReported);
        }

        public function testAbsentFieldsAreNullForOlderServers(): void
        {
            $result = $this->verifyWith([]);
            $this->assertNull($result->designatedAgent);
            $this->assertNull($result->agentReported);
        }

        public function testAgentReportedReachesTheResult(): void
        {
            $reported = ['platform' => 'openclaw', 'model' => ['id' => 'claude-fable-5-1', 'version' => '2026-09']];
            $result = $this->verifyWith(['agent_reported' => $reported]);
            $this->assertSame($reported, $result->agentReported);
        }

        public function testBothRecordsAreCarriedIndependently(): void
        {
            $result = $this->verifyWith([
                'designated_agent' => self::LISTED,
                'agent_reported'   => ['platform' => 'other-runtime', 'model' => ['id' => 'gpt-6']],
            ]);
            $this->assertSame('OpenClaw', $result->designatedAgent['name']);
            $this->assertSame('other-runtime', $result->agentReported['platform']);
            $this->assertSame(['id' => 'gpt-6', 'version' => null], $result->agentReported['model']);
        }

        public function testMalformedDesignationIsDroppedAndNeverFailsTheCall(): void
        {
            $bad = [
                'OpenClaw',
                ['OpenClaw'],
                42,
                ['name' => 'OpenClaw'],
                ['name' => 'OpenClaw', 'source' => 'verified'],
                ['name' => '', 'source' => 'user_declared'],
                ['name' => 7, 'source' => 'user_declared'],
            ];
            foreach ($bad as $value) {
                $result = $this->verifyWith(['designated_agent' => $value, 'agent_reported' => 'x']);
                $this->assertNull($result->designatedAgent, json_encode($value) . ' should be dropped');
                $this->assertNull($result->agentReported);
                $this->assertSame('user_42', $result->userId);
                $this->assertSame(['read:orders'], $result->scopes);
            }
        }

        // ── readers ─────────────────────────────────────────────────────

        public function testMalformedModelIsDroppedAndTheAppIsKept(): void
        {
            foreach (['Claude', ['model_id' => 'mdl_1'], ['name' => ''], ['name' => 5], []] as $model) {
                $out = IntrospectionClient::parseDesignatedAgent([
                    'agent_id' => 'agt_1', 'name' => 'OpenClaw', 'source' => 'user_declared', 'model' => $model,
                ]);
                $this->assertSame('OpenClaw', $out['name']);
                $this->assertNull($out['model'], json_encode($model) . ' should be dropped');
            }
        }

        public function testModelNamedWithoutAListedIdHasNullModelId(): void
        {
            $out = IntrospectionClient::parseDesignatedAgent([
                'name' => 'OpenClaw', 'source' => 'user_declared',
                'model' => ['model_id' => 9, 'name' => 'A local model'],
            ]);
            $this->assertNull($out['agent_id']);
            $this->assertSame(['model_id' => null, 'name' => 'A local model'], $out['model']);
        }

        public function testUnknownKeysAreNotCarried(): void
        {
            $out = IntrospectionClient::parseDesignatedAgent([
                'name' => 'OpenClaw', 'source' => 'user_declared', 'verified' => true,
            ]);
            $this->assertSame(['agent_id', 'name', 'source', 'model'], array_keys($out));
        }

        public function testDesignationReaderReturnsNullForAnythingElse(): void
        {
            $bad = [null, 'x', 1, [], ['name' => 'A'], ['name' => 'A', 'source' => 'operator_verified'],
                ['source' => 'user_declared']];
            foreach ($bad as $value) {
                $this->assertNull(IntrospectionClient::parseDesignatedAgent($value), json_encode($value));
            }
        }

        public function testAgentReportedPlatformOnlyModelOnlyAndNonStringVersion(): void
        {
            $this->assertSame(
                ['platform' => 'openclaw', 'model' => null],
                IntrospectionClient::parseAgentReported(['platform' => 'openclaw'])
            );
            $this->assertSame(
                ['platform' => null, 'model' => ['id' => 'm', 'version' => null]],
                IntrospectionClient::parseAgentReported(['model' => ['id' => 'm']])
            );
            $this->assertSame(
                ['platform' => null, 'model' => ['id' => 'm', 'version' => null]],
                IntrospectionClient::parseAgentReported(['platform' => 3, 'model' => ['id' => 'm', 'version' => 5.1]])
            );
        }

        public function testAgentReportedReaderReturnsNullWithNeitherPlatformNorModelId(): void
        {
            $bad = [null, 'x', [], ['platform' => ''], ['model' => []], ['model' => ['version' => '1']],
                ['platform' => null, 'model' => ['id' => '']]];
            foreach ($bad as $value) {
                $this->assertNull(IntrospectionClient::parseAgentReported($value), json_encode($value));
            }
        }

        // ── middleware attributes ───────────────────────────────────────

        private function runMiddleware(array $overrides): Request
        {
            Http::fake(['*/api/v1/verify' => Http::response($this->validPayload($overrides), 200)]);
            $request = Request::create('/api/orders', 'GET');
            $request->headers->set('Authorization', 'Bearer ag_at_dummy');
            $response = (new RequireScope($this->client()))->handle(
                $request,
                fn (Request $r): Response => new JsonResponse(['ok' => true], 200),
                'read:orders'
            );
            $this->assertSame(200, $response->getStatusCode());

            return $request;
        }

        public function testMiddlewareSetsBothAttributesWhenPresent(): void
        {
            $reported = ['platform' => 'openclaw', 'model' => null];
            $request = $this->runMiddleware(['designated_agent' => self::LISTED, 'agent_reported' => $reported]);
            $this->assertSame(self::LISTED, $request->attributes->get('agentadmit.designated_agent'));
            $this->assertSame($reported, $request->attributes->get('agentadmit.agent_reported'));
            $this->assertSame('my-agent', $request->attributes->get('agentadmit.agent_label'));
        }

        public function testMiddlewareLeavesAttributesUnsetWhenAbsentOrMalformed(): void
        {
            $request = $this->runMiddleware(['designated_agent' => ['name' => 'OpenClaw']]);
            $this->assertFalse($request->attributes->has('agentadmit.designated_agent'));
            $this->assertFalse($request->attributes->has('agentadmit.agent_reported'));
        }
    }
}
