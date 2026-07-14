<?php

/**
 * Tests for the CallerConsent middleware (classify caller, then gate the
 * right independent consent path).
 *
 * The middleware is exercised for real; the two framework helpers it calls
 * (config() and response()) are shimmed below in the global namespace,
 * mirroring exactly what the framework would provide (same pattern as
 * RequirePresenceMiddlewareTest). Http::fake supplies introspection and
 * Consent Ledger responses.
 *
 * Covered invariants:
 *  - classification is derived from credential structure, before any consent
 *    check, and cannot be self-selected;
 *  - each class routes to its OWN isolated path (the human path never calls
 *    the ledger by default);
 *  - fail closed on a denied verdict or an unreachable ledger.
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

    use AgentAdmit\ConsentClient;
    use AgentAdmit\IntrospectionClient;
    use AgentAdmit\Middleware\CallerConsent;
    use Illuminate\Http\Client\Factory;
    use Illuminate\Http\JsonResponse;
    use Illuminate\Http\Request;
    use Illuminate\Support\Facades\Http;
    use Illuminate\Support\Facades\Log;
    use PHPUnit\Framework\TestCase;
    use Symfony\Component\HttpFoundation\Response;

    class CallerConsentMiddlewareTest extends TestCase
    {
        protected function setUp(): void
        {
            parent::setUp();
            Http::swap(new Factory());
            Log::swap(new class {
                public function __call($method, $args) { return null; }
            });
            $GLOBALS['__agentadmit_test_config'] = [];
        }

        private function middleware(): CallerConsent
        {
            $introspection = new class(['api_key' => 'aa_test_dummy']) extends IntrospectionClient {
                protected function waitBeforeRetry(int $totalMs): void {}
            };
            $consent = new ConsentClient(['api_key' => 'aa_test_dummy', 'app_id' => 'app_test']);

            return new CallerConsent($introspection, $consent);
        }

        private function agentRequest(): Request
        {
            $request = Request::create('/api/records', 'GET');
            $request->headers->set('Authorization', 'Bearer ag_at_dummy_token');

            return $request;
        }

        private function humanRequest(): Request
        {
            $request = Request::create('/api/records', 'GET');
            $request->headers->set('Authorization', 'Bearer session_jwt');

            return $request;
        }

        private function validPayload(array $overrides = []): array
        {
            return array_merge([
                'active'        => true,
                'user_id'       => 'user_42',
                'connection_id' => 'conn_abc',
                'scopes'        => ['read:records'],
                'agent_label'   => 'Test Agent',
            ], $overrides);
        }

        private function handle(Request $request, ?bool &$nextCalled = null, ?string $scope = null): Response
        {
            $nextCalled = false;

            return $this->middleware()->handle($request, function (Request $req) use (&$nextCalled): Response {
                $nextCalled = true;

                return new JsonResponse(['ok' => true], 200);
            }, $scope);
        }

        private function body(Response $response): array
        {
            return json_decode($response->getContent(), true);
        }

        private function useInternalAiClassifier(): void
        {
            $GLOBALS['__agentadmit_test_config']['agentadmit.caller_consent.classify_non_agent'] =
                fn (Request $r) => $r->headers->get('x-internal-ai') === 'secret'
                    ? ConsentClient::CALLER_CLASS_IN_APP_AI
                    : ConsentClient::CALLER_CLASS_HUMAN_SESSION;
        }

        // -------------------------------------------------------------------
        // classifyCaller
        // -------------------------------------------------------------------

        public function testClassifiesAgentTokenAsExternalAgent(): void
        {
            $this->assertSame('external_agent', $this->middleware()->classifyCaller($this->agentRequest()));
        }

        public function testClassifiesNonAgentAsHumanByDefault(): void
        {
            $this->assertSame('human_session', $this->middleware()->classifyCaller($this->humanRequest()));
        }

        public function testHonorsNonAgentClassifierForInAppAi(): void
        {
            $this->useInternalAiClassifier();
            $request = Request::create('/api/records', 'GET');
            $request->headers->set('x-internal-ai', 'secret');

            $this->assertSame('in_app_ai', $this->middleware()->classifyCaller($request));
        }

        // -------------------------------------------------------------------
        // external_agent path
        // -------------------------------------------------------------------

        public function testExternalAgentAllowsWithRequiredScope(): void
        {
            Http::fake(['*' => Http::response($this->validPayload())]);

            $request = $this->agentRequest();
            $response = $this->handle($request, $nextCalled, 'read:records');

            $this->assertTrue($nextCalled);
            $this->assertSame('external_agent', $request->attributes->get('agentadmit.caller_class'));
            $this->assertSame('agent', $request->attributes->get('agentadmit.auth_type'));
        }

        public function testExternalAgentDeniedOnMissingScope(): void
        {
            Http::fake(['*' => Http::response($this->validPayload())]);

            $response = $this->handle($this->agentRequest(), $nextCalled, 'write:records');

            $this->assertFalse($nextCalled);
            $this->assertSame(403, $response->getStatusCode());
            $this->assertSame('insufficient_scope', $this->body($response)['error']);
        }

        public function testExternalAgentDeniedWhenConsentDenied(): void
        {
            Http::fake(['*' => Http::response($this->validPayload([
                'consent' => ['caller_class' => 'external_agent', 'granted' => false, 'source' => 'setting'],
            ]))]);

            $response = $this->handle($this->agentRequest(), $nextCalled);

            $this->assertFalse($nextCalled);
            $this->assertSame(403, $response->getStatusCode());
            $this->assertSame('consent_not_granted', $this->body($response)['error']);
        }

        public function testExternalAgentAllowsWhenNoConsentBlock(): void
        {
            Http::fake(['*' => Http::response($this->validPayload())]);

            $this->handle($this->agentRequest(), $nextCalled);

            $this->assertTrue($nextCalled);
        }

        public function testExternalAgentRejectedOnInvalidToken(): void
        {
            Http::fake(['*' => Http::response(['active' => false, 'error' => 'invalid_token'])]);

            $response = $this->handle($this->agentRequest(), $nextCalled);

            $this->assertFalse($nextCalled);
            $this->assertSame(401, $response->getStatusCode());
        }

        // -------------------------------------------------------------------
        // in_app_ai path
        // -------------------------------------------------------------------

        private function configureInternalAi(): void
        {
            $this->useInternalAiClassifier();
            $GLOBALS['__agentadmit_test_config']['agentadmit.caller_consent.resolve_data_owner_id'] =
                fn (Request $r) => 'user_8842';
        }

        private function internalAiRequest(): Request
        {
            $request = Request::create('/api/records', 'GET');
            $request->headers->set('x-internal-ai', 'secret');

            return $request;
        }

        public function testInAppAiAllowsWhenGranted(): void
        {
            $this->configureInternalAi();
            Http::fake(['*' => Http::response([
                'caller_class' => 'in_app_ai', 'granted' => true, 'source' => 'setting', 'evaluated_at' => 'x',
            ])]);

            $request = $this->internalAiRequest();
            $this->handle($request, $nextCalled);

            $this->assertTrue($nextCalled);
            $this->assertSame('in_app_ai', $request->attributes->get('agentadmit.auth_type'));
        }

        public function testInAppAiDeniedWhenDenied(): void
        {
            $this->configureInternalAi();
            Http::fake(['*' => Http::response([
                'caller_class' => 'in_app_ai', 'granted' => false, 'source' => 'setting', 'evaluated_at' => 'x',
            ])]);

            $response = $this->handle($this->internalAiRequest(), $nextCalled);

            $this->assertFalse($nextCalled);
            $this->assertSame(403, $response->getStatusCode());
            $this->assertSame('in_app_ai', $this->body($response)['caller_class']);
        }

        public function testInAppAiFailsClosedWhenLedgerErrors(): void
        {
            $this->configureInternalAi();
            Http::fake(['*' => Http::response(['error' => 'server_error'], 500)]);

            $response = $this->handle($this->internalAiRequest(), $nextCalled);

            $this->assertFalse($nextCalled);
            $this->assertSame(503, $response->getStatusCode());
            $this->assertSame('consent_unavailable', $this->body($response)['error']);
        }

        public function testInAppAiRequiresOwnerResolver(): void
        {
            $this->useInternalAiClassifier();

            $response = $this->handle($this->internalAiRequest(), $nextCalled);

            $this->assertFalse($nextCalled);
            $this->assertSame(500, $response->getStatusCode());
        }

        // -------------------------------------------------------------------
        // human_session path
        // -------------------------------------------------------------------

        public function testHumanDefersWithoutLedgerCall(): void
        {
            Http::fake(['*' => Http::response([], 500)]); // any ledger call would 500 -> fail

            $request = $this->humanRequest();
            $this->handle($request, $nextCalled);

            $this->assertTrue($nextCalled, 'human path must continue by default');
            $this->assertSame('human_session', $request->attributes->get('agentadmit.caller_class'));
            $this->assertSame('user', $request->attributes->get('agentadmit.auth_type'));
            Http::assertNothingSent();
        }

        public function testHumanGatedWhenGateHumanSet(): void
        {
            $GLOBALS['__agentadmit_test_config']['agentadmit.caller_consent.gate_human'] = true;
            $GLOBALS['__agentadmit_test_config']['agentadmit.caller_consent.resolve_data_owner_id'] =
                fn (Request $r) => 'user_1';
            Http::fake(['*' => Http::response([
                'caller_class' => 'human_session', 'granted' => false, 'source' => 'setting', 'evaluated_at' => 'x',
            ])]);

            $response = $this->handle($this->humanRequest(), $nextCalled);

            $this->assertFalse($nextCalled);
            $this->assertSame(403, $response->getStatusCode());
            $this->assertSame('human_session', $this->body($response)['caller_class']);
        }
    }
}
