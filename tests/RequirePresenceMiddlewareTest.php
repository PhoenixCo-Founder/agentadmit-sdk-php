<?php

/**
 * Tests for the RequirePresence middleware (fail-closed WebAuthn presence
 * enforcement, agent-only).
 *
 * The middleware itself is exercised for real: this package's dev
 * dependencies do not ship the Laravel application container, so the two
 * framework helpers the middleware calls (config() and response()) are
 * shimmed below in the global namespace, mirroring exactly what the
 * framework would provide. Everything else (Request, JsonResponse,
 * Http::fake introspection responses) is the real thing.
 *
 * Covered paths, mirroring RequireScope's posture:
 *  - missing or non-agent bearer token       => 401 invalid_token
 *  - verified presence block                 => request passes through
 *  - unverified block / absent block         => 403 presence_required
 *  - malformed block (coerced verified flag) => 403 presence_required
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
    use AgentAdmit\Middleware\RequirePresence;
    use Illuminate\Http\Client\Factory;
    use Illuminate\Http\JsonResponse;
    use Illuminate\Http\Request;
    use Illuminate\Support\Facades\Http;
    use Illuminate\Support\Facades\Log;
    use PHPUnit\Framework\TestCase;
    use Symfony\Component\HttpFoundation\Response;

    class RequirePresenceMiddlewareTest extends TestCase
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

        private function middleware(): RequirePresence
        {
            $client = new class(['api_key' => 'aa_test_dummy']) extends IntrospectionClient {
                protected function waitBeforeRetry(int $totalMs): void {}
            };

            return new RequirePresence($client);
        }

        private function request(?string $token): Request
        {
            $request = Request::create('/api/orders', 'POST');
            if ($token !== null) {
                $request->headers->set('Authorization', 'Bearer ' . $token);
            }

            return $request;
        }

        /** Minimal valid introspection payload used as a baseline across tests. */
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

        /** Run the middleware and report whether $next was reached. */
        private function handle(Request $request, ?bool &$nextCalled = null): Response
        {
            $nextCalled = false;

            return $this->middleware()->handle($request, function (Request $req) use (&$nextCalled): Response {
                $nextCalled = true;

                return new JsonResponse(['ok' => true], 200);
            });
        }

        private function body(Response $response): array
        {
            return json_decode($response->getContent(), true);
        }

        // ---------------------------------------------------------------------
        // Missing / non-agent tokens (mirrors RequireScope: 401 invalid_token)
        // ---------------------------------------------------------------------

        public function testMissingTokenReturns401(): void
        {
            $response = $this->handle($this->request(null), $nextCalled);

            $this->assertSame(401, $response->getStatusCode());
            $this->assertSame([
                'error' => 'invalid_token',
                'error_description' => 'AgentAdmit token required',
            ], $this->body($response));
            $this->assertFalse($nextCalled);
        }

        public function testNonAgentTokenReturns401(): void
        {
            $response = $this->handle($this->request('some_session_cookie_token'), $nextCalled);

            $this->assertSame(401, $response->getStatusCode());
            $this->assertSame('invalid_token', $this->body($response)['error']);
            $this->assertFalse($nextCalled);
        }

        // ---------------------------------------------------------------------
        // Pass path: verified presence block
        // ---------------------------------------------------------------------

        public function testVerifiedPresencePassesAndSetsRequestAttributes(): void
        {
            Http::fake(['*' => Http::response($this->validPayload(['presence' => [
                'verified'    => true,
                'method'      => 'webauthn',
                'uv'          => true,
                'verified_at' => '2026-07-05T00:00:00Z',
            ]]), 200)]);

            $request = $this->request('ag_at_dummy');
            $response = $this->handle($request, $nextCalled);

            $this->assertSame(200, $response->getStatusCode());
            $this->assertTrue($nextCalled);
            $this->assertSame('agent', $request->attributes->get('agentadmit.auth_type'));
            $this->assertSame('user_42', $request->attributes->get('agentadmit.user_id'));
            $this->assertSame(['read:orders'], $request->attributes->get('agentadmit.scopes'));
            $this->assertSame('conn_abc', $request->attributes->get('agentadmit.connection_id'));
            $this->assertSame('Test Agent', $request->attributes->get('agentadmit.agent_label'));
        }

        // ---------------------------------------------------------------------
        // 403 presence_required paths (fail closed)
        // ---------------------------------------------------------------------

        /** Exact 403 body the middleware must produce for every deny path. */
        private function assertPresenceRequired403(Response $response, bool $nextCalled): void
        {
            $this->assertSame(403, $response->getStatusCode());
            $this->assertSame([
                'error' => 'presence_required',
                'error_description' => 'This action requires a connection authorized with human presence verification.',
            ], $this->body($response));
            $this->assertFalse($nextCalled);
        }

        public function testUnverifiedPresenceBlockReturns403(): void
        {
            Http::fake(['*' => Http::response($this->validPayload(['presence' => [
                'verified' => false, 'method' => null, 'uv' => null, 'verified_at' => null,
            ]]), 200)]);

            $response = $this->handle($this->request('ag_at_dummy'), $nextCalled);
            $this->assertPresenceRequired403($response, $nextCalled);
        }

        public function testAbsentPresenceBlockReturns403(): void
        {
            // Older servers never send the block: still fail closed.
            Http::fake(['*' => Http::response($this->validPayload(), 200)]);

            $response = $this->handle($this->request('ag_at_dummy'), $nextCalled);
            $this->assertPresenceRequired403($response, $nextCalled);
        }

        public function testCoercedVerifiedFlagReturns403(): void
        {
            foreach (['true', 1, null] as $bad) {
                Http::fake(['*' => Http::response(
                    $this->validPayload(['presence' => ['verified' => $bad]]),
                    200
                )]);

                $response = $this->handle($this->request('ag_at_dummy'), $nextCalled);
                $this->assertPresenceRequired403($response, $nextCalled);
            }
        }

        // ---------------------------------------------------------------------
        // Introspection failures (mirrors RequireScope's generic messages)
        // ---------------------------------------------------------------------

        public function testInactiveTokenReturns401WithGenericMessage(): void
        {
            Http::fake(['*' => Http::response([
                'active' => false, 'error' => 'token_revoked',
            ], 200)]);

            $response = $this->handle($this->request('ag_at_dummy'), $nextCalled);

            $this->assertSame(401, $response->getStatusCode());
            $this->assertSame([
                'error' => 'invalid_token',
                'error_description' => 'Token is invalid or not authorized.',
            ], $this->body($response));
            $this->assertFalse($nextCalled);
        }

        public function testServiceErrorReturns502WithGenericMessage(): void
        {
            Http::fake(['*' => Http::response(['error' => 'server_error'], 500)]);

            $response = $this->handle($this->request('ag_at_dummy'), $nextCalled);

            $this->assertSame(502, $response->getStatusCode());
            $this->assertSame([
                'error' => 'introspection_failed',
                'error_description' => 'Token verification failed. Please try again.',
            ], $this->body($response));
            $this->assertFalse($nextCalled);
        }
    }
}
