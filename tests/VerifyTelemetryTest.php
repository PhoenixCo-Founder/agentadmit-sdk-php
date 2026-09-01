<?php

/**
 * Tests for SDK 1.10 - per-call verification telemetry + active-error
 * fail-closed (semantic matrix sections 1, 4, 5, 6).
 *
 * Request-side (matrix section 1): the verify POST body gains optional
 * scope_used / endpoint / method - sent when known, omitted entirely when
 * not (never null / empty string). endpoint is path only (query stripped,
 * 500-char cap); method is uppercased (20-char cap).
 *
 * Response-side (matrix section 4): an introspection response with
 * active: true AND a string error field is a DENIAL, never a pass-through:
 *   insufficient_scope -> 403 step-up shape {error, required_scope, granted_scopes}
 *   bound_exceeded     -> 403 hosted fields passed through verbatim
 *   unknown code       -> 403 generic fail-closed
 * In every denial the request handler ($next) must NOT be invoked.
 *
 * The middleware is exercised for real; the two framework helpers it calls
 * (config() and response()) are shimmed below in the global namespace,
 * mirroring RequirePresenceMiddlewareTest. Request bodies are captured with
 * Http::fake + Http::recorded.
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
    use AgentAdmit\Middleware\RequirePresence;
    use AgentAdmit\Middleware\RequireScope;
    use AgentAdmit\Middleware\RequireScopeIfAgent;
    use AgentAdmit\VerificationDeniedException;
    use Illuminate\Http\Client\Factory;
    use Illuminate\Http\JsonResponse;
    use Illuminate\Http\Request;
    use Illuminate\Support\Facades\Http;
    use Illuminate\Support\Facades\Log;
    use PHPUnit\Framework\TestCase;
    use Symfony\Component\HttpFoundation\Response;

    class VerifyTelemetryTest extends TestCase
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

        private function client(): IntrospectionClient
        {
            return new class(['api_key' => 'aa_test_dummy']) extends IntrospectionClient {
                protected function waitBeforeRetry(int $totalMs): void {}
            };
        }

        private function request(string $uri = '/api/orders', string $method = 'GET', ?string $token = 'ag_at_dummy'): Request
        {
            $request = Request::create($uri, $method);
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

        /** The decoded JSON body of the single recorded introspection request. */
        private function recordedBody(): array
        {
            $recorded = Http::recorded();
            $this->assertCount(1, $recorded, 'expected exactly one introspection request');

            return $recorded[0][0]->data();
        }

        /** Run any middleware handle() and report whether $next was reached. */
        private function handle(object $middleware, Request $request, ?bool &$nextCalled = null, ...$params): Response
        {
            $nextCalled = false;
            $next = function (Request $req) use (&$nextCalled): Response {
                $nextCalled = true;

                return new JsonResponse(['ok' => true], 200);
            };

            return $middleware->handle($request, $next, ...$params);
        }

        private function body(Response $response): array
        {
            return json_decode($response->getContent(), true);
        }

        // ---------------------------------------------------------------------
        // Matrix 6(a): scope middleware sends scope_used + endpoint + method
        // ---------------------------------------------------------------------

        public function testRequireScopeSendsScopeUsedEndpointMethod(): void
        {
            Http::fake(['*' => Http::response($this->validPayload(), 200)]);

            $request = $this->request('/api/orders?user_email=pii@example.com', 'GET');
            $response = $this->handle(new RequireScope($this->client()), $request, $nextCalled, 'read:orders');

            // Matrix section 5: active response without error passes unchanged.
            $this->assertSame(200, $response->getStatusCode());
            $this->assertTrue($nextCalled);

            // Exact body: token + the three telemetry fields, query stripped.
            $this->assertSame([
                'token'      => 'ag_at_dummy',
                'scope_used' => 'read:orders',
                'endpoint'   => '/api/orders',
                'method'     => 'GET',
            ], $this->recordedBody());
        }

        public function testRequireScopeIfAgentSendsScopeUsedEndpointMethod(): void
        {
            Http::fake(['*' => Http::response($this->validPayload(), 200)]);

            $request = $this->request('/api/orders?page=2', 'POST');
            $response = $this->handle(new RequireScopeIfAgent($this->client()), $request, $nextCalled, 'read:orders');

            $this->assertSame(200, $response->getStatusCode());
            $this->assertTrue($nextCalled);
            $this->assertSame([
                'token'      => 'ag_at_dummy',
                'scope_used' => 'read:orders',
                'endpoint'   => '/api/orders',
                'method'     => 'POST',
            ], $this->recordedBody());
        }

        // ---------------------------------------------------------------------
        // Matrix 6(b): scope_used omitted when unknown, endpoint+method still sent
        // ---------------------------------------------------------------------

        public function testRequirePresenceOmitsScopeUsedButSendsEndpointMethod(): void
        {
            Http::fake(['*' => Http::response($this->validPayload([
                'presence' => ['verified' => true, 'method' => 'webauthn', 'uv' => true],
            ]), 200)]);

            $request = $this->request('/api/orders', 'POST');
            $response = $this->handle(new RequirePresence($this->client()), $request, $nextCalled);

            $this->assertSame(200, $response->getStatusCode());
            $this->assertTrue($nextCalled);
            $this->assertSame([
                'token'    => 'ag_at_dummy',
                'endpoint' => '/api/orders',
                'method'   => 'POST',
            ], $this->recordedBody());
        }

        public function testCallerConsentOmitsScopeUsedEvenWhenScopeParamGiven(): void
        {
            // Deliberate: consent is evaluated BEFORE scope on this path
            // (Patent FIG. 3 / the 1.5.1 fix), so reporting scope_used would
            // let the hosted service refuse with insufficient_scope ahead of
            // the consent decision, leaking scope state to a denied class.
            Http::fake(['*' => Http::response($this->validPayload([
                'consent' => ['granted' => true],
            ]), 200)]);

            $middleware = new CallerConsent(
                $this->client(),
                new ConsentClient(['api_key' => 'aa_test_dummy'])
            );
            $request = $this->request('/api/records/7?expand=all', 'GET');
            $response = $this->handle($middleware, $request, $nextCalled, 'read:orders');

            $this->assertSame(200, $response->getStatusCode());
            $this->assertTrue($nextCalled);
            $this->assertSame([
                'token'    => 'ag_at_dummy',
                'endpoint' => '/api/records/7',
                'method'   => 'GET',
            ], $this->recordedBody());
        }

        public function testDirectVerifySendsOnlyTokenByDefault(): void
        {
            // Backward compatibility: no telemetry args, body is exactly {token}.
            Http::fake(['*' => Http::response($this->validPayload(), 200)]);

            $this->client()->verify('ag_at_dummy');

            $this->assertSame(['token' => 'ag_at_dummy'], $this->recordedBody());
        }

        public function testEmptyStringTelemetryValuesAreOmitted(): void
        {
            // Never null / empty string on the wire: empty values behave as unknown.
            Http::fake(['*' => Http::response($this->validPayload(), 200)]);

            $this->client()->verify('ag_at_dummy', '', '', '');

            $this->assertSame(['token' => 'ag_at_dummy'], $this->recordedBody());
        }

        // ---------------------------------------------------------------------
        // Matrix 6(c): endpoint query-strip + 500-char truncation; method caps
        // ---------------------------------------------------------------------

        public function testEndpointQueryStrippedAndTruncatedTo500Chars(): void
        {
            Http::fake(['*' => Http::response($this->validPayload(), 200)]);

            $longPath = '/api/' . str_repeat('a', 600);
            $this->client()->verify('ag_at_dummy', 'read:orders', $longPath . '?user_email=pii@example.com', 'get');

            $body = $this->recordedBody();
            $this->assertSame(substr($longPath, 0, 500), $body['endpoint']);
            $this->assertSame(500, strlen($body['endpoint']));
            $this->assertStringNotContainsString('?', $body['endpoint']);
            $this->assertStringNotContainsString('pii@example.com', $body['endpoint']);
            // Caller-provided lowercase method is uppercased.
            $this->assertSame('GET', $body['method']);
        }

        public function testEndpointFragmentStrippedAndMethodCappedAt20(): void
        {
            Http::fake(['*' => Http::response($this->validPayload(), 200)]);

            $this->client()->verify('ag_at_dummy', null, '/api/orders#section', str_repeat('m', 30));

            $body = $this->recordedBody();
            $this->assertSame('/api/orders', $body['endpoint']);
            $this->assertSame(str_repeat('M', 20), $body['method']);
            $this->assertArrayNotHasKey('scope_used', $body);
        }

        public function testQueryOnlyEndpointIsOmittedNotSentEmpty(): void
        {
            Http::fake(['*' => Http::response($this->validPayload(), 200)]);

            $this->client()->verify('ag_at_dummy', null, '?only=query', 'GET');

            $body = $this->recordedBody();
            $this->assertArrayNotHasKey('endpoint', $body);
            $this->assertSame('GET', $body['method']);
        }

        // ---------------------------------------------------------------------
        // Matrix 6(d): active + bound_exceeded -> 403, handler NOT invoked
        // ---------------------------------------------------------------------

        public function testActiveBoundExceededReturns403AndHandlerNotInvoked(): void
        {
            $bound   = ['type' => 'spend', 'limit' => 100, 'used' => 112];
            $renewal = ['renews_at' => '2026-10-01T00:00:00Z'];
            Http::fake(['*' => Http::response($this->validPayload([
                'error'             => 'bound_exceeded',
                'error_description' => 'Spending bound exceeded for this connection.',
                'bound'             => $bound,
                'renewal'           => $renewal,
            ]), 200)]);

            $response = $this->handle(new RequireScope($this->client()), $this->request(), $nextCalled, 'read:orders');

            $this->assertSame(403, $response->getStatusCode());
            $this->assertFalse($nextCalled);
            // Hosted fields pass through verbatim.
            $this->assertSame([
                'error'             => 'bound_exceeded',
                'error_description' => 'Spending bound exceeded for this connection.',
                'bound'             => $bound,
                'renewal'           => $renewal,
            ], $this->body($response));
        }

        public function testBoundExceededWithoutOptionalFieldsOmitsThem(): void
        {
            Http::fake(['*' => Http::response($this->validPayload([
                'error'             => 'bound_exceeded',
                'error_description' => 'Bound exhausted.',
            ]), 200)]);

            $response = $this->handle(new RequireScope($this->client()), $this->request(), $nextCalled, 'read:orders');

            $this->assertSame(403, $response->getStatusCode());
            $this->assertFalse($nextCalled);
            $this->assertSame([
                'error'             => 'bound_exceeded',
                'error_description' => 'Bound exhausted.',
            ], $this->body($response));
        }

        public function testRequirePresenceMapsBoundExceededDenial(): void
        {
            // The active-error denial applies on every verify path, not just
            // the scope middlewares.
            Http::fake(['*' => Http::response($this->validPayload([
                'error'             => 'bound_exceeded',
                'error_description' => 'Bound exhausted.',
                'presence'          => ['verified' => true],
            ]), 200)]);

            $response = $this->handle(new RequirePresence($this->client()), $this->request(), $nextCalled);

            $this->assertSame(403, $response->getStatusCode());
            $this->assertFalse($nextCalled);
            $this->assertSame('bound_exceeded', $this->body($response)['error']);
        }

        // ---------------------------------------------------------------------
        // Matrix 6(e): active + insufficient_scope -> 403 step-up shape
        // ---------------------------------------------------------------------

        public function testActiveInsufficientScopeReturns403StepUpShape(): void
        {
            Http::fake(['*' => Http::response($this->validPayload([
                'error'          => 'insufficient_scope',
                'required_scope' => 'write:orders',
                'granted_scopes' => ['read:orders'],
            ]), 200)]);

            $response = $this->handle(new RequireScope($this->client()), $this->request(), $nextCalled, 'write:orders');

            $this->assertSame(403, $response->getStatusCode());
            $this->assertFalse($nextCalled);
            $this->assertSame([
                'error'          => 'insufficient_scope',
                'required_scope' => 'write:orders',
                'granted_scopes' => ['read:orders'],
            ], $this->body($response));
        }

        public function testInsufficientScopeFallsBackToHostedScopesAndLocalScope(): void
        {
            // Hosted response omits required_scope/granted_scopes: fall back to
            // the scope this call enforced and the hosted scopes array.
            Http::fake(['*' => Http::response($this->validPayload([
                'error' => 'insufficient_scope',
            ]), 200)]);

            $response = $this->handle(new RequireScope($this->client()), $this->request(), $nextCalled, 'write:orders');

            $this->assertSame(403, $response->getStatusCode());
            $this->assertFalse($nextCalled);
            $this->assertSame([
                'error'          => 'insufficient_scope',
                'required_scope' => 'write:orders',
                'granted_scopes' => ['read:orders'],
            ], $this->body($response));
        }

        // ---------------------------------------------------------------------
        // Matrix 6(f): unknown active-error -> 403 generic fail-closed
        // ---------------------------------------------------------------------

        public function testUnknownActiveErrorReturns403FailClosed(): void
        {
            foreach (['quota_exhausted', 'capability_suspended'] as $code) {
                Http::swap(new Factory()); // fresh fake per iteration
                Http::fake(['*' => Http::response($this->validPayload(['error' => $code]), 200)]);

                $response = $this->handle(new RequireScope($this->client()), $this->request(), $nextCalled, 'read:orders');

                $this->assertSame(403, $response->getStatusCode());
                $this->assertFalse($nextCalled);
                $this->assertSame([
                    'error'             => $code,
                    'error_description' => 'Call refused by the authorization service.',
                ], $this->body($response));
            }
        }

        public function testClientThrowsTypedDenialWith403AndErrorCode(): void
        {
            Http::fake(['*' => Http::response($this->validPayload([
                'error'             => 'bound_exceeded',
                'error_description' => 'Bound exhausted.',
            ]), 200)]);

            try {
                $this->client()->verify('ag_at_dummy');
                $this->fail('expected VerificationDeniedException');
            } catch (VerificationDeniedException $e) {
                $this->assertSame(403, $e->getStatusCode());
                $this->assertSame('bound_exceeded', $e->getErrorCode());
                $this->assertSame('bound_exceeded', $e->getDenialBody()['error']);
            }
        }

        // ---------------------------------------------------------------------
        // Matrix section 5: no behavior change for active responses without error
        // ---------------------------------------------------------------------

        public function testActiveResponseWithoutErrorStillVerifies(): void
        {
            Http::fake(['*' => Http::response($this->validPayload(), 200)]);

            $result = $this->client()->verify('ag_at_dummy', 'read:orders', '/api/orders', 'GET');

            $this->assertSame('user_42', $result->userId);
            $this->assertSame(['read:orders'], $result->scopes);
        }
    }
}
