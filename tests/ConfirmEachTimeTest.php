<?php

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

    use AgentAdmit\ConfirmationRequiredException;
    use AgentAdmit\IntrospectionClient;
    use AgentAdmit\Middleware\RequireScope;
    use AgentAdmit\VerificationDeniedException;
    use Illuminate\Http\Client\Factory;
    use Illuminate\Http\JsonResponse;
    use Illuminate\Http\Request;
    use Illuminate\Support\Facades\Http;
    use Illuminate\Support\Facades\Log;
    use PHPUnit\Framework\TestCase;

    class ConfirmEachTimeTest extends TestCase
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

        private function client(array $extra = []): IntrospectionClient
        {
            return new class(array_merge(['api_key' => 'aa_test_dummy'], $extra)) extends IntrospectionClient {
                protected function waitBeforeRetry(int $totalMs): void {}
            };
        }

        private function active(array $extra = []): array
        {
            return array_merge([
                'active' => true,
                'user_id' => 'user_1',
                'connection_id' => 'conn_1',
                'scopes' => ['write:payments'],
                'agent_label' => 'Test Agent',
            ], $extra);
        }

        private function confirmation(): array
        {
            return [
                'action_session_id' => 'asess_abc',
                'action_session_url' => 'https://agentadmit.com/confirm/action/asess_abc',
                'expires_at' => '2026-09-03T22:00:00Z',
                'scope' => 'write:payments',
                'method' => 'POST',
                'endpoint' => '/api/payments',
                'request_digest' => 'sha256:deadbeef',
                'summary' => 'Pay Alex $50',
            ];
        }

        private function recordedBody(): array
        {
            $recorded = Http::recorded();
            $this->assertCount(1, $recorded);
            return $recorded[0][0]->data();
        }

        public function testTypedConfirmationRequiredDenialCarriesOnlyTheContract(): void
        {
            Http::fake(['*' => Http::response($this->active([
                'error' => 'confirmation_required',
                'confirmation' => $this->confirmation(),
                'attestation_status' => 'action_mismatch',
                'attestation_description' => 'Different action.',
                'renewal' => 'Confirm with a passkey.',
                'user_secret' => 'must-not-leak',
            ]), 200)]);

            try {
                $this->client()->verify('ag_at_dummy', 'write:payments');
                $this->fail('confirmation_required must deny');
            } catch (ConfirmationRequiredException $e) {
                $this->assertInstanceOf(VerificationDeniedException::class, $e);
                $this->assertSame('asess_abc', $e->getActionSessionId());
                $this->assertSame('action_mismatch', $e->getAttestationStatus());
                $body = $e->getDenialBody();
                $this->assertSame($this->confirmation(), $body['confirmation']);
                $this->assertArrayNotHasKey('user_secret', $body);
            }
        }

        public function testMalformedCeremonyStaysAPlainFailClosedDenial(): void
        {
            Http::fake(['*' => Http::response($this->active([
                'error' => 'confirmation_required',
                'confirmation' => ['action_session_id' => 17],
            ]), 200)]);

            try {
                $this->client()->verify('ag_at_dummy', 'write:payments');
                $this->fail('malformed confirmation must still deny');
            } catch (VerificationDeniedException $e) {
                $this->assertNotInstanceOf(ConfirmationRequiredException::class, $e);
                $this->assertArrayNotHasKey('confirmation', $e->getDenialBody());
            }
        }

        public function testVerifyForwardsAndCapsConfirmEachTimeFields(): void
        {
            Http::fake(['*' => Http::response($this->active(), 200)]);
            $this->client()->verify(
                'ag_at_dummy',
                'write:payments',
                '/api/payments',
                'post',
                false,
                '  ' . str_repeat('a', 150) . '  ',
                'sha256:' . str_repeat('b', 200),
                '  ' . str_repeat('s', 250) . '  '
            );

            $body = $this->recordedBody();
            $this->assertSame(120, strlen($body['action_attestation_id']));
            $this->assertSame(128, strlen($body['request_digest']));
            $this->assertSame(200, strlen($body['action_summary']));
        }

        public function testMiddlewareDigestsBodyForwardsHeaderAndSurfacesConsumption(): void
        {
            $raw = '{"trainer":"Alex","amount":50}';
            $GLOBALS['__agentadmit_test_config'] = [
                'agentadmit.token_prefix_access' => 'ag_at_',
                'agentadmit.confirm_each_time.summaries.pay' =>
                    function (Request $request): string {
                        $body = json_decode($request->getContent(), true);
                        return 'Pay ' . $body['trainer'] . ' $' . $body['amount'];
                    },
            ];
            Http::fake(['*' => Http::response($this->active([
                'action_confirmation' => ['action_session_id' => 'asess_abc', 'consumed' => true],
            ]), 200)]);

            $request = Request::create('/api/payments?secret=no', 'POST', [], [], [], [], $raw);
            $request->headers->set('Authorization', 'Bearer ag_at_dummy');
            $request->headers->set('x-agentadmit-action-attestation', ' asess_abc ');
            $nextCalled = false;
            $response = (new RequireScope($this->client()))->handle(
                $request,
                function () use (&$nextCalled): JsonResponse {
                    $nextCalled = true;
                    return new JsonResponse(['ok' => true]);
                },
                'write:payments',
                'pay'
            );

            $this->assertSame(200, $response->getStatusCode());
            $this->assertTrue($nextCalled);
            $body = $this->recordedBody();
            $this->assertSame('/api/payments', $body['endpoint']);
            $this->assertSame('asess_abc', $body['action_attestation_id']);
            $this->assertSame('sha256:' . hash('sha256', $raw), $body['request_digest']);
            $this->assertSame('Pay Alex $50', $body['action_summary']);
            $this->assertSame(
                ['action_session_id' => 'asess_abc', 'consumed' => true],
                $request->attributes->get('agentadmit.action_confirmation')
            );
        }

        public function testNoSummaryHookStillForwardsAttestationButOmitsDigest(): void
        {
            $GLOBALS['__agentadmit_test_config'] = ['agentadmit.token_prefix_access' => 'ag_at_'];
            Http::fake(['*' => Http::response($this->active(), 200)]);
            $request = Request::create('/api/payments', 'POST', [], [], [], [], '{"amount":50}');
            $request->headers->set('Authorization', 'Bearer ag_at_dummy');
            $request->headers->set('X-AgentAdmit-Action-Attestation', 'asess_abc');
            (new RequireScope($this->client()))->handle(
                $request,
                fn () => new JsonResponse(['ok' => true]),
                'write:payments'
            );

            $body = $this->recordedBody();
            $this->assertSame('asess_abc', $body['action_attestation_id']);
            $this->assertArrayNotHasKey('request_digest', $body);
            $this->assertArrayNotHasKey('action_summary', $body);
        }

        public function testConsumedConfirmationParsingIsStrict(): void
        {
            foreach ([
                ['action_session_id' => 'asess_abc', 'consumed' => false],
                ['action_session_id' => 7, 'consumed' => true],
                ['action_session_id' => 'asess_abc', 'consumed' => 'true'],
            ] as $malformed) {
                Http::swap(new Factory());
                Http::fake(['*' => Http::response($this->active(['action_confirmation' => $malformed]), 200)]);
                $this->assertNull($this->client()->verify('ag_at_dummy')->actionConfirmation);
            }
        }

        public function testVerifyUrlFollowsNonDefaultApiUrlUnlessCustomVerifyIsSet(): void
        {
            $derived = $this->client(['api_url' => 'http://127.0.0.1:3003/']);
            $this->assertSame('http://127.0.0.1:3003/api/v1/verify', $derived->getVerifyUrl());

            $explicit = $this->client([
                'api_url' => 'http://127.0.0.1:3003',
                'verify_url' => 'http://127.0.0.1:9999/verify',
            ]);
            $this->assertSame('http://127.0.0.1:9999/verify', $explicit->getVerifyUrl());
        }
    }
}
