<?php

/**
 * Tests for outcome reporting:
 *  - verify surfaces audit_row_id and consumed_receipt without treating the
 *    replay diagnostic as authorization;
 *  - reportOutcome() posts the exact hosted outcome body;
 *  - Laravel middleware reports only after a downstream Response exists,
 *    maps status classes automatically, and never replaces the app response
 *    when reporting fails.
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

    use AgentAdmit\AgentAdmitException;
    use AgentAdmit\IntrospectionClient;
    use AgentAdmit\Middleware\RequireScope;
    use Illuminate\Http\Client\Factory;
    use Illuminate\Http\JsonResponse;
    use Illuminate\Http\Request;
    use Illuminate\Support\Facades\Http;
    use Illuminate\Support\Facades\Log;
    use PHPUnit\Framework\TestCase;
    use Symfony\Component\HttpFoundation\Response;

    class OutcomeReportingTest extends TestCase
    {
        private array $warnings = [];

        protected function setUp(): void
        {
            parent::setUp();
            Http::swap(new Factory());
            $this->warnings = [];
            $warnings = &$this->warnings;
            Log::swap(new class($warnings) {
                public function __construct(private array &$warnings) {}
                public function warning(string $message): void { $this->warnings[] = $message; }
                public function __call($method, $args) { return null; }
            });
            $GLOBALS['__agentadmit_test_config'] = [];
        }

        private function client(array $config = []): IntrospectionClient
        {
            return new class(array_merge([
                'api_key' => 'aa_test_dummy',
                'api_url' => 'http://127.0.0.1:3003',
            ], $config)) extends IntrospectionClient {
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
                'agent_label'   => 'Test Agent',
            ], $overrides);
        }

        private function request(): Request
        {
            $request = Request::create('/api/orders', 'POST');
            $request->headers->set('Authorization', 'Bearer ag_at_dummy');

            return $request;
        }

        private function handleWithStatus(int $status): Response
        {
            $middleware = new RequireScope($this->client());

            return $middleware->handle(
                $this->request(),
                fn (Request $request): Response => new JsonResponse(['status' => $status], $status),
                'read:orders'
            );
        }

        public function testVerifySurfacesAuditRowIdAndConsumedReceipt(): void
        {
            Http::fake(['*' => Http::response($this->validPayload([
                'audit_row_id' => 'audit_123',
                'consumed_receipt' => [
                    'already_consumed' => true,
                    'consumed_at' => '2026-09-30T02:54:07Z',
                    'action_session_id' => 'asess_123',
                ],
            ]), 200)]);

            $result = $this->client()->verify('ag_at_dummy');

            $this->assertSame('audit_123', $result->auditRowId);
            $this->assertSame([
                'already_consumed' => true,
                'consumed_at' => '2026-09-30T02:54:07Z',
                'action_session_id' => 'asess_123',
            ], $result->consumedReceipt);
            $this->assertNull($result->actionConfirmation);
        }

        public function testMalformedConsumedReceiptIsDropped(): void
        {
            Http::fake(['*' => Http::response($this->validPayload([
                'audit_row_id' => 'audit_123',
                'consumed_receipt' => ['already_consumed' => false],
            ]), 200)]);

            $result = $this->client()->verify('ag_at_dummy');

            $this->assertSame('audit_123', $result->auditRowId);
            $this->assertNull($result->consumedReceipt);
        }

        public function testReportOutcomePostsExactBody(): void
        {
            Http::fake([
                'http://127.0.0.1:3003/api/v1/audit/audit_123/outcome' =>
                    Http::response(['id' => 'outcome_123'], 201),
            ]);

            $response = $this->client()->reportOutcome('audit_123', IntrospectionClient::OUTCOME_EXECUTED, '2xx');

            $this->assertSame(['id' => 'outcome_123'], $response);
            $recorded = Http::recorded();
            $this->assertCount(1, $recorded);
            $this->assertSame([
                'outcome' => 'executed',
                'status_class' => '2xx',
            ], $recorded[0][0]->data());
        }

        public function testReportOutcomeAllowsExplicitUnknownWithNullStatusClass(): void
        {
            Http::fake(['*' => Http::response(['id' => 'outcome_123'], 201)]);

            $this->client()->reportOutcome('audit_123', IntrospectionClient::OUTCOME_UNKNOWN, null);

            $this->assertSame([
                'outcome' => 'unknown',
                'status_class' => null,
            ], Http::recorded()[0][0]->data());
        }

        public function testReportOutcomeRejectsInvalidOutcomeAndStatusClass(): void
        {
            $this->expectException(AgentAdmitException::class);
            $this->client()->reportOutcome('audit_123', 'maybe', '2xx');
        }

        public function testMiddlewareReportsExecutedAfterSuccessfulResponse(): void
        {
            $GLOBALS['__agentadmit_test_config']['agentadmit.outcome_reporting.enabled'] = true;
            Http::fake([
                '*/api/v1/verify' => Http::response($this->validPayload(['audit_row_id' => 'audit_123']), 200),
                '*/api/v1/audit/audit_123/outcome' => Http::response(['id' => 'outcome_123'], 201),
            ]);

            $response = $this->handleWithStatus(201);

            $this->assertSame(201, $response->getStatusCode());
            $recorded = Http::recorded();
            $this->assertCount(2, $recorded);
            $this->assertSame([
                'outcome' => 'executed',
                'status_class' => '2xx',
            ], $recorded[1][0]->data());
        }

        public function testMiddlewareReportsFailedForFourHundredOrHigher(): void
        {
            $GLOBALS['__agentadmit_test_config']['agentadmit.outcome_reporting.enabled'] = true;
            Http::fake([
                '*/api/v1/verify' => Http::response($this->validPayload(['audit_row_id' => 'audit_123']), 200),
                '*/api/v1/audit/audit_123/outcome' => Http::response(['id' => 'outcome_123'], 201),
            ]);

            $response = $this->handleWithStatus(404);

            $this->assertSame(404, $response->getStatusCode());
            $this->assertSame([
                'outcome' => 'failed',
                'status_class' => '4xx',
            ], Http::recorded()[1][0]->data());
        }

        public function testMiddlewareSkipsOutcomeWhenDisabledOrNoAuditRow(): void
        {
            $GLOBALS['__agentadmit_test_config']['agentadmit.outcome_reporting.enabled'] = false;
            Http::fake(['*/api/v1/verify' => Http::response($this->validPayload(['audit_row_id' => 'audit_123']), 200)]);
            $this->handleWithStatus(200);
            Http::assertSentCount(1);

            Http::swap(new Factory());
            $GLOBALS['__agentadmit_test_config']['agentadmit.outcome_reporting.enabled'] = true;
            Http::fake(['*/api/v1/verify' => Http::response($this->validPayload(), 200)]);
            $this->handleWithStatus(200);
            Http::assertSentCount(1);
        }

        public function testMiddlewareDoesNotReportWhenDownstreamThrows(): void
        {
            $GLOBALS['__agentadmit_test_config']['agentadmit.outcome_reporting.enabled'] = true;
            Http::fake([
                '*/api/v1/verify' => Http::response($this->validPayload(['audit_row_id' => 'audit_123']), 200),
                '*/api/v1/audit/audit_123/outcome' => Http::response(['id' => 'outcome_123'], 201),
            ]);

            $this->expectException(\RuntimeException::class);

            try {
                (new RequireScope($this->client()))->handle(
                    $this->request(),
                    fn (Request $request): Response => throw new \RuntimeException('aborted'),
                    'read:orders'
                );
            } finally {
                Http::assertSentCount(1);
            }
        }

        public function testOutcomeReportFailureDoesNotReplaceAppResponse(): void
        {
            $GLOBALS['__agentadmit_test_config']['agentadmit.outcome_reporting.enabled'] = true;
            Http::fake([
                '*/api/v1/verify' => Http::response($this->validPayload(['audit_row_id' => 'audit_123']), 200),
                '*/api/v1/audit/audit_123/outcome' => Http::response(['error' => 'temporary'], 503),
            ]);

            $response = $this->handleWithStatus(204);

            $this->assertSame(204, $response->getStatusCode());
            $this->assertNotEmpty($this->warnings);
        }
    }
}
