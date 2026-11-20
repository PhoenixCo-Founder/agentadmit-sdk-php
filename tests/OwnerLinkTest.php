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

    use AgentAdmit\AgentAdmitException;
    use AgentAdmit\ConfirmationRequiredException;
    use AgentAdmit\IntrospectionClient;
    use AgentAdmit\Middleware\RequireScope;
    use AgentAdmit\OwnerLink;
    use AgentAdmit\TokensClient;
    use AgentAdmit\VerificationDeniedException;
    use Illuminate\Http\Client\Factory;
    use Illuminate\Http\JsonResponse;
    use Illuminate\Http\Request;
    use Illuminate\Support\Facades\Http;
    use Illuminate\Support\Facades\Log;
    use PHPUnit\Framework\Attributes\DataProvider;
    use PHPUnit\Framework\TestCase;

    /**
     * SDK 1.15.
     *
     * Row A: confirmation.enrollment_required on the confirmation_required
     * refusal is kept strictly (a JSON boolean only), on
     * ConfirmationRequiredException and in the 403 body; when it is true the
     * agent is told the link alone cannot be used.
     *
     * Row B: TokensClient::createOwnerLink().
     */
    class OwnerLinkTest extends TestCase
    {
        private const ENROLLMENT_SENTENCE = 'This action requires a fresh human confirmation, and this user has no passkey on file for the app yet, so the confirmation link alone cannot be used. Ask the user to open the request from inside the app. After they confirm, retry with the X-AgentAdmit-Action-Attestation header.';

        private const OLD_SENTENCE = 'This action requires a fresh human confirmation. Give the confirmation link to the user, then retry with the X-AgentAdmit-Action-Attestation header.';

        private const SESSION = 'asess_0123456789abcdef';

        /** @var array<int, string> */
        private array $logLines = [];

        protected function setUp(): void
        {
            parent::setUp();
            Http::swap(new Factory());
            $lines = &$this->logLines;
            Log::swap(new class($lines) {
                private array $lines;
                public function __construct(array &$lines) { $this->lines = &$lines; }
                public function __call($method, $args) { $this->lines[] = (string) ($args[0] ?? ''); return null; }
            });
            $GLOBALS['__agentadmit_test_config'] = [];
        }

        // -----------------------------------------------------------------
        // Row A
        // -----------------------------------------------------------------

        private function introspection(): IntrospectionClient
        {
            return new class(['api_key' => 'aa_test_dummy']) extends IntrospectionClient {
                protected function waitBeforeRetry(int $totalMs): void {}
            };
        }

        private function refusal(array $confirmationExtra = [], ?string $hostedDescription = null, bool $withUrl = true): array
        {
            $confirmation = ['action_session_id' => 'asess_abc'];
            if ($withUrl) {
                $confirmation['action_session_url'] = 'https://agentadmit.com/confirm/action/asess_abc';
            }
            $confirmation += $confirmationExtra + [
                'expires_at' => 'e',
                'scope' => 'write:payments',
                'method' => null,
                'endpoint' => null,
                'request_digest' => null,
                'summary' => null,
            ];
            $data = [
                'active' => true,
                'error' => 'confirmation_required',
                'confirmation' => $confirmation,
            ];
            if ($hostedDescription !== null) {
                $data['error_description'] = $hostedDescription;
            }
            return $data;
        }

        private function typedRefusal(array $wire): VerificationDeniedException
        {
            Http::swap(new Factory());
            Http::fake(['*' => Http::response($wire, 200)]);
            try {
                $this->introspection()->verify('ag_at_dummy', 'write:payments');
            } catch (VerificationDeniedException $e) {
                return $e;
            }
            $this->fail('confirmation_required must deny');
        }

        /** The serialized 403 body the middleware writes for the agent. */
        private function middleware403(array $wire): array
        {
            Http::swap(new Factory());
            Http::fake(['*' => Http::response($wire, 200)]);
            $request = Request::create('/api/payments', 'POST', [], [], [], [], '{}');
            $request->headers->set('Authorization', 'Bearer ag_at_dummy');
            $nextCalled = false;
            $response = (new RequireScope($this->introspection()))->handle(
                $request,
                function () use (&$nextCalled): JsonResponse {
                    $nextCalled = true;
                    return new JsonResponse(['ok' => true]);
                },
                'write:payments'
            );
            $this->assertFalse($nextCalled, 'a refusal never reaches the handler');
            $this->assertSame(403, $response->getStatusCode());
            return json_decode($response->getContent(), true);
        }

        public static function enrollmentWireValues(): array
        {
            return [
                'true'        => [['enrollment_required' => true], true, true],
                'false'       => [['enrollment_required' => false], false, true],
                'absent'      => [[], null, false],
                'null'        => [['enrollment_required' => null], null, false],
                'string true' => [['enrollment_required' => 'true'], null, false],
                'one'         => [['enrollment_required' => 1], null, false],
                'zero'        => [['enrollment_required' => 0], null, false],
                'object'      => [['enrollment_required' => new \stdClass()], null, false],
                'array'       => [['enrollment_required' => []], null, false],
            ];
        }

        #[DataProvider('enrollmentWireValues')]
        public function testEnrollmentRequiredMatrix(array $extra, ?bool $expected, bool $keyPresent): void
        {
            $wire = $this->refusal($extra);

            $e = $this->typedRefusal($wire);
            $this->assertInstanceOf(ConfirmationRequiredException::class, $e);
            $this->assertSame($expected, $e->isEnrollmentRequired());
            $this->assertSame($keyPresent, array_key_exists('enrollment_required', $e->getConfirmation()));
            if ($keyPresent) {
                $this->assertSame($expected, $e->getConfirmation()['enrollment_required']);
            }

            $body = $this->middleware403($wire);
            $this->assertSame('https://agentadmit.com/confirm/action/asess_abc', $body['confirmation']['action_session_url']);
            $this->assertSame($keyPresent, array_key_exists('enrollment_required', $body['confirmation']));
            if ($keyPresent) {
                $this->assertSame($expected, $body['confirmation']['enrollment_required']);
            }
        }

        public function testBlockMissingTheUrlIsStillDroppedWhole(): void
        {
            $wire = $this->refusal(['enrollment_required' => true], null, withUrl: false);
            $e = $this->typedRefusal($wire);
            $this->assertNotInstanceOf(ConfirmationRequiredException::class, $e);
            $this->assertArrayNotHasKey('confirmation', $e->getDenialBody());
            $body = $this->middleware403($wire);
            $this->assertArrayNotHasKey('confirmation', $body);
            $this->assertSame(self::OLD_SENTENCE, $body['error_description']);
        }

        public function testSentenceForTrueAndUnchangedOtherwise(): void
        {
            $this->assertSame(self::ENROLLMENT_SENTENCE,
                $this->middleware403($this->refusal(['enrollment_required' => true]))['error_description']);
            $this->assertSame(self::ENROLLMENT_SENTENCE,
                $this->typedRefusal($this->refusal(['enrollment_required' => true]))->getMessage());
            $this->assertSame(self::OLD_SENTENCE,
                $this->middleware403($this->refusal(['enrollment_required' => false]))['error_description']);
            $this->assertSame(self::OLD_SENTENCE,
                $this->middleware403($this->refusal())['error_description']);
            // The hosted description still wins for false and absent, as
            // before; for true the enrollment sentence replaces it.
            $this->assertSame('hosted words',
                $this->middleware403($this->refusal(['enrollment_required' => false], 'hosted words'))['error_description']);
            $this->assertSame('hosted words',
                $this->middleware403($this->refusal([], 'hosted words'))['error_description']);
            $this->assertSame(self::ENROLLMENT_SENTENCE,
                $this->middleware403($this->refusal(['enrollment_required' => true], 'hosted words'))['error_description']);
        }

        // -----------------------------------------------------------------
        // Row B
        // -----------------------------------------------------------------

        private function tokens(): TokensClient
        {
            return new TokensClient([
                'app_id'  => 'app_test123',
                'api_key' => 'aa_test_dummy',
                'api_url' => 'https://api.agentadmit.com',
            ]);
        }

        public function testRequestShape(): void
        {
            Http::fake(['*' => Http::response([
                'action_session_id' => 'x',
                'owner_session_url' => 'https://agentadmit.com/o#t=1',
                'enrollment_required' => true,
                'enrollment_reason' => 'no_passkey',
                'expires_at' => 'e',
            ], 201)]);

            // An id with characters that need encoding proves it goes through
            // an encoder (real ids only use - and _).
            $this->tokens()->createOwnerLink('asess_a/b c-_0123456789', 'user_42');
            $this->tokens()->createOwnerLink(self::SESSION, 'user_42');

            $recorded = Http::recorded();
            $this->assertCount(2, $recorded);
            $request = $recorded[0][0];
            $this->assertSame('POST', $request->method());
            $this->assertSame('https://api.agentadmit.com/api/v1/action-sessions/asess_a%2Fb%20c-_0123456789/owner-link', $request->url());
            $this->assertSame(['Bearer aa_test_dummy'], $request->header('Authorization'));
            $this->assertSame(['application/json'], $request->header('Content-Type'));
            $this->assertSame(['app_user_id' => 'user_42'], $request->data());
            $this->assertSame('{"app_user_id":"user_42"}', $request->body());
            $this->assertSame('https://api.agentadmit.com/api/v1/action-sessions/' . self::SESSION . '/owner-link', $recorded[1][0]->url());
        }

        public function testCreatedAndOkResults(): void
        {
            Http::fake(['*' => Http::response([
                'action_session_id' => self::SESSION,
                'owner_session_url' => 'https://agentadmit.com/o#t=1',
                'enrollment_required' => true,
                'enrollment_reason' => 'no_eligible_authenticator',
                'expires_at' => '2026-11-20T18:00:00.000Z',
            ], 201)]);
            $created = $this->tokens()->createOwnerLink(self::SESSION, 'user_42');
            $this->assertEquals(new OwnerLink(self::SESSION, 'https://agentadmit.com/o#t=1', true,
                'no_eligible_authenticator', '2026-11-20T18:00:00.000Z'), $created);
            $this->assertStringNotContainsString('agentadmit.com/o', print_r($created, true));

            Http::swap(new Factory());
            Http::fake(['*' => Http::response([
                'action_session_id' => self::SESSION,
                'owner_session_url' => 'https://agentadmit.com/confirm/action/x',
                'enrollment_required' => false,
                'expires_at' => 'e',
            ], 200)]);
            $ok = $this->tokens()->createOwnerLink(self::SESSION, 'user_42');
            $this->assertFalse($ok->enrollmentRequired);
            $this->assertNull($ok->enrollmentReason);
            $this->assertSame('https://agentadmit.com/confirm/action/x', $ok->ownerSessionUrl);
        }

        public static function errorStatuses(): array
        {
            return [
                [401, 'invalid_api_key'],
                [403, 'api_key_not_app_linked'],
                [404, 'not_found'],
                [409, 'already_consumed'],
                [409, 'already_verified'],
                [410, 'session_expired'],
                [429, 'rate_limited'],
            ];
        }

        #[DataProvider('errorStatuses')]
        public function testErrorStatusesMapToTheApiError(int $status, string $code): void
        {
            Http::fake(['*' => Http::response(['error' => $code, 'error_description' => 'd'], $status)]);
            try {
                $this->tokens()->createOwnerLink(self::SESSION, 'user_42');
                $this->fail('must throw');
            } catch (AgentAdmitException $e) {
                $this->assertSame($status, $e->getStatusCode());
                $this->assertSame($code, $e->getErrorCode());
            }
            $this->assertCount(1, Http::recorded(), 'no retry on a 4xx');
        }

        public function testServerErrorAndNetworkFailure(): void
        {
            Http::fake(['*' => Http::response('upstream', 503)]);
            try {
                $this->tokens()->createOwnerLink(self::SESSION, 'user_42');
                $this->fail('must throw');
            } catch (AgentAdmitException $e) {
                $this->assertSame(503, $e->getStatusCode());
                $this->assertNull($e->getErrorCode());
            }

            Http::swap(new Factory());
            Http::fake(function () {
                throw new \Illuminate\Http\Client\ConnectionException('connection reset');
            });
            try {
                $this->tokens()->createOwnerLink(self::SESSION, 'user_42');
                $this->fail('must throw');
            } catch (AgentAdmitException $e) {
                $this->assertSame(502, $e->getStatusCode());
            }
        }

        public function testArgumentErrorsMakeNoRequest(): void
        {
            Http::fake(['*' => Http::response([], 201)]);
            foreach ([
                ['sess_0123456789abcdefgh', 'u'],
                ['asess_short', 'u'],
                ['', 'u'],
                [self::SESSION, ''],
                [self::SESSION, str_repeat('u', 256)],
            ] as [$session, $user]) {
                try {
                    $this->tokens()->createOwnerLink($session, $user);
                    $this->fail("({$session}, " . strlen($user) . ' chars) must be rejected');
                } catch (\InvalidArgumentException $e) {
                    $this->assertNotInstanceOf(AgentAdmitException::class, $e);
                }
            }
            $this->assertCount(0, Http::recorded(), 'no request before the arguments pass');
        }

        public function testMalformed2xxIsAnErrorNeverAPartialResult(): void
        {
            foreach ([
                ['action_session_id' => 'x', 'enrollment_required' => true, 'expires_at' => 'e'],
                ['action_session_id' => 'x', 'owner_session_url' => 5, 'enrollment_required' => true],
                ['action_session_id' => 'x', 'owner_session_url' => 'https://agentadmit.com/o#t=secret', 'expires_at' => 'e'],
                ['owner_session_url' => 'https://agentadmit.com/o#t=secret', 'enrollment_required' => 'true'],
                'not json https://agentadmit.com/o#t=secret',
                [],
            ] as $body) {
                Http::swap(new Factory());
                Http::fake(['*' => Http::response($body, 201)]);
                try {
                    $this->tokens()->createOwnerLink(self::SESSION, 'user_42');
                    $this->fail('malformed 2xx must throw');
                } catch (AgentAdmitException $e) {
                    $this->assertSame(502, $e->getStatusCode());
                    $this->assertStringNotContainsString('secret', $e->getMessage());
                }
            }
        }

        public function testNeverLogsTheOwnerSessionUrl(): void
        {
            $url = 'https://agentadmit.com/confirm/owner/asess_x#t=secret_fragment';
            $bodies = [
                [['owner_session_url' => $url, 'enrollment_required' => true], 201],
                [['owner_session_url' => $url], 201],
                ['garbage ' . $url, 201],
                [['error' => 'already_consumed', 'owner_session_url' => $url], 409],
            ];
            foreach ($bodies as [$body, $status]) {
                Http::swap(new Factory());
                Http::fake(['*' => Http::response($body, $status)]);
                try {
                    $this->tokens()->createOwnerLink(self::SESSION, 'user_42');
                } catch (AgentAdmitException $e) {
                    // expected on the error paths
                }
            }
            $this->assertNotEmpty($this->logLines, 'the error paths log their path and status');
            foreach ($this->logLines as $line) {
                $this->assertStringNotContainsString('secret_fragment', $line);
                $this->assertStringNotContainsString('confirm/owner', $line);
                $this->assertStringContainsString('/api/v1/action-sessions/' . self::SESSION . '/owner-link', $line);
            }
        }
    }
}
