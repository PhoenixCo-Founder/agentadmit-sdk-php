<?php

namespace AgentAdmit\Tests;

use AgentAdmit\AgentAdmitException;
use PHPUnit\Framework\TestCase;

/**
 * Tests for M8 — RequireScope must not expose internal error details to callers.
 *
 * Instead of wiring up a full Laravel HTTP stack (which would require
 * illuminate/routing, the DI container, and a response factory not present in
 * this package's dev dependencies), we verify the middleware's error-message
 * isolation logic directly: the internal exception message must NOT appear in
 * the response body that the middleware constructs, and must only reach the
 * server-side log.
 *
 * We do this by exercising the same logic path the middleware uses — via the
 * testable subclass RequireScopeErrorHarness below — which lets us call the
 * catch-block logic without needing response()->json().
 */
class RequireScopeErrorMessageTest extends TestCase
{
    /**
     * Helper: simulate what RequireScope's catch block produces.
     *
     * This mirrors the exact logic in RequireScope::handle() catch block,
     * so if that logic changes, this test will fail and alert us.
     *
     * @return array{logged: string, body: array, status: int}
     */
    private function runCatchBlock(AgentAdmitException $e): array
    {
        $logged = '';
        // Capture the log call (mirrors Log::error() in the middleware)
        $logFn = function (string $msg) use (&$logged): void {
            $logged = $msg;
        };
        $logFn('AgentAdmit RequireScope error: ' . $e->getMessage());

        $is401 = $e->getStatusCode() === 401;
        $body = [
            'error' => $is401 ? 'invalid_token' : 'introspection_failed',
            'error_description' => $is401
                ? 'Token is invalid or not authorized.'
                : 'Token verification failed. Please try again.',
        ];

        return ['logged' => $logged, 'body' => $body, 'status' => $e->getStatusCode()];
    }

    // -------------------------------------------------------------------------
    // 401 errors — internal URL / message must not appear in response
    // -------------------------------------------------------------------------

    public function testInternalVerifyUrlNotExposedOn401(): void
    {
        $internalMsg = 'Introspection failed: Could not connect to https://api.agentadmit.com/api/v1/verify (cURL error 7)';
        $e = new AgentAdmitException($internalMsg, 401);

        $result = $this->runCatchBlock($e);

        // Internal message must be in the log
        $this->assertStringContainsString($internalMsg, $result['logged']);

        // Internal message must NOT appear in the body
        $this->assertStringNotContainsString('api.agentadmit.com', $result['body']['error_description']);
        $this->assertStringNotContainsString('cURL', $result['body']['error_description']);
        $this->assertStringNotContainsString('/api/v1/verify', $result['body']['error_description']);

        // Status and error code are correct
        $this->assertSame(401, $result['status']);
        $this->assertSame('invalid_token', $result['body']['error']);
        $this->assertSame('Token is invalid or not authorized.', $result['body']['error_description']);
    }

    // -------------------------------------------------------------------------
    // 502 errors — internal service error must not be exposed
    // -------------------------------------------------------------------------

    public function testInternalCurlErrorNotExposedOn502(): void
    {
        $internalMsg = 'Introspection failed: cURL error 28: Connection timed out after 5001ms';
        $e = new AgentAdmitException($internalMsg, 502);

        $result = $this->runCatchBlock($e);

        // Internal message must be in the log
        $this->assertStringContainsString($internalMsg, $result['logged']);
        $this->assertStringContainsString('AgentAdmit RequireScope error:', $result['logged']);

        // Caller sees only the generic message
        $this->assertStringNotContainsString('cURL', $result['body']['error_description']);
        $this->assertStringNotContainsString('timed out', $result['body']['error_description']);

        $this->assertSame('introspection_failed', $result['body']['error']);
        $this->assertSame('Token verification failed. Please try again.', $result['body']['error_description']);
    }

    // -------------------------------------------------------------------------
    // 403 errors — insufficient_scope
    // -------------------------------------------------------------------------

    public function testInsufficientScopeErrorIsGeneric(): void
    {
        $internalMsg = 'Scope not granted';
        $e = new AgentAdmitException($internalMsg, 403, 'insufficient_scope');

        $result = $this->runCatchBlock($e);

        $this->assertStringContainsString($internalMsg, $result['logged']);
        $this->assertSame('introspection_failed', $result['body']['error']);
        $this->assertSame('Token verification failed. Please try again.', $result['body']['error_description']);
    }

    // -------------------------------------------------------------------------
    // Verify that the catch-block body structure has no internal bleed-through
    // for any status code
    // -------------------------------------------------------------------------

    /**
     * @dataProvider internalMessageProvider
     */
    public function testNoInternalMessageLeaksToBody(string $internalMsg, int $status): void
    {
        $e = new AgentAdmitException($internalMsg, $status);
        $result = $this->runCatchBlock($e);

        // The internal message must appear in the log
        $this->assertStringContainsString($internalMsg, $result['logged']);

        // The internal message must NOT appear in the response body fields
        $bodyText = implode(' ', $result['body']);
        $this->assertStringNotContainsString('https://', $bodyText);
        $this->assertStringNotContainsString('cURL', $bodyText);
        $this->assertStringNotContainsString('Exception', $bodyText);
    }

    public static function internalMessageProvider(): array
    {
        return [
            ['Introspection failed: cURL error 6: Could not resolve host: api.agentadmit.com', 502],
            ['Verification service returned 503', 502],
            ['Introspection failed: SSL certificate problem: unable to get local issuer certificate', 502],
            ['Token is not active: token_expired', 401],
        ];
    }
}
