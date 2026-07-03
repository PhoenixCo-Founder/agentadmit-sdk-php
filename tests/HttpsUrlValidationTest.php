<?php

namespace AgentAdmit\Tests;

use AgentAdmit\AgentAdmitException;
use AgentAdmit\AlertsClient;
use AgentAdmit\IntrospectionClient;
use AgentAdmit\TokensClient;
use PHPUnit\Framework\TestCase;

/**
 * Tests for M4 — require HTTPS on configurable client URLs.
 *
 * HTTP is allowed only on loopback hosts (localhost, 127.0.0.1, [::1]).
 * Any other http:// URL must throw AgentAdmitException at construction time.
 */
class HttpsUrlValidationTest extends TestCase
{
    // -------------------------------------------------------------------------
    // AgentAdmitException::assertHttpsUrl — unit tests for the shared helper
    // -------------------------------------------------------------------------

    public function testHttpsUrlPasses(): void
    {
        AgentAdmitException::assertHttpsUrl('https://api.agentadmit.com/api/v1/verify', 'verify_url');
        $this->addToAssertionCount(1);
    }

    public function testHttpLocalhostPasses(): void
    {
        AgentAdmitException::assertHttpsUrl('http://localhost/api/v1/verify', 'verify_url');
        $this->addToAssertionCount(1);
    }

    public function testHttp127001Passes(): void
    {
        AgentAdmitException::assertHttpsUrl('http://127.0.0.1:8080/api/v1/verify', 'verify_url');
        $this->addToAssertionCount(1);
    }

    public function testHttpLoopbackIpv6Passes(): void
    {
        AgentAdmitException::assertHttpsUrl('http://[::1]/api/v1/verify', 'verify_url');
        $this->addToAssertionCount(1);
    }

    public function testHttpExternalHostThrows(): void
    {
        $this->expectException(AgentAdmitException::class);
        $this->expectExceptionMessageMatches('/must use HTTPS/');
        AgentAdmitException::assertHttpsUrl('http://api.agentadmit.com/api/v1/verify', 'verify_url');
    }

    public function testHttpExternalWithPortThrows(): void
    {
        $this->expectException(AgentAdmitException::class);
        AgentAdmitException::assertHttpsUrl('http://example.com:8080/path', 'api_url');
    }

    public function testFtpUrlThrows(): void
    {
        $this->expectException(AgentAdmitException::class);
        AgentAdmitException::assertHttpsUrl('ftp://api.agentadmit.com/file', 'api_url');
    }

    // -------------------------------------------------------------------------
    // IntrospectionClient — construction-time validation of verify_url
    // -------------------------------------------------------------------------

    public function testIntrospectionClientRejectsHttpUrl(): void
    {
        $this->expectException(AgentAdmitException::class);
        $this->expectExceptionMessageMatches('/must use HTTPS/');
        new IntrospectionClient([
            'api_key'    => 'aa_test_dummy',
            'verify_url' => 'http://evil.example.com/api/v1/verify',
        ]);
    }

    public function testIntrospectionClientAcceptsHttpsUrl(): void
    {
        $client = new IntrospectionClient([
            'api_key'    => 'aa_test_dummy',
            'verify_url' => 'https://api.agentadmit.com/api/v1/verify',
        ]);
        $this->assertInstanceOf(IntrospectionClient::class, $client);
    }

    public function testIntrospectionClientAcceptsLocalhostHttp(): void
    {
        $client = new IntrospectionClient([
            'api_key'    => 'aa_test_dummy',
            'verify_url' => 'http://localhost:8080/api/v1/verify',
        ]);
        $this->assertInstanceOf(IntrospectionClient::class, $client);
    }

    // -------------------------------------------------------------------------
    // TokensClient — construction-time validation of api_url
    // -------------------------------------------------------------------------

    public function testTokensClientRejectsHttpUrl(): void
    {
        $this->expectException(AgentAdmitException::class);
        $this->expectExceptionMessageMatches('/must use HTTPS/');
        new TokensClient([
            'api_key' => 'aa_test_dummy',
            'app_id'  => 'app_test',
            'api_url' => 'http://evil.example.com',
        ]);
    }

    public function testTokensClientAcceptsHttpsUrl(): void
    {
        $client = new TokensClient([
            'api_key' => 'aa_test_dummy',
            'app_id'  => 'app_test',
            'api_url' => 'https://api.agentadmit.com',
        ]);
        $this->assertInstanceOf(TokensClient::class, $client);
    }

    // -------------------------------------------------------------------------
    // AlertsClient — construction-time validation of api_url
    // -------------------------------------------------------------------------

    public function testAlertsClientRejectsHttpUrl(): void
    {
        $this->expectException(AgentAdmitException::class);
        $this->expectExceptionMessageMatches('/must use HTTPS/');
        new AlertsClient([
            'api_key' => 'aa_test_dummy',
            'app_id'  => 'app_test',
            'api_url' => 'http://evil.example.com',
        ]);
    }

    public function testAlertsClientAcceptsLocalhostHttp(): void
    {
        $client = new AlertsClient([
            'api_key' => 'aa_test_dummy',
            'app_id'  => 'app_test',
            'api_url' => 'http://127.0.0.1:9000',
        ]);
        $this->assertInstanceOf(AlertsClient::class, $client);
    }
}
