<?php

namespace AgentAdmit\Tests;

use AgentAdmit\AgentAdmitException;
use AgentAdmit\Webhook;
use PHPUnit\Framework\TestCase;

class WebhookTest extends TestCase
{
    private const SECRET = 'whsec_test123';
    private const PAYLOAD = '{"event":"agentadmit.alert","alert_type":"usage_spike"}';
    private const NOW = 1750000000;

    private function sign(string $payload, string $secret = self::SECRET, int $ts = self::NOW): string
    {
        $digest = hash_hmac('sha256', $ts . '.' . $payload, $secret);
        return "t={$ts},v1={$digest}";
    }

    public function testValidSignaturePasses(): void
    {
        Webhook::verifySignature(self::PAYLOAD, $this->sign(self::PAYLOAD), self::SECRET, now: self::NOW);
        $this->addToAssertionCount(1);
    }

    public function testTamperedPayloadFails(): void
    {
        $this->expectException(AgentAdmitException::class);
        $this->expectExceptionMessage('verification failed');
        Webhook::verifySignature(self::PAYLOAD . ' ', $this->sign(self::PAYLOAD), self::SECRET, now: self::NOW);
    }

    public function testWrongSecretFails(): void
    {
        $this->expectException(AgentAdmitException::class);
        Webhook::verifySignature(
            self::PAYLOAD,
            $this->sign(self::PAYLOAD, 'whsec_other456'),
            self::SECRET,
            now: self::NOW
        );
    }

    public function testStaleTimestampFails(): void
    {
        $this->expectException(AgentAdmitException::class);
        $this->expectExceptionMessage('tolerance');
        Webhook::verifySignature(
            self::PAYLOAD,
            $this->sign(self::PAYLOAD, self::SECRET, self::NOW - 600),
            self::SECRET,
            now: self::NOW
        );
    }

    public function testFutureTimestampFails(): void
    {
        $this->expectException(AgentAdmitException::class);
        Webhook::verifySignature(
            self::PAYLOAD,
            $this->sign(self::PAYLOAD, self::SECRET, self::NOW + 600),
            self::SECRET,
            now: self::NOW
        );
    }

    public function testWithinTolerancePasses(): void
    {
        Webhook::verifySignature(
            self::PAYLOAD,
            $this->sign(self::PAYLOAD, self::SECRET, self::NOW - 200),
            self::SECRET,
            now: self::NOW
        );
        $this->addToAssertionCount(1);
    }

    public function testToleranceZeroDisablesTimestampCheck(): void
    {
        Webhook::verifySignature(
            self::PAYLOAD,
            $this->sign(self::PAYLOAD, self::SECRET, self::NOW - 99999),
            self::SECRET,
            tolerance: 0,
            now: self::NOW
        );
        $this->addToAssertionCount(1);
    }

    public function testMissingHeaderFails(): void
    {
        $this->expectException(AgentAdmitException::class);
        $this->expectExceptionMessage('Missing');
        Webhook::verifySignature(self::PAYLOAD, '', self::SECRET, now: self::NOW);
    }

    /**
     * @dataProvider malformedHeaders
     */
    public function testMalformedHeaderFails(string $header): void
    {
        $this->expectException(AgentAdmitException::class);
        $this->expectExceptionMessage('Malformed');
        Webhook::verifySignature(self::PAYLOAD, $header, self::SECRET, now: self::NOW);
    }

    public static function malformedHeaders(): array
    {
        return [
            ['nonsense'],
            ['t=abc,v1=def'],
            ['t=123'],
            ['v1=abc'],
        ];
    }

    public function testMissingSecretFails(): void
    {
        $this->expectException(AgentAdmitException::class);
        $this->expectExceptionMessage('secret');
        Webhook::verifySignature(self::PAYLOAD, $this->sign(self::PAYLOAD), '', now: self::NOW);
    }

    public function testMultipleCandidatesAnyMatchPasses(): void
    {
        Webhook::verifySignature(
            self::PAYLOAD,
            $this->sign(self::PAYLOAD) . ',v1=deadbeef',
            self::SECRET,
            now: self::NOW
        );
        $this->addToAssertionCount(1);
    }

    public function testBooleanForm(): void
    {
        $this->assertTrue(
            Webhook::isValidSignature(self::PAYLOAD, $this->sign(self::PAYLOAD), self::SECRET, now: self::NOW)
        );
        $this->assertFalse(
            Webhook::isValidSignature(self::PAYLOAD . 'x', $this->sign(self::PAYLOAD), self::SECRET, now: self::NOW)
        );
    }
}
