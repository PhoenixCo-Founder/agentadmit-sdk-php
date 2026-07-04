<?php

namespace AgentAdmit;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

/**
 * ConsentClient — Consent Ledger verdicts via the AgentAdmit hosted service.
 *
 * External agents get their verdict inline in the verify response
 * (IntrospectionResult::$consent). The two token-less caller classes
 * (human sessions and your app's own in-app AI) ask checkConsent().
 *
 * Consent is orthogonal to token revocation: on a denied verdict your app
 * returns its own 403; nothing is revoked. Every evaluation is appended to
 * the exportable consent trail.
 */
class ConsentClient
{
    public const CALLER_CLASS_HUMAN_SESSION  = 'human_session';
    public const CALLER_CLASS_IN_APP_AI      = 'in_app_ai';
    public const CALLER_CLASS_EXTERNAL_AGENT = 'external_agent';

    public const CALLER_CLASSES = [
        self::CALLER_CLASS_HUMAN_SESSION,
        self::CALLER_CLASS_IN_APP_AI,
        self::CALLER_CLASS_EXTERNAL_AGENT,
    ];

    private array $config;

    public function __construct(array $config)
    {
        $this->config = $config;

        // Require HTTPS on configurable URLs (HTTP allowed only on loopback).
        $apiUrl = rtrim($config['api_url'] ?? 'https://api.agentadmit.com', '/');
        AgentAdmitException::assertHttpsUrl($apiUrl, 'api_url');
    }

    /**
     * Ask the Consent Ledger whether a caller class may act on a user's data.
     * POST /api/v1/consent/check
     *
     * @param string      $appUserId   Your app's identifier for the data owner
     * @param string      $callerClass One of the CALLER_CLASS_* constants
     * @param string|null $scopeGroup  Optional finer-than-class consent group
     * @return array      { "granted": bool, "caller_class": string,
     *                      "scope_group": ?string, "source": string,
     *                      "evaluated_at": string }
     * @throws AgentAdmitException
     */
    public function checkConsent(string $appUserId, string $callerClass, ?string $scopeGroup = null): array
    {
        if (!in_array($callerClass, self::CALLER_CLASSES, true)) {
            throw new AgentAdmitException(
                'callerClass must be one of: ' . implode(', ', self::CALLER_CLASSES),
                400
            );
        }

        $body = ['app_user_id' => $appUserId, 'caller_class' => $callerClass];
        if ($scopeGroup !== null) {
            $body['scope_group'] = $scopeGroup;
        }

        try {
            $response = Http::timeout(10)
                ->withHeaders($this->authHeaders())
                ->post($this->apiUrl('/api/v1/consent/check'), $body);

            $this->checkStatus($response, 'checkConsent');
            return $response->json();
        } catch (AgentAdmitException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new AgentAdmitException('checkConsent failed: ' . $e->getMessage(), 502);
        }
    }

    private function authHeaders(): array
    {
        return [
            'Authorization' => 'Bearer ' . ($this->config['api_key'] ?? ''),
            'X-App-Id'      => $this->config['app_id'] ?? '',
        ];
    }

    private function apiUrl(string $path): string
    {
        $base = rtrim($this->config['api_url'] ?? 'https://api.agentadmit.com', '/');
        return $base . $path;
    }

    private function checkStatus($response, string $operation): void
    {
        if ($response->failed()) {
            $status = $response->status();
            Log::error("AgentAdmit {$operation} failed with status {$status}: " . $response->body());
            throw new AgentAdmitException("{$operation} failed with HTTP {$status}", $status);
        }
    }
}
