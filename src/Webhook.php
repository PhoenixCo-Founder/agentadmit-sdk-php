<?php

namespace AgentAdmit;

/**
 * Verification for inbound AgentAdmit alert webhooks.
 *
 * AgentAdmit signs every alert webhook delivery with the app's webhook
 * signing secret (whsec_…, returned once when the webhook URL is
 * configured). The signature arrives in the X-AgentAdmit-Signature header:
 *
 *     X-AgentAdmit-Signature: t=<unix_ts>,v1=<hex hmac-sha256>
 *
 * where the HMAC input is "{t}.{rawBody}" keyed with the full whsec_ secret.
 * Always verify against the raw request body ($request->getContent()),
 * before any JSON parsing.
 *
 * @example
 * ```php
 * Route::post('/agentadmit/alerts', function (Request $request) {
 *     try {
 *         Webhook::verifySignature(
 *             $request->getContent(),
 *             $request->header('X-AgentAdmit-Signature', ''),
 *             config('agentadmit.webhook_secret'),
 *         );
 *     } catch (AgentAdmitException $e) {
 *         return response()->json(['error' => 'invalid_signature'], 400);
 *     }
 *     $event = $request->json()->all();
 *     // ...
 * });
 * ```
 */
final class Webhook
{
    /** Header AgentAdmit signs alert webhook deliveries with. */
    public const SIGNATURE_HEADER = 'X-AgentAdmit-Signature';

    /** Default maximum clock skew (seconds) allowed for replay protection. */
    public const DEFAULT_TOLERANCE_SECONDS = 300;

    private function __construct() {}

    /**
     * Verify the X-AgentAdmit-Signature header on an inbound alert webhook.
     *
     * @param string $payload   The raw request body
     * @param string $header    The X-AgentAdmit-Signature header value
     * @param string $secret    The app's webhook signing secret (whsec_…)
     * @param int    $tolerance Max clock skew in seconds (0 disables the check)
     * @param int|null $now     Override the current Unix timestamp (for tests)
     * @throws AgentAdmitException if the header is missing/malformed, the
     *         timestamp is outside the tolerance window, or no signature
     *         matches; the message never includes the secret or payload
     */
    public static function verifySignature(
        string $payload,
        string $header,
        string $secret,
        int $tolerance = self::DEFAULT_TOLERANCE_SECONDS,
        ?int $now = null
    ): void {
        if ($secret === '') {
            throw new AgentAdmitException('Webhook signing secret is required', 400);
        }
        if ($header === '') {
            throw new AgentAdmitException('Missing X-AgentAdmit-Signature header', 400);
        }

        $timestamp = null;
        $candidates = [];
        foreach (explode(',', $header) as $part) {
            $eq = strpos($part, '=');
            if ($eq === false) {
                continue;
            }
            $key = trim(substr($part, 0, $eq));
            $value = trim(substr($part, $eq + 1));
            if ($key === 't') {
                if (!ctype_digit($value)) {
                    throw new AgentAdmitException('Malformed signature header', 400);
                }
                $timestamp = (int) $value;
            } elseif ($key === 'v1') {
                $candidates[] = $value;
            }
        }

        if ($timestamp === null || $candidates === []) {
            throw new AgentAdmitException('Malformed signature header', 400);
        }

        if ($tolerance > 0 && abs(($now ?? time()) - $timestamp) > $tolerance) {
            throw new AgentAdmitException('Signature timestamp outside tolerance window', 400);
        }

        $expected = hash_hmac('sha256', $timestamp . '.' . $payload, $secret);
        foreach ($candidates as $candidate) {
            if (hash_equals($expected, $candidate)) {
                return;
            }
        }

        throw new AgentAdmitException('Webhook signature verification failed', 400);
    }

    /**
     * Boolean form of verifySignature().
     */
    public static function isValidSignature(
        string $payload,
        string $header,
        string $secret,
        int $tolerance = self::DEFAULT_TOLERANCE_SECONDS,
        ?int $now = null
    ): bool {
        try {
            self::verifySignature($payload, $header, $secret, $tolerance, $now);
            return true;
        } catch (AgentAdmitException $e) {
            return false;
        }
    }
}
