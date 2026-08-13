<?php

declare(strict_types=1);

namespace AgentAdmit;

/**
 * App-attested presence: a ceremony fact your app attests at token issuance.
 *
 * Pass an instance to TokensClient::issueToken() AFTER verifying and
 * consuming your app's own fresh, purpose-bound WebAuthn/passkey attestation
 * for the mint. The SDK forwards it to the hosted mint as
 * presence {verified: true, uv: true, method, verified_at}; the hosted
 * service stores it method-prefixed "app:<method>" — the provenance marker
 * that keeps app-attested facts distinct from hosted-witnessed ceremonies.
 *
 * Honesty ceiling: this is YOUR attestation, recorded and provenance-marked.
 * It is not witnessed by AgentAdmit and not independently verifiable. Only
 * construct one for a ceremony that verified the user with UV (biometric or
 * PIN user verification); verified/uv serialize as literal true and cannot
 * represent anything else — a ceremony without UV carries no presence fact,
 * so simply pass null.
 *
 * $verifiedAt must be recent: the hosted service enforces a 10-minute
 * freshness window with 60 seconds of future clock-skew slack. PHP
 * DateTimeInterface always carries a timezone, so serialization is RFC 3339
 * with an explicit offset by construction (the hosted contract; offset-less
 * timestamps are rejected with 400).
 */
final class AppAttestedPresence
{
    private const METHOD_PATTERN = '/^[a-z0-9_]+$/';
    private const METHOD_MAX_LENGTH = 60;

    public readonly string $method;
    public readonly \DateTimeImmutable $verifiedAt;

    /**
     * @param string             $method     Your ceremony mechanism, 1-60 lowercase
     *                                       alphanumeric/underscore characters
     *                                       (e.g. 'my_webauthn')
     * @param \DateTimeInterface $verifiedAt When the ceremony completed
     * @throws \InvalidArgumentException When $method is out of contract —
     *                                   validated at construction, before any
     *                                   request, where the fix is obvious
     */
    public function __construct(string $method, \DateTimeInterface $verifiedAt)
    {
        if (
            $method === ''
            || strlen($method) > self::METHOD_MAX_LENGTH
            || preg_match(self::METHOD_PATTERN, $method) !== 1
        ) {
            throw new \InvalidArgumentException(
                'method must be 1-' . self::METHOD_MAX_LENGTH
                . " lowercase alphanumeric/underscore characters (e.g. 'my_webauthn')"
            );
        }

        $this->method = $method;
        $this->verifiedAt = \DateTimeImmutable::createFromInterface($verifiedAt);
    }

    /**
     * The exact JSON object forwarded to the hosted mint.
     *
     * @return array{verified: true, uv: true, method: string, verified_at: string}
     */
    public function toWire(): array
    {
        return [
            'verified' => true,
            'uv' => true,
            'method' => $this->method,
            'verified_at' => $this->verifiedAt->format(\DateTimeInterface::ATOM),
        ];
    }
}
