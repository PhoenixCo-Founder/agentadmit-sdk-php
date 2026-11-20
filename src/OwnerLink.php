<?php

namespace AgentAdmit;

/**
 * SDK 1.15: the result of {@see TokensClient::createOwnerLink()}.
 *
 * $ownerSessionUrl opens a pending confirm-each-time request for the app's own
 * signed-in user: the user creates a passkey (when they have none yet) and
 * confirms on that page; on a computer the page can show a QR code to continue
 * on the user's phone. The URL is for that user's browser only. Do not return
 * it to an agent and do not log it; the SDK does not log it either, and
 * var_dump/print_r show it masked.
 */
final class OwnerLink
{
    public function __construct(
        public readonly string $actionSessionId,
        public readonly string $ownerSessionUrl,
        /**
         * True (201) when the user has no passkey on file for the app yet and
         * creates one on the page; false (200) when a passkey is already on
         * file and the URL is the ordinary confirmation page.
         */
        public readonly bool $enrollmentRequired,
        /** 'no_passkey' or 'no_eligible_authenticator' when enrollment is required, else null. */
        public readonly ?string $enrollmentReason,
        public readonly string $expiresAt,
    ) {
    }

    /** Keeps the owner session URL out of var_dump / print_r output. */
    public function __debugInfo(): array
    {
        return [
            'actionSessionId' => $this->actionSessionId,
            'ownerSessionUrl' => '[hidden]',
            'enrollmentRequired' => $this->enrollmentRequired,
            'enrollmentReason' => $this->enrollmentReason,
            'expiresAt' => $this->expiresAt,
        ];
    }
}
