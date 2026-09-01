<?php

namespace AgentAdmit;

/**
 * SDK 1.10: the hosted verify endpoint refused an otherwise-active call.
 *
 * An introspection response with `active: true` AND a string `error` field is
 * a DENIAL, never a pass-through. The hosted service uses this shape when the
 * token itself is valid but THIS call must be refused (scope not granted,
 * bounded capability exceeded, or a refusal class this SDK version does not
 * know yet). Every 1.9.0 SDK checked only `active` and allowed those refused
 * calls through; this typed exception carries the hosted refusal fields so
 * middleware can return the correct 403 body instead of the generic
 * introspection-failure message.
 *
 * Status code is always 403. {@see getDenialBody()} is the exact JSON body a
 * middleware should return:
 *
 *  - insufficient_scope -> {error, required_scope, granted_scopes}
 *    (spec 6.4 step-up shape; granted_scopes from the hosted response when
 *    present, the hosted `scopes` array otherwise)
 *  - bound_exceeded     -> {error, error_description, bound?, renewal?}
 *    (hosted fields passed through verbatim)
 *  - anything else      -> {error, error_description: "Call refused by the
 *    authorization service."} (forward-compatible fail-closed)
 */
class VerificationDeniedException extends AgentAdmitException
{
    public const ERROR_BOUND_EXCEEDED = 'bound_exceeded';

    /** Generic description for refusal classes this SDK does not know. */
    public const GENERIC_REFUSAL_DESCRIPTION = 'Call refused by the authorization service.';

    /** @var array The exact 403 JSON body the middleware should return. */
    private array $denialBody;

    public function __construct(string $message, string $errorCode, array $denialBody)
    {
        parent::__construct($message, 403, $errorCode);
        $this->denialBody = $denialBody;
    }

    /** The exact 403 JSON body to return to the caller. */
    public function getDenialBody(): array
    {
        return $this->denialBody;
    }

    /**
     * Build the typed denial from an active-but-refused hosted response.
     *
     * @param string      $errorCode The string `error` on the active response.
     * @param array       $data      The full hosted response payload.
     * @param string|null $scopeUsed The scope this call reported as scope_used
     *                               (local fallback for required_scope when the
     *                               hosted response omits it).
     */
    public static function fromActiveError(string $errorCode, array $data, ?string $scopeUsed = null): self
    {
        if ($errorCode === IntrospectionClient::ERROR_INSUFFICIENT_SCOPE) {
            // Spec 6.4 step-up shape. granted_scopes comes from the hosted
            // response when present; otherwise fall back to the hosted
            // `scopes` array (the locally known granted set), else [].
            $granted = $data['granted_scopes'] ?? $data['scopes'] ?? [];
            if (!is_array($granted)) {
                $granted = [];
            }
            $granted = array_values(array_filter($granted, 'is_string'));

            $required = is_string($data['required_scope'] ?? null)
                ? $data['required_scope']
                : $scopeUsed;

            return new self(
                is_string($data['error_description'] ?? null)
                    ? $data['error_description']
                    : 'Scope not granted',
                IntrospectionClient::ERROR_INSUFFICIENT_SCOPE,
                [
                    'error' => IntrospectionClient::ERROR_INSUFFICIENT_SCOPE,
                    'required_scope' => $required,
                    'granted_scopes' => $granted,
                ]
            );
        }

        if ($errorCode === self::ERROR_BOUND_EXCEEDED) {
            // Pass the hosted refusal fields through verbatim; bound and
            // renewal ride along only when the hosted service sent them.
            $description = is_string($data['error_description'] ?? null)
                ? $data['error_description']
                : self::GENERIC_REFUSAL_DESCRIPTION;

            $body = [
                'error' => self::ERROR_BOUND_EXCEEDED,
                'error_description' => $description,
            ];
            if (isset($data['bound'])) {
                $body['bound'] = $data['bound'];
            }
            if (isset($data['renewal'])) {
                $body['renewal'] = $data['renewal'];
            }

            return new self($description, self::ERROR_BOUND_EXCEEDED, $body);
        }

        // Unknown refusal class on an active response: fail closed with the
        // code preserved and a generic description (the v1.5.1 lesson - never
        // let an unrecognized hosted verdict become an allow).
        return new self(
            'Call refused by the authorization service: ' . $errorCode,
            $errorCode,
            [
                'error' => $errorCode,
                'error_description' => self::GENERIC_REFUSAL_DESCRIPTION,
            ]
        );
    }
}
