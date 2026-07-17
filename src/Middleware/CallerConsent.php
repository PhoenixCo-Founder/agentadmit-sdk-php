<?php

namespace AgentAdmit\Middleware;

use AgentAdmit\AgentAdmitException;
use AgentAdmit\ConsentClient;
use AgentAdmit\IntrospectionClient;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

/**
 * Caller-Identity Consent middleware: the "classify caller, then gate the
 * right independent path" recipe as one Laravel middleware, so an app owner
 * does not have to hand-roll it.
 *
 * One endpoint serves every caller class. On each request the middleware:
 *
 *  1. classifies the caller from the STRUCTURE of the credential (a class the
 *     caller cannot self-select), before any consent check;
 *  2. routes to that class's ISOLATED consent path; no path reads or inherits
 *     another class's preference;
 *  3. permits or denies, and sets request attributes
 *     (agentadmit.caller_class, agentadmit.consent, plus the standard agent
 *     attributes on the external-agent path).
 *
 *  - external_agent: an ag_at_ access token -> hosted introspection, which
 *    returns the external-agent consent verdict inline plus the granted
 *    scopes. Consent is evaluated BEFORE scope (a denied class must not learn
 *    scope state or step-up guidance). A missing or malformed verdict is
 *    resolved through the Consent Ledger, fail closed - absence is never a
 *    grant.
 *  - in_app_ai: your application's own server-side AI code path -> the
 *    Consent Ledger /consent/check for the in-app-AI class.
 *  - human_session: your application's own permission model (sharing, roles,
 *    grants). Deferred to your existing authorization by default; opt in to a
 *    stored human-session switch with the gate_human config flag.
 *
 * The three decisions are independent: granting one never grants another.
 *
 * SECURITY: this is a consent gate, not an authenticator. It classifies the
 * caller and enforces the per-class CONSENT decision; it does not by itself
 * authenticate a human session. Register it AFTER your own authentication.
 * On the human_session path it defers to your application's permission model
 * and continues the pipeline without re-authenticating. The external_agent
 * path is always authenticated (hosted introspection); the in_app_ai path
 * always evaluates the ledger.
 *
 * Configuration (config/agentadmit.php):
 *   'caller_consent' => [
 *       // Given the Request, return your app's identifier for the data owner.
 *       // Required for the in_app_ai path (and human_session under gate_human).
 *       'resolve_data_owner_id' => fn ($request) => $request->route('owner_id'),
 *       // Given the Request, return 'in_app_ai' or 'human_session' from the
 *       // STRUCTURE of the credential (e.g. an internal service token), never
 *       // a value the caller can set. Defaults to 'human_session'.
 *       'classify_non_agent' => fn ($request) => 'human_session',
 *       // Optional finer-than-class consent group for ledger checks.
 *       'scope_group' => null,
 *       // Also gate human sessions against a stored switch. Default false.
 *       'gate_human' => false,
 *   ],
 *
 * Usage in routes (scope is the optional middleware parameter):
 *   Route::middleware('agentadmit.caller_consent:read:records')
 *       ->get('/api/records/{owner_id}', ...);
 */
class CallerConsent
{
    private IntrospectionClient $introspection;
    private ConsentClient $consent;

    public function __construct(IntrospectionClient $introspection, ConsentClient $consent)
    {
        $this->introspection = $introspection;
        $this->consent = $consent;
    }

    /**
     * Classify the caller from credential structure, before any consent
     * check. An ag_at_ bearer token is an external agent; anything else is
     * resolved by the classify_non_agent callable (default: human_session).
     * The class is derived, never self-selected by the caller.
     */
    public function classifyCaller(Request $request): string
    {
        $token = $request->bearerToken();
        $prefix = config('agentadmit.token_prefix_access', 'ag_at_');

        if ($token && str_starts_with($token, $prefix)) {
            return ConsentClient::CALLER_CLASS_EXTERNAL_AGENT;
        }

        $classify = config('agentadmit.caller_consent.classify_non_agent');
        if (is_callable($classify) && $classify($request) === ConsentClient::CALLER_CLASS_IN_APP_AI) {
            return ConsentClient::CALLER_CLASS_IN_APP_AI;
        }

        return ConsentClient::CALLER_CLASS_HUMAN_SESSION;
    }

    public function handle(Request $request, Closure $next, ?string $scope = null): Response
    {
        $callerClass = $this->classifyCaller($request);
        $request->attributes->set('agentadmit.caller_class', $callerClass);

        if ($callerClass === ConsentClient::CALLER_CLASS_EXTERNAL_AGENT) {
            return $this->handleExternalAgent($request, $next, $scope);
        }

        if ($callerClass === ConsentClient::CALLER_CLASS_IN_APP_AI) {
            return $this->handleLedgerGated(
                $request,
                $next,
                ConsentClient::CALLER_CLASS_IN_APP_AI,
                'in_app_ai',
                'The data owner has not enabled in-app AI analysis.'
            );
        }

        if (config('agentadmit.caller_consent.gate_human', false)) {
            return $this->handleLedgerGated(
                $request,
                $next,
                ConsentClient::CALLER_CLASS_HUMAN_SESSION,
                'user',
                'The data owner has not enabled this access.'
            );
        }

        // Default: defer the human path to the app's existing authorization.
        $request->attributes->set('agentadmit.auth_type', 'user');

        return $next($request);
    }

    /**
     * External-agent path: hosted introspection carries the verdict and the
     * scopes. Consent is evaluated BEFORE scope (Patent FIG. 3: the class
     * consent decision precedes scope evaluation), so a caller whose class the
     * owner has denied never learns scope state. An absent or malformed
     * verdict is resolved through the Consent Ledger, fail closed - the hosted
     * service omits the block when its consent-store read fails (designed
     * degraded mode), so absence is never a grant.
     */
    private function handleExternalAgent(Request $request, Closure $next, ?string $scope): Response
    {
        try {
            $result = $this->introspection->verify($request->bearerToken());
        } catch (AgentAdmitException $e) {
            Log::error('AgentAdmit CallerConsent verify error: ' . $e->getMessage());
            $is401 = $e->getStatusCode() === 401;

            return response()->json([
                'error' => $is401 ? 'invalid_token' : 'introspection_failed',
                'error_description' => $is401
                    ? 'Token is invalid or not authorized.'
                    : 'Token verification failed. Please try again.',
            ], $e->getStatusCode());
        }

        // Consent first (Patent FIG. 3: the class consent decision precedes
        // scope evaluation). Checking scope first leaked granted-scope state
        // to callers whose class the owner had denied.
        $verdict = $result->consent;
        if (!is_array($verdict) || !is_bool($verdict['granted'] ?? null)) {
            // Absent or malformed verdict: the hosted service omits the block
            // when its consent-store read fails (designed degraded mode).
            // Resolve through the Consent Ledger; never treat absence as a
            // grant. Fail closed when the owner is unresolvable or the ledger
            // errors.
            $owner = $result->userId;
            if ($owner === '') {
                return response()->json([
                    'error' => 'consent_unavailable',
                    'error_description' => 'Introspection carried no consent verdict and no resolvable data owner.',
                ], 503);
            }

            try {
                $verdict = $this->consent->checkConsent(
                    $owner,
                    ConsentClient::CALLER_CLASS_EXTERNAL_AGENT,
                    config('agentadmit.caller_consent.scope_group')
                );
            } catch (\Throwable $e) {
                Log::warning('AgentAdmit CallerConsent ledger unavailable: ' . $e->getMessage());

                return response()->json([
                    'error' => 'consent_unavailable',
                    'error_description' => 'Consent check failed',
                ], 503);
            }
        }

        if (($verdict['granted'] ?? null) !== true) {
            return response()->json([
                'error' => 'consent_not_granted',
                'caller_class' => ConsentClient::CALLER_CLASS_EXTERNAL_AGENT,
                'message' => 'The data owner has not enabled external agent access.',
            ], 403);
        }

        if ($scope !== null && !$result->hasScope($scope)) {
            return response()->json([
                'error' => 'insufficient_scope',
                'required_scope' => $scope,
                'granted_scopes' => $result->scopes,
                'message' => "This action requires '{$scope}' scope.",
            ], 403);
        }

        $request->attributes->set('agentadmit.auth_type', 'agent');
        $request->attributes->set('agentadmit.user_id', $result->userId);
        $request->attributes->set('agentadmit.scopes', $result->scopes);
        $request->attributes->set('agentadmit.connection_id', $result->connectionId);
        $request->attributes->set('agentadmit.agent_label', $result->agentLabel);
        $request->attributes->set('agentadmit.consent', $verdict);

        return $next($request);
    }

    /**
     * Token-less caller class (in_app_ai, or human_session under gate_human),
     * gated on the Consent Ledger. Fail closed: an unreachable or erroring
     * ledger denies, never allows.
     */
    private function handleLedgerGated(
        Request $request,
        Closure $next,
        string $callerClass,
        string $authType,
        string $deniedMessage
    ): Response {
        $resolver = config('agentadmit.caller_consent.resolve_data_owner_id');
        $owner = is_callable($resolver) ? $resolver($request) : null;

        if (!$owner) {
            return response()->json([
                'error' => 'server_error',
                'error_description' => 'caller_consent.resolve_data_owner_id is required for this caller class',
            ], 500);
        }

        try {
            $verdict = $this->consent->checkConsent(
                $owner,
                $callerClass,
                config('agentadmit.caller_consent.scope_group')
            );
        } catch (\Throwable $e) {
            Log::warning('AgentAdmit CallerConsent ledger unavailable: ' . $e->getMessage());

            return response()->json([
                'error' => 'consent_unavailable',
                'error_description' => 'Consent check failed',
            ], 503);
        }

        if (($verdict['granted'] ?? null) !== true) {
            return response()->json([
                'error' => 'consent_not_granted',
                'caller_class' => $callerClass,
                'message' => $deniedMessage,
            ], 403);
        }

        $request->attributes->set('agentadmit.auth_type', $authType);
        $request->attributes->set('agentadmit.consent', $verdict);

        return $next($request);
    }
}
