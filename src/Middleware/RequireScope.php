<?php

namespace AgentAdmit\Middleware;

use AgentAdmit\AgentAdmitException;
use AgentAdmit\IntrospectionClient;
use AgentAdmit\VerificationDeniedException;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

/**
 * Laravel middleware that enforces a required scope.
 * Agent MUST have the scope or gets 403.
 *
 * Usage in routes:
 *   Route::middleware('agentadmit.scope:read:orders')->get('/api/orders', ...);
 *
 * Confirm-each-time (1.11): an optional SECOND parameter names an action
 * summary hook under `agentadmit.confirm_each_time.summaries`, used to
 * describe THIS action to the human on the hosted confirmation page:
 *
 *   Route::middleware('agentadmit.scope:write:payments,pay')->post('/api/pay', ...);
 *
 * When the hosted service requires a fresh confirmation it refuses with
 * `confirmation_required`; the middleware returns 403 carrying the
 * `confirmation` block, and the agent retries with the
 * `X-AgentAdmit-Action-Attestation` header (always forwarded).
 */
class RequireScope
{
    use ConfirmsAction;

    private IntrospectionClient $client;

    public function __construct(IntrospectionClient $client)
    {
        $this->client = $client;
    }

    public function handle(Request $request, Closure $next, string $scope, ?string $summaryKey = null): Response
    {
        $token = $request->bearerToken();
        $prefix = config('agentadmit.token_prefix_access', 'ag_at_');

        if (!$token || !str_starts_with($token, $prefix)) {
            return response()->json([
                'error' => 'invalid_token',
                'error_description' => 'AgentAdmit token required',
            ], 401);
        }

        try {
            // SDK 1.10: the scope this middleware enforces IS known at verify
            // time, so it rides in the verify body as scope_used, alongside
            // the request path (query stripped client-side) and method, for
            // the hosted per-call audit log.
            // SDK 1.11 confirm-each-time: the agent's attestation header is
            // always forwarded; the body digest and the app's action summary
            // ride along when a summary hook is configured for this route.
            [$requestDigest, $actionSummary] = $this->confirmEachTimeFields($request, $summaryKey);

            $result = $this->client->verify(
                $token,
                $scope,
                $request->getPathInfo(),
                $request->method(),
                false,
                $this->actionAttestationId($request),
                $requestDigest,
                $actionSummary
            );

            if (!$result->hasScope($scope)) {
                return response()->json([
                    'error' => 'insufficient_scope',
                    'required_scope' => $scope,
                    'granted_scopes' => $result->scopes,
                    'message' => "This action requires '{$scope}' scope.",
                ], 403);
            }

            // Set request attributes for downstream use
            $request->attributes->set('agentadmit.auth_type', 'agent');
            $request->attributes->set('agentadmit.user_id', $result->userId);
            $request->attributes->set('agentadmit.scopes', $result->scopes);
            $request->attributes->set('agentadmit.connection_id', $result->connectionId);
            $request->attributes->set('agentadmit.agent_label', $result->agentLabel);
            // Confirm-each-time (1.11): only set when the hosted service
            // accepted this call by consuming a fresh human confirmation for
            // exactly this action.
            if ($result->actionConfirmation !== null) {
                $request->attributes->set('agentadmit.action_confirmation', $result->actionConfirmation);
            }

            return $next($request);

        } catch (VerificationDeniedException $e) {
            // SDK 1.10: the hosted service refused this otherwise-active call
            // (active: true + error). Return the typed 403 denial body -
            // step-up shape for insufficient_scope, hosted fields verbatim
            // for bound_exceeded, generic fail-closed for unknown codes.
            Log::warning('AgentAdmit RequireScope hosted denial: ' . $e->getMessage());

            return response()->json($e->getDenialBody(), 403);
        } catch (AgentAdmitException $e) {
            // M8: Log internal detail server-side; return a generic message to the caller
            // to avoid leaking verify URLs, cURL errors, or other internal information.
            Log::error('AgentAdmit RequireScope error: ' . $e->getMessage());

            $is401 = $e->getStatusCode() === 401;
            return response()->json([
                'error' => $is401 ? 'invalid_token' : 'introspection_failed',
                'error_description' => $is401
                    ? 'Token is invalid or not authorized.'
                    : 'Token verification failed. Please try again.',
            ], $e->getStatusCode());
        }
    }
}
