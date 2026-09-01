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
 * Laravel middleware that enforces scope ONLY for agent tokens.
 * Regular user requests pass through without scope enforcement.
 *
 * Usage in routes:
 *   Route::middleware('agentadmit.scope_if_agent:read:orders')->get('/api/orders', ...);
 */
class RequireScopeIfAgent
{
    private IntrospectionClient $client;

    public function __construct(IntrospectionClient $client)
    {
        $this->client = $client;
    }

    public function handle(Request $request, Closure $next, string $scope): Response
    {
        $token = $request->bearerToken();
        $prefix = config('agentadmit.token_prefix_access', 'ag_at_');

        // Not an agent token — pass through
        if (!$token || !str_starts_with($token, $prefix)) {
            return $next($request);
        }

        try {
            // SDK 1.10: the scope this middleware enforces IS known at verify
            // time, so it rides in the verify body as scope_used, alongside
            // the request path (query stripped client-side) and method, for
            // the hosted per-call audit log.
            $result = $this->client->verify(
                $token,
                $scope,
                $request->getPathInfo(),
                $request->method()
            );

            if (!$result->hasScope($scope)) {
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

            return $next($request);

        } catch (VerificationDeniedException $e) {
            // SDK 1.10: the hosted service refused this otherwise-active call
            // (active: true + error). Return the typed 403 denial body -
            // step-up shape for insufficient_scope, hosted fields verbatim
            // for bound_exceeded, generic fail-closed for unknown codes.
            Log::warning('AgentAdmit RequireScopeIfAgent hosted denial: ' . $e->getMessage());

            return response()->json($e->getDenialBody(), 403);
        } catch (AgentAdmitException $e) {
            // M8: Log internal detail server-side; return a generic message to the caller
            // to avoid leaking verify URLs, cURL errors, or other internal information.
            Log::error('AgentAdmit RequireScopeIfAgent error: ' . $e->getMessage());

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
