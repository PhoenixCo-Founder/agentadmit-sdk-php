<?php

namespace AgentAdmit\Middleware;

use AgentAdmit\AgentAdmitException;
use AgentAdmit\IntrospectionClient;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Laravel middleware that enforces a required scope.
 * Agent MUST have the scope or gets 403.
 *
 * Usage in routes:
 *   Route::middleware('agentadmit.scope:read:orders')->get('/api/orders', ...);
 */
class RequireScope
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

        if (!$token || !str_starts_with($token, $prefix)) {
            return response()->json([
                'error' => 'invalid_token',
                'error_description' => 'AgentAdmit token required',
            ], 401);
        }

        try {
            $result = $this->client->verify($token);

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

            return $next($request);

        } catch (AgentAdmitException $e) {
            return response()->json([
                'error' => $e->getStatusCode() === 401 ? 'invalid_token' : 'introspection_failed',
                'error_description' => $e->getMessage(),
            ], $e->getStatusCode());
        }
    }
}
