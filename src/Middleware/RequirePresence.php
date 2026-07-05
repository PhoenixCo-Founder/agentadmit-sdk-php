<?php

namespace AgentAdmit\Middleware;

use AgentAdmit\AgentAdmitException;
use AgentAdmit\IntrospectionClient;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

/**
 * Laravel middleware that requires a presence-verified connection (agent-only).
 * Agent MUST be on a connection authorized with a completed WebAuthn presence
 * ceremony or gets 403 presence_required. Fail closed: connections minted
 * without a ceremony, malformed presence blocks, and older servers that omit
 * the block entirely are all rejected.
 *
 * Usage in routes:
 *   Route::middleware('agentadmit.presence')->post('/api/orders', ...);
 */
class RequirePresence
{
    private IntrospectionClient $client;

    public function __construct(IntrospectionClient $client)
    {
        $this->client = $client;
    }

    public function handle(Request $request, Closure $next): Response
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

            if (!$result->presenceVerified()) {
                return response()->json([
                    'error' => 'presence_required',
                    'error_description' => 'This action requires a connection authorized with human presence verification.',
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
            // M8: Log internal detail server-side; return a generic message to the caller
            // to avoid leaking verify URLs, cURL errors, or other internal information.
            Log::error('AgentAdmit RequirePresence error: ' . $e->getMessage());

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
