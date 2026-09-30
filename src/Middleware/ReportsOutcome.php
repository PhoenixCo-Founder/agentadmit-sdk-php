<?php

namespace AgentAdmit\Middleware;

use AgentAdmit\IntrospectionClient;
use AgentAdmit\IntrospectionResult;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

/**
 * Optional post-handler outcome reporting for Laravel middleware.
 *
 * The report is sent only after the downstream app returns a Response, and
 * failures are logged without replacing that app response.
 */
trait ReportsOutcome
{
    protected function attachAgentAdmitAttributes(Request $request, IntrospectionResult $result): void
    {
        $request->attributes->set('agentadmit.auth_type', 'agent');
        $request->attributes->set('agentadmit.user_id', $result->userId);
        $request->attributes->set('agentadmit.scopes', $result->scopes);
        $request->attributes->set('agentadmit.connection_id', $result->connectionId);
        $request->attributes->set('agentadmit.agent_label', $result->agentLabel);
        if ($result->auditRowId !== null) {
            $request->attributes->set('agentadmit.audit_row_id', $result->auditRowId);
        }
        if ($result->consumedReceipt !== null) {
            $request->attributes->set('agentadmit.consumed_receipt', $result->consumedReceipt);
        }
        if ($result->actionConfirmation !== null) {
            $request->attributes->set('agentadmit.action_confirmation', $result->actionConfirmation);
        }
    }

    protected function withOutcomeReport(Request $request, \Closure $next, IntrospectionClient $client, IntrospectionResult $result): Response
    {
        $response = $next($request);

        if (!$response instanceof Response) {
            return $response;
        }

        $this->reportOutcomeAfterResponse($client, $result, $response);

        return $response;
    }

    private function reportOutcomeAfterResponse(IntrospectionClient $client, IntrospectionResult $result, Response $response): void
    {
        if (config('agentadmit.outcome_reporting.enabled', false) !== true) {
            return;
        }

        if ($result->auditRowId === null) {
            return;
        }

        $statusClass = self::statusClassFor($response->getStatusCode());
        if ($statusClass === null) {
            return;
        }

        $outcome = $response->getStatusCode() < 400
            ? IntrospectionClient::OUTCOME_EXECUTED
            : IntrospectionClient::OUTCOME_FAILED;

        try {
            $client->reportOutcome($result->auditRowId, $outcome, $statusClass);
        } catch (\Throwable $e) {
            Log::warning('AgentAdmit outcome report failed after response: ' . $e->getMessage());
        }
    }

    private static function statusClassFor(int $statusCode): ?string
    {
        if ($statusCode < 100 || $statusCode > 599) {
            return null;
        }

        return intdiv($statusCode, 100) . 'xx';
    }
}
