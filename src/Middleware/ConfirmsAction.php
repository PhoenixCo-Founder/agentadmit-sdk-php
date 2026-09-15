<?php

namespace AgentAdmit\Middleware;

use AgentAdmit\IntrospectionClient;
use Illuminate\Http\Request;

/**
 * SDK 1.11 confirm-each-time: the per-request pieces every AgentAdmit
 * middleware contributes to the verify call.
 *
 *  - The agent's `X-AgentAdmit-Action-Attestation` header is ALWAYS forwarded
 *    when present, with or without an action summary — it is how the agent's
 *    retry proves the human confirmed.
 *  - When an action-summary hook is configured for the route, the middleware
 *    also digests the RAW request body (`sha256:<hex>`) and sends the summary,
 *    so the hosted ceremony commits to the exact payload and to the words the
 *    human was shown.
 *
 * Configuration (config/agentadmit.php):
 *
 *   'confirm_each_time' => [
 *       // Default hook: callable(Request $request): ?string
 *       'action_summary' => fn ($request) => 'Pay ' . $request->input('trainer')
 *           . ' $' . $request->input('amount'),
 *       // Per-route hooks, selected by the middleware's second parameter:
 *       //   Route::middleware('agentadmit.scope:write:payments,pay')
 *       'summaries' => [
 *           'pay' => fn ($request) => 'Pay ' . $request->input('trainer'),
 *       ],
 *   ],
 *
 * A hook that throws, or returns a non-string / empty value, never blocks the
 * call: the summary is simply omitted (the digest still rides along, so the
 * confirmation still covers the exact payload).
 */
trait ConfirmsAction
{
    /**
     * The agent's attestation id from the inbound request, or null. Always
     * forwarded, on every gate, summary hook or not.
     */
    protected function actionAttestationId(Request $request): ?string
    {
        return IntrospectionClient::attestationFromRequest($request);
    }

    /**
     * The confirm-each-time body pair for this request: [$requestDigest,
     * $actionSummary]. Both null when no summary hook is configured for the
     * route — an app that has not opted in sends exactly what 1.10 sent.
     *
     * @param  string|null $summaryKey Optional route parameter naming a hook
     *                                 under `agentadmit.confirm_each_time.summaries`.
     * @return array{0: ?string, 1: ?string}
     */
    protected function confirmEachTimeFields(Request $request, ?string $summaryKey = null): array
    {
        $hook = $this->actionSummaryHook($summaryKey);
        if ($hook === null) {
            return [null, null];
        }

        // Laravel returns the raw body without consuming it, so the route
        // handler still reads the same payload.
        $digest = IntrospectionClient::requestDigestFor($request->getContent());

        $summary = null;
        try {
            $summary = $hook($request);
        } catch (\Throwable $e) {
            // A broken summary hook must not take the endpoint down; the call
            // still verifies, just without the human-readable description.
            $summary = null;
        }

        if (!is_string($summary) || trim($summary) === '') {
            return [$digest, null];
        }

        return [$digest, substr(trim($summary), 0, IntrospectionClient::MAX_SUMMARY_LENGTH)];
    }

    /**
     * Resolve the configured summary callable: the named per-route hook when
     * the route names one, otherwise the app-wide default. Null when neither
     * is configured (or the configured value is not callable).
     */
    private function actionSummaryHook(?string $summaryKey): ?callable
    {
        if (is_string($summaryKey) && $summaryKey !== '') {
            $named = config('agentadmit.confirm_each_time.summaries.' . $summaryKey);
            if (is_callable($named)) {
                return $named;
            }
        }

        $default = config('agentadmit.confirm_each_time.action_summary');

        return is_callable($default) ? $default : null;
    }
}
