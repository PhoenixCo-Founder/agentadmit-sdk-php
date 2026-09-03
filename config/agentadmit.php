<?php

/*
 * IMPORTANT: AgentAdmit uses MANDATORY hosted introspection.
 * All token validation goes through api.agentadmit.com.
 * There is no self-hosted mode. No local JWT validation. No bypass.
 * This is required for security, audit logging, and scope enforcement.
 */

return [
    // From your AgentAdmit dashboard (agentadmit.com)
    'app_id' => env('AGENTADMIT_APP_ID', ''),
    'api_key' => env('AGENTADMIT_API_KEY', ''),

    // AgentAdmit hosted service URLs (do not change unless instructed).
    // One origin, not two: if you point AGENTADMIT_API_URL at another service
    // (staging, a local rig) and leave the verify URL at its default, verify
    // follows the API URL automatically. An explicitly set AGENTADMIT_VERIFY_URL
    // always wins.
    'verify_url' => env('AGENTADMIT_VERIFY_URL', 'https://api.agentadmit.com/api/v1/verify'),
    'api_url' => env('AGENTADMIT_API_URL', 'https://api.agentadmit.com'),

    // Confirm each time (1.11): scopes you registered with confirm_each_time
    // require a fresh human confirmation for EVERY call. The action summary is
    // the plain-language description of THIS action shown to the human on the
    // hosted confirmation page and committed into their passkey signature —
    // AgentAdmit does not verify it against the request, it proves what the
    // human was shown. Each hook is callable(Illuminate\Http\Request): ?string.
    'confirm_each_time' => [
        // App-wide default hook, used by any AgentAdmit gate that does not
        // name one. Leave null to send no summary.
        //   'action_summary' => fn ($request) => 'Pay ' . $request->input('trainer'),
        'action_summary' => null,

        // Per-route hooks, selected by the middleware's second parameter:
        //   Route::middleware('agentadmit.scope:write:payments,pay')
        //   'summaries' => ['pay' => fn ($request) => 'Pay ' . $request->input('trainer')],
        'summaries' => [],
    ],

    // Webhook signing secret (whsec_…) — shown once when you configure the
    // alert webhook URL in the dashboard. Used to verify inbound alert
    // webhooks via AgentAdmit\Webhook::verifySignature().
    'webhook_secret' => env('AGENTADMIT_WEBHOOK_SECRET', ''),

    // Token prefixes
    'token_prefix_access' => 'ag_at_',
    'token_prefix_connection' => 'ag_ct_',

    // Rate limiting — introspection retry policy
    // Max retries on HTTP 429 before throwing RateLimitException. Default: 3.
    'max_retries' => (int) env('AGENTADMIT_MAX_RETRIES', 3),
];
