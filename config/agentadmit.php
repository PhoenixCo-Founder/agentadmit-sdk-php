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

    // AgentAdmit hosted service URLs (do not change unless instructed)
    'verify_url' => env('AGENTADMIT_VERIFY_URL', 'https://api.agentadmit.com/api/v1/verify'),
    'api_url' => env('AGENTADMIT_API_URL', 'https://api.agentadmit.com'),

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
