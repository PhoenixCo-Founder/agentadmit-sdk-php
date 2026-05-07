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
    'verify_url' => env('AGENTADMIT_VERIFY_URL', 'https://api.agentadmit.com/v1/verify'),
    'api_url' => env('AGENTADMIT_API_URL', 'https://api.agentadmit.com'),

    // Token prefixes
    'token_prefix_access' => 'ag_at_',
    'token_prefix_connection' => 'ag_ct_',

    // Rate limiting — introspection retry policy
    // Max retries on HTTP 429 before throwing RateLimitException. Default: 3.
    'max_retries' => (int) env('AGENTADMIT_MAX_RETRIES', 3),
];
