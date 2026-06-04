<?php

namespace AgentAdmit;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

/**
 * AlertsClient — configure and query security alerts via the AgentAdmit hosted service.
 *
 * Supported alert types:
 *  - volume_spike
 *  - failed_scope_attempts
 *  - burst_pattern
 *  - stale_reactivation
 *  - new_scope_usage
 *  - revoked_connection_attempt
 */
class AlertsClient
{
    public const ALERT_TYPE_VOLUME_SPIKE               = 'volume_spike';
    public const ALERT_TYPE_FAILED_SCOPE_ATTEMPTS      = 'failed_scope_attempts';
    public const ALERT_TYPE_BURST_PATTERN              = 'burst_pattern';
    public const ALERT_TYPE_STALE_REACTIVATION         = 'stale_reactivation';
    public const ALERT_TYPE_NEW_SCOPE_USAGE            = 'new_scope_usage';
    public const ALERT_TYPE_REVOKED_CONNECTION_ATTEMPT = 'revoked_connection_attempt';

    private array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    /**
     * Configure alert thresholds for an app or connection.
     * POST /api/v1/alerts
     *
     * @param string      $appId       Your AgentAdmit application ID
     * @param string      $alertType   One of the ALERT_TYPE_* constants
     * @param array       $options     Optional fields: connection_id, enabled,
     *                                 threshold_value, threshold_window_minutes,
     *                                 threshold_rate_per_minute, stale_days,
     *                                 kill_switch_enabled, kill_switch_threshold_value,
     *                                 kill_switch_threshold_window_minutes
     * @return array      { "ok": true, "config": {...} }
     * @throws AgentAdmitException
     */
    public function configureAlerts(string $appId, string $alertType, array $options = []): array
    {
        $body = array_merge(['app_id' => $appId, 'alert_type' => $alertType], $options);

        try {
            $response = Http::timeout(10)
                ->withHeaders($this->authHeaders())
                ->post($this->apiUrl('/api/v1/alerts'), $body);

            $this->checkStatus($response, 'configureAlerts');
            return $response->json();
        } catch (AgentAdmitException $e) {
            throw $e;
        } catch (\Exception $e) {
            Log::error('AgentAdmit configureAlerts failed: ' . $e->getMessage());
            throw new AgentAdmitException('configureAlerts failed: ' . $e->getMessage(), 502);
        }
    }

    /**
     * List alert events for an app.
     * GET /api/v1/alerts
     *
     * @param string      $appId        Your AgentAdmit application ID
     * @param string|null $connectionId Filter by connection (optional)
     * @param string|null $alertType    Filter by alert type (optional)
     * @param int         $limit        Max events to return (default 50)
     * @param int         $offset       Pagination offset
     * @return array      { "events": [...], "total": int, "limit": int, "offset": int }
     * @throws AgentAdmitException
     */
    public function listAlerts(
        string $appId,
        ?string $connectionId = null,
        ?string $alertType = null,
        int $limit = 50,
        int $offset = 0
    ): array {
        $query = ['app_id' => $appId, 'limit' => $limit, 'offset' => $offset];
        if ($connectionId !== null) {
            $query['connection_id'] = $connectionId;
        }
        if ($alertType !== null) {
            $query['alert_type'] = $alertType;
        }

        try {
            $response = Http::timeout(10)
                ->withHeaders($this->authHeaders())
                ->get($this->apiUrl('/api/v1/alerts'), $query);

            $this->checkStatus($response, 'listAlerts');
            return $response->json();
        } catch (AgentAdmitException $e) {
            throw $e;
        } catch (\Exception $e) {
            Log::error('AgentAdmit listAlerts failed: ' . $e->getMessage());
            throw new AgentAdmitException('listAlerts failed: ' . $e->getMessage(), 502);
        }
    }

    /**
     * Get the current alert configuration for an app.
     * GET /api/v1/alerts/config
     *
     * @param string      $appId        Your AgentAdmit application ID
     * @param string|null $connectionId Filter by connection (optional)
     * @return array      { "app_id", "app_level", "connection_overrides", "alert_types" }
     * @throws AgentAdmitException
     */
    public function getAlertConfig(string $appId, ?string $connectionId = null): array
    {
        $query = ['app_id' => $appId];
        if ($connectionId !== null) {
            $query['connection_id'] = $connectionId;
        }

        try {
            $response = Http::timeout(10)
                ->withHeaders($this->authHeaders())
                ->get($this->apiUrl('/api/v1/alerts/config'), $query);

            $this->checkStatus($response, 'getAlertConfig');
            return $response->json();
        } catch (AgentAdmitException $e) {
            throw $e;
        } catch (\Exception $e) {
            Log::error('AgentAdmit getAlertConfig failed: ' . $e->getMessage());
            throw new AgentAdmitException('getAlertConfig failed: ' . $e->getMessage(), 502);
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private function authHeaders(): array
    {
        return [
            'Authorization' => 'Bearer ' . ($this->config['api_key'] ?? ''),
            'X-App-Id'      => $this->config['app_id'] ?? '',
        ];
    }

    private function apiUrl(string $path): string
    {
        $base = rtrim($this->config['api_url'] ?? 'https://api.agentadmit.com', '/');
        return $base . $path;
    }

    private function checkStatus($response, string $operation): void
    {
        if ($response->failed()) {
            $status = $response->status();
            Log::error("AgentAdmit {$operation} failed with status {$status}: " . $response->body());
            throw new AgentAdmitException("{$operation} failed with HTTP {$status}", $status);
        }
    }
}
