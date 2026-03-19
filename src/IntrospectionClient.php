<?php

namespace AgentAdmit;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

/**
 * Mandatory introspection client — validates tokens via AgentAdmit hosted service.
 * No local JWT decode. Every verification call goes through AgentAdmit.
 */
class IntrospectionClient
{
    private array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    /**
     * Validate an ag_at_ token via introspection.
     *
     * @param string $token The full token including ag_at_ prefix
     * @return IntrospectionResult
     * @throws AgentAdmitException
     */
    public function verify(string $token): IntrospectionResult
    {
        $prefix = $this->config['token_prefix_access'] ?? 'ag_at_';

        if (!str_starts_with($token, $prefix)) {
            throw new AgentAdmitException('Not an AgentAdmit access token', 401);
        }

        try {
            $response = Http::timeout(5)
                ->withHeaders([
                    'Authorization' => 'Bearer ' . $token,
                    'X-App-Id' => $this->config['app_id'] ?? '',
                    'X-Api-Key' => $this->config['api_key'] ?? '',
                ])
                ->post($this->config['verify_url'] ?? 'https://api.agentadmit.com/v1/verify');

            if ($response->status() === 401) {
                $data = $response->json();
                throw new AgentAdmitException(
                    $data['error_description'] ?? 'Token validation failed',
                    401
                );
            }

            if ($response->status() !== 200) {
                throw new AgentAdmitException(
                    'Verification service returned ' . $response->status(),
                    502
                );
            }

            $data = $response->json();

            if (empty($data['user_id'])) {
                throw new AgentAdmitException('Introspection returned no user', 401);
            }

            return new IntrospectionResult(
                userId: $data['user_id'],
                connectionId: $data['connection_id'] ?? null,
                scopes: $data['scopes'] ?? [],
                agentLabel: $data['agent_label'] ?? 'Unknown Agent',
            );

        } catch (AgentAdmitException $e) {
            throw $e;
        } catch (\Exception $e) {
            Log::error('AgentAdmit introspection failed: ' . $e->getMessage());
            throw new AgentAdmitException('Introspection failed: ' . $e->getMessage(), 502);
        }
    }
}
