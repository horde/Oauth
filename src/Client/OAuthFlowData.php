<?php

declare(strict_types=1);

/**
 * Copyright 2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (BSD). If you
 * did not receive this file, see http://www.horde.org/licenses/bsd.
 *
 * @author   Ralf Lang <ralf.lang@ralf-lang.de>
 */

namespace Horde\OAuth\Client;

final class OAuthFlowData
{
    public function __construct(
        public readonly string $state,
        public readonly string $providerId,
        public readonly string $pkceVerifier,
        public readonly string $flowType,
        public readonly int $createdAt,
        public readonly string $redirectUrl = '',
        public readonly string $requestingApp = '',
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'state' => $this->state,
            'provider_id' => $this->providerId,
            'pkce_verifier' => $this->pkceVerifier,
            'flow_type' => $this->flowType,
            'created_at' => $this->createdAt,
            'redirect_url' => $this->redirectUrl,
            'requesting_app' => $this->requestingApp,
        ];
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            state: (string) ($data['state'] ?? ''),
            providerId: (string) ($data['provider_id'] ?? ''),
            pkceVerifier: (string) ($data['pkce_verifier'] ?? ''),
            flowType: (string) ($data['flow_type'] ?? ''),
            createdAt: (int) ($data['created_at'] ?? 0),
            redirectUrl: (string) ($data['redirect_url'] ?? ''),
            requestingApp: (string) ($data['requesting_app'] ?? ''),
        );
    }
}
