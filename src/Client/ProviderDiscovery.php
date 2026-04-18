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

namespace Horde\Oauth\Client;

use Horde\Oauth\Exception\OAuthException;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;

final class ProviderDiscovery
{
    public function __construct(
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
    ) {}

    public function discover(string $issuerUrl): ProviderConfig
    {
        $issuerUrl = rtrim($issuerUrl, '/');

        $urls = [
            $issuerUrl . '/.well-known/openid-configuration',
            $issuerUrl . '/.well-known/oauth-authorization-server',
        ];

        foreach ($urls as $url) {
            $request = $this->requestFactory->createRequest('GET', $url)
                ->withHeader('Accept', 'application/json');

            $response = $this->httpClient->sendRequest($request);

            if ($response->getStatusCode() === 200) {
                $data = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);
                if (!is_array($data)) {
                    throw new OAuthException('invalid_request', 'Discovery document is not a JSON object');
                }
                return ProviderConfig::fromArray($data);
            }
        }

        throw new OAuthException('invalid_request', "Failed to discover provider at {$issuerUrl}");
    }
}
