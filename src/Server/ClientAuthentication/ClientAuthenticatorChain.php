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

namespace Horde\OAuth\Server\ClientAuthentication;

use Horde\OAuth\Exception\InvalidClientException;
use Horde\OAuth\Server\Entity\Client;
use Horde\OAuth\Server\Repository\ClientRepository;
use Psr\Http\Message\ServerRequestInterface;

final class ClientAuthenticatorChain
{
    /** @var ClientAuthenticator[] */
    private readonly array $authenticators;

    public function __construct(
        private readonly ClientRepository $clientRepository,
        ClientAuthenticator ...$authenticators,
    ) {
        $this->authenticators = $authenticators;
    }

    public function authenticateClient(ServerRequestInterface $request): Client
    {
        foreach ($this->authenticators as $authenticator) {
            $result = $authenticator->authenticate($request);
            if ($result === null) {
                continue;
            }

            [$clientId, $clientSecret] = $result;

            $client = $this->clientRepository->findById($clientId);
            if ($client === null) {
                throw new InvalidClientException('Unknown client');
            }

            if ($client->tokenEndpointAuthMethod !== $authenticator->getMethod()) {
                throw new InvalidClientException('Invalid authentication method for this client');
            }

            if ($client->isConfidential()) {
                if ($clientSecret === null || !$client->verifySecret($clientSecret)) {
                    throw new InvalidClientException('Invalid client credentials');
                }
            }

            return $client;
        }

        throw new InvalidClientException('No client authentication provided');
    }

    public function authenticateClientOrPublic(ServerRequestInterface $request): Client
    {
        foreach ($this->authenticators as $authenticator) {
            $result = $authenticator->authenticate($request);
            if ($result === null) {
                continue;
            }

            [$clientId, $clientSecret] = $result;

            $client = $this->clientRepository->findById($clientId);
            if ($client === null) {
                throw new InvalidClientException('Unknown client');
            }

            if ($client->isConfidential()) {
                if ($clientSecret === null || !$client->verifySecret($clientSecret)) {
                    throw new InvalidClientException('Invalid client credentials');
                }
            }

            return $client;
        }

        $body = $request->getParsedBody();
        $clientId = is_array($body) ? ($body['client_id'] ?? null) : null;
        if (!is_string($clientId) || $clientId === '') {
            throw new InvalidClientException('No client identification provided');
        }

        $client = $this->clientRepository->findById($clientId);
        if ($client === null) {
            throw new InvalidClientException('Unknown client');
        }

        if (!$client->isPublic()) {
            throw new InvalidClientException('Confidential client must authenticate');
        }

        return $client;
    }
}
