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

namespace Horde\OAuth\Server\Repository\InMemory;

use Horde\OAuth\Server\Entity\Client;
use Horde\OAuth\Server\Repository\ClientRepository;

final class InMemoryClientRepository implements ClientRepository
{
    /** @var array<string, Client> */
    private array $clients = [];

    public function __construct(Client ...$clients)
    {
        foreach ($clients as $client) {
            $this->clients[$client->clientId] = $client;
        }
    }

    public function findById(string $clientId): ?Client
    {
        return $this->clients[$clientId] ?? null;
    }

    public function validateClient(string $clientId, ?string $clientSecret, string $grantType): bool
    {
        $client = $this->findById($clientId);
        if ($client === null) {
            return false;
        }

        if (!$client->supportsGrantType($grantType)) {
            return false;
        }

        if ($client->isConfidential()) {
            if ($clientSecret === null) {
                return false;
            }
            return $client->verifySecret($clientSecret);
        }

        return true;
    }
}
