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

namespace Horde\OAuth\Server\Token;

use Horde\Jwt\Signer\SignerInterface;
use Horde\Jwt\TokenEncoder;
use Horde\OAuth\Server\Entity\AccessToken;
use Horde\OAuth\Server\Entity\Client;
use Horde\OAuth\Server\Entity\Scope;
use Horde\OAuth\Server\Repository\AccessTokenRepository;
use DateTimeImmutable;

final class AccessTokenIssuer
{
    public function __construct(
        private readonly TokenEncoder $encoder,
        private readonly SignerInterface $signer,
        private readonly AccessTokenRepository $repository,
        private readonly string $issuer,
        private readonly int $ttl = 3600,
    ) {}

    /**
     * @param Scope[] $scopes
     * @return array<string, mixed>
     */
    public function issue(Client $client, ?string $identityId, array $scopes): array
    {
        $jti = bin2hex(random_bytes(16));
        $scopeString = Scope::toSpaceSeparated($scopes);
        $expiresAt = new DateTimeImmutable("+{$this->ttl} seconds");

        $claims = [
            'iss' => $this->issuer,
            'sub' => $identityId,
            'aud' => $client->clientId,
            'jti' => $jti,
            'scope' => $scopeString,
            'client_id' => $client->clientId,
        ];

        $token = $this->encoder->encode($claims, $this->signer, $this->ttl);

        $entity = new AccessToken(
            $jti,
            $client->clientId,
            $identityId,
            $scopeString,
            $expiresAt,
        );
        $this->repository->persist($entity);

        $result = [
            'access_token' => $token->toString(),
            'token_type' => 'Bearer',
            'expires_in' => $this->ttl,
        ];

        if ($scopeString !== '') {
            $result['scope'] = $scopeString;
        }

        $result['_jti'] = $jti;

        return $result;
    }
}
