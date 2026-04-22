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

namespace Horde\OAuth\Oidc;

use Horde\Jwt\Base64Url;
use Horde\Jwt\Signer\SignerInterface;
use Horde\Jwt\TokenEncoder;

final class IdTokenBuilder
{
    public function __construct(
        private readonly TokenEncoder $encoder,
        private readonly SignerInterface $signer,
        private readonly ClaimsMapper $claimsMapper,
        private readonly ScopeClaimsMapping $scopeMapping,
        private readonly string $issuer,
        private readonly int $ttl = 3600,
    ) {}

    /**
     * @param string[] $scopes
     */
    public function build(
        string $identityId,
        string $clientId,
        array $scopes,
        ?string $nonce = null,
        ?string $accessTokenHash = null,
        ?string $codeHash = null,
    ): string {
        $claimNames = $this->scopeMapping->getClaimsForScopes($scopes);
        $userClaims = $this->claimsMapper->getClaims($identityId, $claimNames);

        $claims = [
            'iss' => $this->issuer,
            'sub' => $identityId,
            'aud' => $clientId,
            'auth_time' => time(),
        ];

        if ($nonce !== null) {
            $claims['nonce'] = $nonce;
        }

        if ($accessTokenHash !== null) {
            $claims['at_hash'] = $accessTokenHash;
        }

        if ($codeHash !== null) {
            $claims['c_hash'] = $codeHash;
        }

        $claims = array_merge($claims, $userClaims);

        $token = $this->encoder->encode($claims, $this->signer, $this->ttl);

        return $token->toString();
    }

    public static function computeAtHash(string $accessToken, string $algorithm = 'RS256'): string
    {
        $hashAlg = match ($algorithm) {
            'RS256', 'ES256', 'HS256' => 'sha256',
            default => 'sha256',
        };

        $hash = hash($hashAlg, $accessToken, true);
        $leftHalf = substr($hash, 0, (int) (strlen($hash) / 2));

        return Base64Url::encode($leftHalf);
    }
}
