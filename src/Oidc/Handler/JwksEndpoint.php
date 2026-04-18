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

namespace Horde\Oauth\Oidc\Handler;

use Horde\Jwt\Key\Jwk;
use Horde\Jwt\Key\PublicKey;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class JwksEndpoint implements RequestHandlerInterface
{
    public function __construct(
        private readonly PublicKey $publicKey,
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly StreamFactoryInterface $streamFactory,
        private readonly string $keyId = 'default',
        private readonly string $algorithm = 'RS256',
    ) {}

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $jwk = Jwk::fromPublicKey($this->publicKey);
        $jwk['kid'] = $this->keyId;
        $jwk['alg'] = $this->algorithm;

        $json = json_encode(['keys' => [$jwk]], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $body = $this->streamFactory->createStream($json);

        return $this->responseFactory->createResponse(200)
            ->withHeader('Content-Type', 'application/json;charset=UTF-8')
            ->withBody($body);
    }
}
