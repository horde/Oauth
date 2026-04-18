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

use Horde\Oauth\Server\ServerMetadata;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class DiscoveryEndpoint implements RequestHandlerInterface
{
    public function __construct(
        private readonly ServerMetadata $metadata,
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly StreamFactoryInterface $streamFactory,
    ) {}

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $body = $this->streamFactory->createStream($this->metadata->toJson());

        return $this->responseFactory->createResponse(200)
            ->withHeader('Content-Type', 'application/json;charset=UTF-8')
            ->withBody($body);
    }
}
