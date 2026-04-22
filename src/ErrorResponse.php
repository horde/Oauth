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

namespace Horde\Oauth;

use Horde\OAuth\Exception\OAuthException;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;

final class ErrorResponse
{
    /**
     * @return array<string, string>
     */
    public static function toArray(OAuthException $e): array
    {
        $data = ['error' => $e->getError()];

        if ($e->getErrorDescription() !== '') {
            $data['error_description'] = $e->getErrorDescription();
        }

        if ($e->getErrorUri() !== '') {
            $data['error_uri'] = $e->getErrorUri();
        }

        return $data;
    }

    public static function toJson(OAuthException $e): string
    {
        return json_encode(self::toArray($e), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }

    public static function toResponse(
        OAuthException $e,
        ResponseFactoryInterface $responseFactory,
        StreamFactoryInterface $streamFactory,
    ): ResponseInterface {
        $body = $streamFactory->createStream(self::toJson($e));

        return $responseFactory->createResponse($e->getHttpStatusCode())
            ->withHeader('Content-Type', 'application/json;charset=UTF-8')
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('Pragma', 'no-cache')
            ->withBody($body);
    }
}
