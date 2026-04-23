<?php

declare(strict_types=1);

/**
 * Copyright 2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (BSD). If you
 * did not receive this file, see http://www.horde.org/licenses/bsd.
 */

namespace Horde\OAuth\V10a\Client;

use Horde\OAuth\V10a\Request\SignedRequest;
use Horde\OAuth\V10a\Signature\SignatureMethod;
use Horde\OAuth\V10a\Util\NonceGenerator;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

final class AuthenticatedHttpClient implements ClientInterface
{
    public function __construct(
        private readonly ClientInterface $inner,
        private readonly ConsumerCredentials $consumer,
        private readonly Token $accessToken,
        private readonly SignatureMethod $signatureMethod,
    ) {}

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $method = $request->getMethod();
        $url = (string) $request->getUri();

        $params = [
            'oauth_consumer_key' => $this->consumer->key,
            'oauth_token' => $this->accessToken->key,
            'oauth_version' => '1.0',
            'oauth_nonce' => NonceGenerator::generate(),
            'oauth_timestamp' => (string) time(),
        ];

        $signed = new SignedRequest($url, $params, $method);
        $signed->sign($this->signatureMethod, $this->consumer->secret, $this->accessToken->secret);

        $request = $request->withHeader('Authorization', $signed->toAuthorizationHeader());

        return $this->inner->sendRequest($request);
    }
}
