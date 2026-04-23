<?php

declare(strict_types=1);

/**
 * Copyright 2008-2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (BSD). If you
 * did not receive this file, see http://www.horde.org/licenses/bsd.
 */

namespace Horde\OAuth\V10a\Client;

use Horde\OAuth\Exception\OAuthException;
use Horde\OAuth\V10a\Util\Rfc3986;

final class Token
{
    public function __construct(
        public readonly string $key,
        public readonly string $secret,
    ) {}

    public static function fromResponseBody(string $body): self
    {
        parse_str($body, $parts);

        if (!isset($parts['oauth_token'], $parts['oauth_token_secret'])) {
            throw new OAuthException(
                'invalid_response',
                'Response does not contain oauth_token and oauth_token_secret',
            );
        }

        return new self((string) $parts['oauth_token'], (string) $parts['oauth_token_secret']);
    }

    public function toQueryString(): string
    {
        return 'oauth_token=' . Rfc3986::encode($this->key)
            . '&oauth_token_secret=' . Rfc3986::encode($this->secret);
    }
}
