<?php

declare(strict_types=1);

/**
 * Copyright 2008-2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (BSD). If you
 * did not receive this file, see http://www.horde.org/licenses/bsd.
 */

namespace Horde\OAuth\V10a\Request;

use Horde\OAuth\V10a\Signature\SignatureMethod;
use Horde\OAuth\V10a\Util\Rfc3986;

final class SignedRequest
{
    /** @var array<string, string|string[]> */
    private array $params;
    private string $url;
    private string $method;

    /**
     * @param array<string, string|string[]> $params All OAuth and extra parameters (nonce, timestamp, consumer_key already set by caller).
     */
    public function __construct(
        string $url,
        array $params,
        string $method = 'POST',
    ) {
        $this->url = $url;
        $this->params = $params;
        $this->method = $method;
    }

    public function sign(SignatureMethod $signatureMethod, string $consumerSecret, string $tokenSecret): void
    {
        $this->params['oauth_signature_method'] = $signatureMethod->getName();
        $baseString = $this->getBaseString();
        $this->params['oauth_signature'] = $signatureMethod->sign($baseString, $consumerSecret, $tokenSecret);
    }

    public function getBaseString(): string
    {
        $parts = [
            strtoupper($this->method),
            $this->normalizeUrl(),
            $this->getSignableParams(),
        ];

        return implode('&', array_map([Rfc3986::class, 'encode'], $parts));
    }

    public function toFormBody(): string
    {
        $parts = [];
        foreach ($this->params as $key => $value) {
            if (is_array($value)) {
                foreach ($value as $v) {
                    $parts[] = Rfc3986::encode($key) . '=' . Rfc3986::encode($v);
                }
            } else {
                $parts[] = Rfc3986::encode($key) . '=' . Rfc3986::encode($value);
            }
        }

        return implode('&', $parts);
    }

    public function toAuthorizationHeader(string $realm = ''): string
    {
        return AuthorizationHeader::build($this->params, $realm);
    }

    public function toQueryString(): string
    {
        return $this->normalizeUrl() . '?' . $this->toFormBody();
    }

    private function getSignableParams(): string
    {
        $params = $this->params;
        unset($params['oauth_signature']);

        $encoded = [];
        foreach ($params as $key => $value) {
            $encKey = Rfc3986::encode($key);
            if (is_array($value)) {
                foreach ($value as $v) {
                    $encoded[] = [$encKey, Rfc3986::encode($v)];
                }
            } else {
                $encoded[] = [$encKey, Rfc3986::encode($value)];
            }
        }

        usort($encoded, function (array $a, array $b): int {
            return ($a[0] <=> $b[0]) ?: ($a[1] <=> $b[1]);
        });

        $pairs = [];
        foreach ($encoded as [$key, $value]) {
            $pairs[] = $key . '=' . $value;
        }

        return implode('&', $pairs);
    }

    private function normalizeUrl(): string
    {
        $parts = parse_url($this->url);
        $scheme = strtolower($parts['scheme'] ?? 'https');
        $host = strtolower($parts['host'] ?? '');
        $port = $parts['port'] ?? null;
        $path = $parts['path'] ?? '';

        if ($port !== null
            && !(($scheme === 'https' && $port === 443) || ($scheme === 'http' && $port === 80))
        ) {
            $host .= ':' . $port;
        }

        return $scheme . '://' . $host . $path;
    }
}
