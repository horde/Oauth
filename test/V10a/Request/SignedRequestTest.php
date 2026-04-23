<?php

declare(strict_types=1);

/**
 * Copyright 2026 The Horde Project (http://www.horde.org/)
 *
 * See the enclosed file LICENSE for license information (BSD). If you
 * did not receive this file, see http://www.horde.org/licenses/bsd.
 */

namespace Horde\OAuth\Test\V10a\Request;

use Horde\OAuth\V10a\Request\SignedRequest;
use Horde\OAuth\V10a\Signature\HmacSha1;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(SignedRequest::class)]
final class SignedRequestTest extends TestCase
{
    public function testGetBaseStringFormat(): void
    {
        $req = new SignedRequest('https://example.com/resource', [
            'oauth_consumer_key' => 'key',
            'oauth_nonce' => 'nonce',
            'oauth_timestamp' => '1234567890',
            'oauth_version' => '1.0',
        ], 'GET');

        $base = $req->getBaseString();
        $parts = explode('&', $base);

        self::assertCount(3, $parts);
        self::assertSame('GET', $parts[0]);
        self::assertSame('https%3A%2F%2Fexample.com%2Fresource', $parts[1]);
    }

    public function testGetBaseStringMethodUppercased(): void
    {
        $req = new SignedRequest('https://example.com/', [
            'oauth_consumer_key' => 'key',
        ], 'post');

        $base = $req->getBaseString();
        self::assertStringStartsWith('POST&', $base);
    }

    public function testGetBaseStringNormalizesUrl(): void
    {
        $req = new SignedRequest('HTTPS://EXAMPLE.COM:443/path', [
            'oauth_consumer_key' => 'key',
        ]);

        $base = $req->getBaseString();
        self::assertStringContainsString('https%3A%2F%2Fexample.com%2Fpath', $base);
    }

    public function testGetBaseStringKeepsNonDefaultPort(): void
    {
        $req = new SignedRequest('https://example.com:8443/path', [
            'oauth_consumer_key' => 'key',
        ]);

        $base = $req->getBaseString();
        self::assertStringContainsString('https%3A%2F%2Fexample.com%3A8443%2Fpath', $base);
    }

    public function testGetBaseStringSortsParams(): void
    {
        $req = new SignedRequest('https://example.com/', [
            'z_param' => 'last',
            'a_param' => 'first',
            'oauth_consumer_key' => 'key',
        ]);

        $base = $req->getBaseString();
        $paramsPart = urldecode(explode('&', $base, 3)[2]);
        self::assertStringStartsWith('a_param', $paramsPart);
    }

    public function testGetBaseStringExcludesSignature(): void
    {
        $req = new SignedRequest('https://example.com/', [
            'oauth_consumer_key' => 'key',
            'oauth_signature' => 'should-be-excluded',
            'oauth_nonce' => 'nonce',
        ]);

        $base = $req->getBaseString();
        self::assertStringNotContainsString('should-be-excluded', $base);
        self::assertStringNotContainsString('oauth_signature', urldecode($base));
    }

    public function testSignAddsSignatureToParams(): void
    {
        $req = new SignedRequest('https://example.com/', [
            'oauth_consumer_key' => 'key',
            'oauth_nonce' => 'nonce',
            'oauth_timestamp' => '1234567890',
            'oauth_version' => '1.0',
        ]);

        $req->sign(new HmacSha1(), 'consumer-secret', 'token-secret');

        $body = $req->toFormBody();
        self::assertStringContainsString('oauth_signature_method=HMAC-SHA1', $body);
        self::assertStringContainsString('oauth_signature=', $body);
    }

    public function testToFormBodyEncodesAllParams(): void
    {
        $req = new SignedRequest('https://example.com/', [
            'oauth_consumer_key' => 'key with spaces',
            'oauth_nonce' => 'nonce',
        ]);

        $body = $req->toFormBody();
        self::assertStringContainsString('oauth_consumer_key=key%20with%20spaces', $body);
        self::assertStringContainsString('oauth_nonce=nonce', $body);
    }

    public function testToAuthorizationHeaderDelegatesToBuilder(): void
    {
        $req = new SignedRequest('https://example.com/', [
            'oauth_consumer_key' => 'key',
            'oauth_nonce' => 'nonce',
        ]);

        $header = $req->toAuthorizationHeader();
        self::assertStringStartsWith('OAuth ', $header);
        self::assertStringContainsString('oauth_consumer_key="key"', $header);
    }

    public function testToQueryString(): void
    {
        $req = new SignedRequest('https://example.com/path', [
            'oauth_consumer_key' => 'key',
        ], 'GET');

        $qs = $req->toQueryString();
        self::assertStringStartsWith('https://example.com/path?', $qs);
        self::assertStringContainsString('oauth_consumer_key=key', $qs);
    }

    public function testArrayValueParams(): void
    {
        $req = new SignedRequest('https://example.com/', [
            'multi' => ['b', 'a'],
            'oauth_consumer_key' => 'key',
        ]);

        $body = $req->toFormBody();
        self::assertStringContainsString('multi=b', $body);
        self::assertStringContainsString('multi=a', $body);
    }

    /**
     * RFC 5849 Section 3.4.1.1 example adapted.
     */
    public function testBaseStringMatchesRfcExample(): void
    {
        $req = new SignedRequest('http://example.com/request', [
            'oauth_consumer_key' => '0685bd9184jfhq22',
            'oauth_token' => 'ad180jjd733klru7',
            'oauth_signature_method' => 'HMAC-SHA1',
            'oauth_timestamp' => '137131200',
            'oauth_nonce' => '7d8f3e4a',
            'oauth_version' => '1.0',
            'b5' => '=%3D',
            'a3' => 'a',
            'c@' => '',
            'a2' => 'r b',
        ], 'POST');

        $base = $req->getBaseString();
        $parts = explode('&', $base, 3);

        self::assertSame('POST', $parts[0]);
        self::assertSame('http%3A%2F%2Fexample.com%2Frequest', $parts[1]);
    }
}
