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

namespace Horde\OAuth\Test\Server\Pkce;

use Horde\Jwt\Base64Url;
use Horde\OAuth\Exception\InvalidRequestException;
use Horde\OAuth\Server\Pkce\PkceVerifier;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(PkceVerifier::class)]
final class PkceVerifierTest extends TestCase
{
    public function testS256Succeeds(): void
    {
        $verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
        $challenge = Base64Url::encode(hash('sha256', $verifier, true));
        self::assertTrue(PkceVerifier::verify($verifier, $challenge, 'S256'));
    }

    public function testS256FailsWithWrongVerifier(): void
    {
        $challenge = Base64Url::encode(hash('sha256', 'correct-verifier', true));
        self::assertFalse(PkceVerifier::verify('wrong-verifier', $challenge, 'S256'));
    }

    public function testPlainSucceeds(): void
    {
        $verifier = 'my-plain-verifier';
        self::assertTrue(PkceVerifier::verify($verifier, $verifier, 'plain'));
    }

    public function testPlainFails(): void
    {
        self::assertFalse(PkceVerifier::verify('a', 'b', 'plain'));
    }

    public function testUnsupportedMethodThrows(): void
    {
        $this->expectException(InvalidRequestException::class);
        PkceVerifier::verify('a', 'b', 'unsupported');
    }

    public function testIsValidMethod(): void
    {
        self::assertTrue(PkceVerifier::isValidMethod('S256'));
        self::assertTrue(PkceVerifier::isValidMethod('plain'));
        self::assertFalse(PkceVerifier::isValidMethod('RS256'));
    }
}
