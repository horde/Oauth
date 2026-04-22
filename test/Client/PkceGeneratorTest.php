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

namespace Horde\OAuth\Test\Client;

use Horde\Jwt\Base64Url;
use Horde\OAuth\Client\PkceGenerator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

#[CoversClass(PkceGenerator::class)]
final class PkceGeneratorTest extends TestCase
{
    public function testGenerateVerifierDefaultLength(): void
    {
        $verifier = PkceGenerator::generateVerifier();
        self::assertSame(128, strlen($verifier));
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $verifier);
    }

    public function testGenerateVerifierCustomLength(): void
    {
        $verifier = PkceGenerator::generateVerifier(64);
        self::assertSame(64, strlen($verifier));
    }

    public function testGenerateVerifierMinimum43(): void
    {
        $verifier = PkceGenerator::generateVerifier(10);
        self::assertSame(43, strlen($verifier));
    }

    public function testComputeChallengeS256(): void
    {
        $verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
        $challenge = PkceGenerator::computeChallenge($verifier, 'S256');
        $expected = Base64Url::encode(hash('sha256', $verifier, true));
        self::assertSame($expected, $challenge);
    }

    public function testComputeChallengePlain(): void
    {
        $verifier = 'my-plain-verifier';
        self::assertSame($verifier, PkceGenerator::computeChallenge($verifier, 'plain'));
    }

    public function testVerifierAndChallengeRoundTrip(): void
    {
        $verifier = PkceGenerator::generateVerifier();
        $challenge = PkceGenerator::computeChallenge($verifier);
        $computed = Base64Url::encode(hash('sha256', $verifier, true));
        self::assertSame($computed, $challenge);
    }
}
