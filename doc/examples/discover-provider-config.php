#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * Discover OAuth2/OIDC provider configuration from well-known endpoints.
 *
 * Fetches the OpenID Connect discovery document from a real provider
 * and prints the key endpoints and capabilities.
 *
 * Usage:
 *   php doc/examples/discover-provider-config.php [issuer-url]
 *
 * Examples:
 *   php doc/examples/discover-provider-config.php
 *   php doc/examples/discover-provider-config.php https://accounts.google.com
 *   php doc/examples/discover-provider-config.php https://login.microsoftonline.com/common/v2.0
 *   php doc/examples/discover-provider-config.php https://github.com
 *
 * Requires: composer install (horde/http must be available)
 */

require_once __DIR__ . '/../../vendor/autoload.php';

use Horde\Http\Client\Curl;
use Horde\Http\Client\Options;
use Horde\Http\RequestFactory;
use Horde\Http\ResponseFactory;
use Horde\Http\StreamFactory;
use Horde\Oauth\Client\ProviderDiscovery;

$issuer = $argv[1] ?? 'https://accounts.google.com';

$discovery = new ProviderDiscovery(
    new Curl(new ResponseFactory(), new StreamFactory(), new Options()),
    new RequestFactory(),
);

echo "Discovering: {$issuer}\n";
echo str_repeat('-', 60) . "\n\n";

try {
    $config = $discovery->discover($issuer);
} catch (\Throwable $e) {
    fwrite(STDERR, "Discovery failed: {$e->getMessage()}\n");
    exit(1);
}

echo "Issuer:                 {$config->issuer}\n";
echo "Authorization endpoint: {$config->authorizationEndpoint}\n";
echo "Token endpoint:         {$config->tokenEndpoint}\n";
echo "Userinfo endpoint:      " . ($config->userinfoEndpoint ?? '(not advertised)') . "\n";
echo "JWKS URI:               " . ($config->jwksUri ?? '(not advertised)') . "\n";
echo "Revocation endpoint:    " . ($config->revocationEndpoint ?? '(not advertised)') . "\n";
echo "Introspection endpoint: " . ($config->introspectionEndpoint ?? '(not advertised)') . "\n";
echo "\n";

echo "Scopes supported:\n";
if ($config->scopesSupported !== []) {
    foreach ($config->scopesSupported as $scope) {
        echo "  - {$scope}\n";
    }
} else {
    echo "  (not advertised)\n";
}
echo "\n";

echo "Response types supported:\n";
foreach ($config->responseTypesSupported as $type) {
    echo "  - {$type}\n";
}
echo "\n";

echo "Grant types supported:\n";
if ($config->grantTypesSupported !== []) {
    foreach ($config->grantTypesSupported as $grant) {
        echo "  - {$grant}\n";
    }
} else {
    echo "  (not advertised)\n";
}
echo "\n";

echo "Token endpoint auth methods:\n";
foreach ($config->tokenEndpointAuthMethodsSupported as $method) {
    echo "  - {$method}\n";
}
echo "\n";

echo "ID token signing algorithms:\n";
if ($config->idTokenSigningAlgValuesSupported !== []) {
    foreach ($config->idTokenSigningAlgValuesSupported as $alg) {
        echo "  - {$alg}\n";
    }
} else {
    echo "  (not advertised)\n";
}
