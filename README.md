# Horde\OAuth

OAuth 1.0a consumer. OAuth 2.0 authorization server and client.
OpenID Connect provider library for the [Horde Project](https://www.horde.org/) but with virtually no framework ties.

## Features

### OAuth 1.0a Client (`Horde\OAuth\V10a\Client`)

- **3-legged authorization flow**: Request token, user authorization, access
  token exchange
- **PSR-18 HTTP client**: Inject any compliant HTTP client (horde/http, Guzzle, Symfony
  HttpClient etc.)
- **Signature methods**: HMAC-SHA1, HMAC-SHA256, RSA-SHA1, PLAINTEXT
- **Authenticated HTTP client**: PSR-18 decorator that signs every outgoing
  request with OAuth 1.0a credentials
- Immutable value objects for consumer credentials, tokens and provider
  endpoints

### OAuth 2.0 Client (`Horde\OAuth\Client`)

- Authorization code flow with PKCE support
- Token refresh with automatic retry
- OpenID Connect provider discovery
- Incremental consent
- Authenticated HTTP client with transparent token refresh

### OAuth 2.0 Server (`Horde\OAuth\Server`)

- Authorization code, client credentials and refresh token grants
- PKCE verification (S256, plain)
- Token introspection and revocation endpoints
- Bearer token middleware (PSR-15)
- Repository pattern with in-memory reference implementation

### OpenID Connect (`Horde\OAuth\Oidc`)

- ID token building with standard claims
- Discovery and JWKS endpoints
- Userinfo endpoint
- Scope-to-claims mapping

## Installation

```bash
composer require horde/oauth
```

## Quick Example: OAuth 1.0a Client

```php
use Horde\OAuth\V10a\Client\ConsumerCredentials;
use Horde\OAuth\V10a\Client\OAuth1Client;
use Horde\OAuth\V10a\Client\ProviderEndpoints;
use Horde\OAuth\V10a\Signature\HmacSha1;

$client = new OAuth1Client(
    new ConsumerCredentials('your-consumer-key', 'your-consumer-secret'),
    new ProviderEndpoints(
        'https://provider.example/request_token',
        'https://provider.example/authorize',
        'https://provider.example/access_token',
    ),
    new HmacSha1(),
    $psrHttpClient,       // any PSR-18 ClientInterface
    $requestFactory,      // any PSR-17 RequestFactoryInterface
    $streamFactory,       // any PSR-17 StreamFactoryInterface
);

// Step 1: Obtain a request token
$requestToken = $client->getRequestToken('https://yourapp.example/callback');

// Step 2: Redirect user to authorization URL
$authUrl = $client->getAuthorizationUrl($requestToken, 'https://yourapp.example/callback');

// Step 3: Exchange for access token (after user returns with verifier)
$accessToken = $client->getAccessToken($requestToken, $oauthVerifier);
```

### Making authenticated API calls

```php
use Horde\OAuth\V10a\Client\AuthenticatedHttpClient;

$authenticatedClient = new AuthenticatedHttpClient(
    $psrHttpClient,
    $consumerCredentials,
    $accessToken,
    new HmacSha1(),
);

// Every request is automatically signed with OAuth 1.0a Authorization header
$response = $authenticatedClient->sendRequest($request);
```

## Quick Example: OAuth 2.0 Client

```php
use Horde\OAuth\Client\OAuth2Client;
use Horde\OAuth\Client\ProviderConfig;

$provider = ProviderConfig::fromArray([
    'authorization_endpoint' => 'https://provider.example/authorize',
    'token_endpoint'         => 'https://provider.example/token',
]);

$client = new OAuth2Client(
    $provider,
    'your-client-id',
    'your-client-secret',
    'https://yourapp.example/callback',
    $psrHttpClient,
    $requestFactory,
    $streamFactory,
);

$authUrl  = $client->getAuthorizationUrl(['openid', 'profile'], $state);
$tokenSet = $client->exchangeCode($authorizationCode);
```

## Architecture

This library depends only on PSR interfaces (`psr/http-client`,
`psr/http-message`, `psr/http-factory`, `psr/http-server-handler`,
`psr/http-server-middleware`) and `horde/jwt` for JWT token handling. It does
not depend on any concrete HTTP implementation, allowing consumers to bring
their own PSR-18 client. But they really shouldn't. The horde/http library is all they need.

See [doc/ARCHITECTURE.md](doc/ARCHITECTURE.md) for design principles and
rationale and [doc/UPGRADING.md](doc/UPGRADING.md) for migration guidance
from 2.x.

## Relevant RFCs

- [RFC 5849](https://datatracker.ietf.org/doc/html/rfc5849) - OAuth 1.0a
- [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) - OAuth 2.0
- [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) - PKCE
- [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662) - Token Introspection
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)

## Requirements

- PHP 8.1 or later
- `ext-hash`
- `ext-json`
- `ext-openssl`

## License

BSD-2-Clause. See [LICENSE](LICENSE) for details.
