# Upgrading horde/oauth

## From 3.x (lib/ only) to 4.x

Version 4.0 adds a modern PSR-4 codebase under `src/` while keeping the
legacy PSR-0 classes in `lib/` for backward compatibility. Both autoload
roots are active simultaneously.

If you currently use `Horde_Oauth_Consumer` for OAuth 1.0a, you have two
upgrade paths: stay on OAuth 1.0a with the modernized client or migrate to
OAuth 2.0. The right choice depends on what the provider supports and what your application needs.

### Choosing between OAuth 1.0a and OAuth 2.0

| | Stay on OAuth 1.0a | Migrate to OAuth 2.0 |
|---|---|---|
| **When** | Provider only supports 1.0a or you need request-level signing (every API call is cryptographically signed) | Provider supports OAuth 2.0 (most modern APIs do) |
| **Target namespace** | `Horde\OAuth\V10a\Client` | `Horde\OAuth\Client` |
| **Effort** | Low - same flow, same concepts, new classes | Medium - different protocol, different token model |
| **Token model** | Key + secret pair, no expiry | Access token + optional refresh token, expiry, scopes |
| **Request signing** | Every request is signed (HMAC/RSA) | Bearer token in header (no per-request signing) |
| **PKCE** | Not applicable | Supported (recommended for public clients) |
| **Scopes** | Provider-specific, no standard | RFC 6749 scoped authorization |
| **Provider discovery** | Manual endpoint configuration | OpenID Connect discovery supported |
| **Token refresh** | Not part of the protocol - must re-authorize | Built-in refresh token flow |

**Rule of thumb:** If the provider offers OAuth 2.0 you better prefer it.
OAuth 1.0a request signing adds complexity that OAuth 2.0 avoids by relying on TLS for
transport security. Use the modernized 1.0a client only when the provider
requires it.

---

### Path A: Upgrade to modern OAuth 1.0a client

Use this path if you are staying on OAuth 1.0a. The modern client in
`Horde\OAuth\V10a\Client` provides the same 3-legged flow with:

- **PSR-18 HTTP**: Inject any compliant client instead of the hard-coded
  `Horde_Http_Client`
- **Typed, immutable value objects** instead of untyped arrays and public
  properties
- **HMAC-SHA256 support** alongside the existing HMAC-SHA1, RSA-SHA1 and
  PLAINTEXT methods
- **Cryptographically secure nonces** (`random_bytes`) instead of
  `md5(microtime())`

#### Class mapping

| Legacy (lib/) | Modern (src/) |
|---|---|
| `Horde_Oauth_Consumer` | `Horde\OAuth\V10a\Client\OAuth1Client` |
| `Horde_Oauth_Token` | `Horde\OAuth\V10a\Client\Token` |
| `Horde_Oauth_Request` | `Horde\OAuth\V10a\Request\SignedRequest` |
| `Horde_Oauth_SignatureMethod` | `Horde\OAuth\V10a\Signature\SignatureMethod` (interface) |
| `Horde_Oauth_SignatureMethod_HmacSha1` | `Horde\OAuth\V10a\Signature\HmacSha1` |
| `Horde_Oauth_SignatureMethod_RsaSha1` | `Horde\OAuth\V10a\Signature\RsaSha1` |
| `Horde_Oauth_SignatureMethod_Plaintext` | `Horde\OAuth\V10a\Signature\Plaintext` |
| `Horde_Oauth_Utils` | `Horde\OAuth\V10a\Util\Rfc3986` |
| `Horde_Oauth_Exception` | `Horde\OAuth\Exception\OAuthException` |
| *(none)* | `Horde\OAuth\V10a\Signature\HmacSha256` (new) |
| *(none)* | `Horde\OAuth\V10a\Client\AuthenticatedHttpClient` (new) |
| *(none)* | `Horde\OAuth\V10a\Client\ConsumerCredentials` (new) |
| *(none)* | `Horde\OAuth\V10a\Client\ProviderEndpoints` (new) |

#### Migration example

```php
// BEFORE (3.x)
$consumer = new Horde_Oauth_Consumer([
    'key'               => 'consumer-key',
    'secret'            => 'consumer-secret',
    'requestTokenUrl'   => 'https://provider.example/request_token',
    'authorizeTokenUrl' => 'https://provider.example/authorize',
    'accessTokenUrl'    => 'https://provider.example/access_token',
    'signatureMethod'   => new Horde_Oauth_SignatureMethod_HmacSha1(),
    'callbackUrl'       => 'https://app.example/callback',
]);
$requestToken = $consumer->getRequestToken();
$authUrl      = $consumer->getUserAuthorizationUrl($requestToken);
$accessToken  = $consumer->getAccessToken($requestToken, $params);

// AFTER (4.x - staying on OAuth 1.0a)
use Horde\OAuth\V10a\Client\ConsumerCredentials;
use Horde\OAuth\V10a\Client\OAuth1Client;
use Horde\OAuth\V10a\Client\ProviderEndpoints;
use Horde\OAuth\V10a\Signature\HmacSha1;

$client = new OAuth1Client(
    new ConsumerCredentials('consumer-key', 'consumer-secret'),
    new ProviderEndpoints(
        'https://provider.example/request_token',
        'https://provider.example/authorize',
        'https://provider.example/access_token',
    ),
    new HmacSha1(),
    $psrHttpClient,     // any PSR-18 ClientInterface
    $requestFactory,    // any PSR-17 RequestFactoryInterface
    $streamFactory,     // any PSR-17 StreamFactoryInterface
);
$callbackUrl  = 'https://app.example/callback';
$requestToken = $client->getRequestToken($callbackUrl);
$authUrl      = $client->getAuthorizationUrl($requestToken, $callbackUrl);
$accessToken  = $client->getAccessToken($requestToken, $oauthVerifier);
```

#### Key differences from 3.x

**No hardcoded HTTP client.** You must inject a PSR-18 `ClientInterface`
   and PSR-17 factories. Any implementation works (`horde/http`, Guzzle, Symfony HttpClient etc).

**Callback URL is a method parameter** and not a constructor config value. This matches how OAuth 1.0a actually works. The callback can differ per request.

**`getAccessToken()` requires the `oauth_verifier`** as an explicit parameter. The legacy API hides this inside `$params`.

**Tokens are immutable value objects** with `readonly` properties (`$key`, `$secret`) instead of mutable public properties.

**Signature methods implement an interface** instead of extending an abstract class. The `sign()` method receives primitive strings, not the full Request/Consumer/Token objects.

**New: `AuthenticatedHttpClient`** is a PSR-18 decorator that automatically signs every outgoing request. No equivalent existed in 2.x.

---

### Path B: Migrate from OAuth 1.0a to OAuth 2.0

Use this path when the provider supports OAuth 2.0. The protocol is fundamentally different, so this is not a drop-in class swap. It requires understanding the new flow which is different.

#### Conceptual mapping

| OAuth 1.0a concept | OAuth 2.0 equivalent | Notes |
|---|---|---|
| Consumer key + secret | Client ID + client secret | Registered at the provider |
| Request token | *(none)* | OAuth 2.0 has no temporary request token step |
| User authorization URL | Authorization URL | Similar redirect, but OAuth 2.0 returns a `code`, not a token |
| Access token exchange | Code exchange | `exchangeCode()` replaces `getAccessToken()` |
| Token key + secret | Access token (+ optional refresh token) | OAuth 2.0 tokens are opaque strings, not key/secret pairs |
| Per-request HMAC signing | Bearer token header | No cryptographic signing per request |
| *(none)* | Scopes | OAuth 2.0 has standardized scope-based authorization |
| *(none)* | Token refresh | OAuth 2.0 supports automatic token renewal |
| *(none)* | PKCE | Protects public clients against authorization code interception |

#### Flow comparison

**OAuth 1.0a (3-legged):**
1. App to Provider: obtain request token
2. App to User: redirect to authorization URL with request token
3. User to App: callback with `oauth_verifier`
4. App to Provider: exchange request token + verifier for access token

**OAuth 2.0 (authorization code):**
1. App to User: redirect to authorization URL with client ID + scopes
2. User to App: callback with authorization `code`
3. App to Provider: exchange code for access token (+ refresh token)

OAuth 2.0 is one step shorter. There is no request token phase.

#### Migration example

```php
// BEFORE (2.x OAuth 1.0a)
$consumer = new Horde_Oauth_Consumer([
    'key'               => 'consumer-key',
    'secret'            => 'consumer-secret',
    'requestTokenUrl'   => 'https://provider.example/request_token',
    'authorizeTokenUrl' => 'https://provider.example/authorize',
    'accessTokenUrl'    => 'https://provider.example/access_token',
    'signatureMethod'   => new Horde_Oauth_SignatureMethod_HmacSha1(),
    'callbackUrl'       => 'https://app.example/callback',
]);
$requestToken = $consumer->getRequestToken();
$authUrl      = $consumer->getUserAuthorizationUrl($requestToken);
// ... user redirects, returns with verifier ...
$accessToken  = $consumer->getAccessToken($requestToken, $params);

// AFTER (4.x OAuth 2.0)
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
    'https://app.example/callback',
    $psrHttpClient,
    $requestFactory,
    $streamFactory,
);

// Step 1: No request token needed - go straight to authorization
$state   = bin2hex(random_bytes(16));
$authUrl = $client->getAuthorizationUrl(['openid', 'profile'], $state);

// Step 2: After user returns with ?code=...&state=...
$tokenSet = $client->exchangeCode($authorizationCode);

// Access token is a simple string, not a key/secret pair
$accessToken = $tokenSet->accessToken;

// Refresh when expired (OAuth 1.0a had no equivalent)
if ($tokenSet->isExpired()) {
    $tokenSet = $client->refreshToken($tokenSet->refreshToken);
}
```

#### What changes in your application

1. **No request token step** Remove the initial token fetch and the session
   storage for the request token secret. Instead, generate a random `state`
   parameter and store it in the session for CSRF validation.

2. **No per-request signing** Replace `Horde_Oauth_Request` signing logic
   with a simple `Authorization: Bearer <token>` header. The
   `AuthenticatedHttpClient` from `Horde\OAuth\Client` handles this
   automatically, including transparent token refresh.

3. **Token storage changes** Instead of storing a key/secret pair, store the
   `TokenSet` (access token, refresh token, expiry). The `TokenSet::toArray()`
   and `TokenSet::fromArray()` methods support serialization.

4. **Scopes** OAuth 2.0 providers use scopes to control what your application
   can access. You must request the appropriate scopes during authorization.
   Consult the provider's documentation for available scopes.

5. **Provider registration** You will need to register your application with
   the provider's OAuth 2.0 system. The consumer key/secret from OAuth 1.0a
   typically cannot be reused. You will receive a new client ID and secret.
   And that's terrible.

6. **Provider discovery.** If the provider supports OpenID Connect you can use
   `ProviderDiscovery` to auto-configure endpoints instead of hardcoding URLs.

---

### Deprecation timeline

The `lib/` classes (`Horde_Oauth_*`) remain functional in 4.x but are not
actively maintained. They will be removed in a future major version.
