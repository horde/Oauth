# Architecture

## Design philosophy

`horde/oauth` is designed as a **pure protocol library**. It implements the
OAuth and OpenID Connect specifications without coupling to any specific framework,
HTTP stack or persistence layer. Integrators bring their own implementations
of the standardized interfaces and compose the pieces as they need.

### PSR standards over concrete implementations

The library depends exclusively on PSR interface packages:

| PSR | Package | Role |
|---|---|---|
| PSR-7 | `psr/http-message` | Request, response, URI, stream |
| PSR-17 | `psr/http-factory` | Request and stream factories |
| PSR-18 | `psr/http-client` | HTTP client for outgoing requests |
| PSR-15 | `psr/http-server-handler`, `psr/http-server-middleware` | Server-side request handling |

The only non-PSR dependency is `horde/jwt` for JWT token encoding and
verification, because JWT is a complex specification that warrants a dedicated
library and should not be implemented as an inline afterthought.

This means in practice `horde/oauth` never instantiates an HTTP client, never chooses a stream implementation and never assumes which middleware dispatcher is in use. Any PSR compliant stack works: `horde/http`, Slim,
Mezzio, Guzzle or a custom implementation.

### Delegation of concerns to integrators

The library deliberately does not own:

- **Token persistence.** Server-side repositories are defined as interfaces
  (`ClientRepository`, `AccessTokenRepository`, etc.) with in-memory
  reference implementations for testing. Production storage such as database, Redis,
  file is the integrator's responsibility or separated into a bridge library.
  Client side token storage and encryption are similarly delegated. The library provides `TokenSet::toArray()`
  and `TokenSet::fromArray()` for serialization; how and where the result is stored is an application concern.

- **User identity.** The server grants reference an opaque `identityId`
  string. How that maps to a user table, LDAP entry or session is outside
  the library's scope.

- **Session and CSRF management.** Client-side flows require state parameters
  and PKCE verifiers to survive across the redirect. The library provides
  `OAuthFlowStore` as an interface and `FileOAuthFlowStore` as a simple
  default, but integrators are expected to use their own session infrastructure
  in production.

- **UI and routing.** Server handlers implement `RequestHandlerInterface` and
  can be mounted at any path in any framework's router. The library does not
  prescribe URL structure, template engine or consent screen rendering.

- **Transport security.** OAuth 2.0 relies on TLS. The library does not
  enforce HTTPS. That is the responsibility of the deployment environment and
  the HTTP client configuration. The OAuth 1.0a client works reasonably well under plain HTTP but the protocol is largely deprecated among servers.

### Minimal coupling within Horde

`horde/oauth` can be used entirely outside the Horde framework. Within Horde the framework integration layer (`horde/core`, `horde/base`) is responsible for wiring the library to Horde's registry, session, preferences and routing.

This separation means:

- `horde/oauth` never references Horde_Registry, Horde Session, Horde Config, Horde Preferences or any framework service.
- `horde/oauth` never reads configuration files or environment variables.
- Upgrades to `horde/oauth` do not require framework changes and vice versa.

---

## Namespace structure

```
Horde\OAuth\
  Client\                    OAuth 2.0 client role (RFC 6749)
  Server\                    OAuth 2.0 authorization server (RFC 6749)
    Entity\                  Domain objects (Client, AccessToken, etc.)
    Grant\                   Grant type implementations
    Repository\              Persistence interfaces + in-memory reference
    Handler\                 PSR-15 request handlers (endpoints)
    Token\                   Token issuers
    ClientAuthentication\    Client credential extraction
    Middleware\              PSR-15 middleware (Bearer token)
    Pkce\                    PKCE verification (RFC 7636)
  Oidc\                      OpenID Connect layer
    Handler\                 Discovery, JWKS, Userinfo endpoints
  V10a\                      OAuth 1.0a (RFC 5849)
    Client\                  Consumer/client role
    Request\                 Request signing and header building
    Signature\               Signature method implementations
    Util\                    Protocol-specific utilities
  Exception\                 Shared exception hierarchy
```

The `V10a` prefix makes the protocol version explicit. OAuth 1.0 and 1.0a
are materially different protocols (1.0a added the verifier step to prevent
session fixation attacks). The name avoids ambiguity and sits cleanly alongside
the version implicit `Client\` (OAuth 2.0) and `Server\` namespaces.

The legacy `lib/Horde/Oauth/` PSR-0 tree coexists via a separate autoload
root. See [UPGRADING.md](UPGRADING.md) for migration guidance.

---

## Immutability and value objects

All protocol data objects are immutable: `TokenSet`, `ScopeSet`, `Token`,
`ConsumerCredentials`, `ProviderEndpoints`, `ProviderConfig` and the server
entities. Properties are `readonly` and constructors validate invariants. Where
mutation is needed conceptually (e.g. adding a scope), the API returns a new
instance (`ScopeSet::union()` returns a new `ScopeSet`).

This makes token handling, parameter passing and concurrent access
predictable. If a `TokenSet` exists, its fields are trustworthy for the
lifetime of the reference.

---

## Signature method decoupling (OAuth 1.0a)

The legacy `Horde_Oauth_SignatureMethod::sign()` received the full `$request`,
`$consumer` and `$token` objects — coupling the signing algorithm to the
request builder and the credential containers. The modern `SignatureMethod`
interface receives primitive strings:

```php
interface SignatureMethod
{
    public function sign(string $baseString, string $consumerSecret, string $tokenSecret): string;
    public function verify(string $signature, string $baseString, string $consumerSecret, string $tokenSecret): bool;
}
```

This makes signature methods independently testable against RFC 5849 test vectors without constructing mock requests or credential objects. The `OAuth1Client` orchestrates base string construction and passes the result
to the signature method.

---

## Explicit design choices

### URL normalization is private to SignedRequest

The OAuth 1.0a `SignedRequest` performs URL normalization as defined by RFC 5849 Section 3.4.1.2: lowercase scheme and host, strip default ports, keep path, discard query and fragment. The `horde/http` package contains a `Uri`
class with overlapping normalization logic.

The normalization lives as a private method in `SignedRequest` rather than
delegating to `horde/http` because:

- Adding `horde/http` would introduce a hard dependency on a concrete HTTP implementation. Every consumer of `horde/oauth`, even those using Guzzle, Symfony or other stacks would pull in `horde/http` for a single utility method.
- The normalization is defined by RFC 5849, not RFC 3986. The two overlap today but are independent specifications. A protocol-specific private method remains correct even if the general-purpose URI class evolves.
- The logic is 15 lines with no expected changes (RFC 5849 is final). The cost of duplication is negligible. the cost of an unwanted transitive dependency is borne by every downstream consumer.

### RFC 3986 encoding is local to the OAuth package

`Rfc3986::encode()` applies the percent-encoding variant specified by the
OAuth 1.0a signing algorithm: `rawurlencode` with tilde preservation and
plus encoding. This is not general-purpose URL encoding — it exists solely
to produce correct OAuth signature base strings. Extracting it to a shared
utility package would create a dependency for a single static method with OAuth-specific semantics.

### Nonce generation does not reuse horde/Token

The `horde/Token` package contains a `Nonce` class that packs a timestamp and
random bytes into a binary format for token validation purposes. OAuth 1.0a
nonces have different requirements: They must be unique opaque strings with no
embedded structure. Using `random_bytes` directly avoids adding a dependency
and avoids repurposing an internal class designed for a different use case.

### No horde/jwt reuse for OAuth 1.0a HMAC signing

The `horde/jwt` package provides `Hs256Signer` for HMAC-SHA256 JWT signing.
OAuth 1.0a HMAC signatures use a different key construction (consumer secret
and token secret are RFC-3986-encoded and joined with `&`) and a different
hash algorithm (SHA-1 for HMAC-SHA1). Creating an `Hs256Signer` instance
per request just to call its `sign()` method would be semantically misleading and would not avoid the OAuth specific key construction code.

### Exception hierarchy is shared across protocol versions

OAuth 1.0a and OAuth 2.0 exceptions live in the same `Horde\OAuth\Exception\`
namespace. `OAuthException` is the base class for both protocol versions.
Version-specific subclasses (`InvalidSignatureException` for 1.0a,
`InvalidGrantException` for 2.0) extend it. This avoids parallel exception
hierarchies while allowing callers to catch at the granularity they need.
