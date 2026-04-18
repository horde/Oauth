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

namespace Horde\Oauth\Server\Handler;

use Horde\Oauth\ErrorResponse;
use Horde\Oauth\Exception\AccessDeniedException;
use Horde\Oauth\Exception\InvalidRequestException;
use Horde\Oauth\Exception\OAuthException;
use Horde\Oauth\Server\AuthorizationRequest;
use Horde\Oauth\Server\AuthorizationResult;
use Horde\Oauth\Server\Entity\AuthorizationCode;
use Horde\Oauth\Server\Entity\Scope;
use Horde\Oauth\Server\Repository\AuthorizationCodeRepository;
use Horde\Oauth\Server\Repository\ClientRepository;
use Horde\Oauth\Server\Repository\ScopeRepository;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Server\RequestHandlerInterface;
use DateTimeImmutable;

final class AuthorizationEndpoint implements RequestHandlerInterface
{
    public function __construct(
        private readonly ClientRepository $clientRepository,
        private readonly ScopeRepository $scopeRepository,
        private readonly AuthorizationCodeRepository $authCodeRepository,
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly StreamFactoryInterface $streamFactory,
    ) {}

    public function validateAuthorizationRequest(ServerRequestInterface $request): AuthorizationRequest
    {
        $params = $request->getQueryParams();

        $responseType = $params['response_type'] ?? null;
        if ($responseType !== 'code') {
            throw new InvalidRequestException('Only response_type=code is supported');
        }

        $clientId = $params['client_id'] ?? null;
        if (!is_string($clientId) || $clientId === '') {
            throw new InvalidRequestException('Missing required parameter: client_id');
        }

        $client = $this->clientRepository->findById($clientId);
        if ($client === null) {
            throw new InvalidRequestException('Unknown client_id');
        }

        $redirectUri = $params['redirect_uri'] ?? '';
        if ($redirectUri !== '' && !$client->hasRedirectUri($redirectUri)) {
            throw new InvalidRequestException('Invalid redirect_uri');
        }
        if ($redirectUri === '' && count($client->redirectUris) === 1) {
            $redirectUri = $client->redirectUris[0];
        }
        if ($redirectUri === '') {
            throw new InvalidRequestException('Missing required parameter: redirect_uri');
        }

        $state = $params['state'] ?? '';
        $scopeString = $params['scope'] ?? '';
        $scopes = is_string($scopeString) ? Scope::fromSpaceSeparated($scopeString) : [];
        $scopes = $this->scopeRepository->finalizeScopes($scopes, 'authorization_code', $client);

        $codeChallenge = $params['code_challenge'] ?? null;
        $codeChallengeMethod = $params['code_challenge_method'] ?? ($codeChallenge !== null ? 'plain' : null);

        $nonce = $params['nonce'] ?? null;

        return new AuthorizationRequest(
            $client,
            $responseType,
            $redirectUri,
            is_string($state) ? $state : '',
            $scopes,
            is_string($codeChallenge) ? $codeChallenge : null,
            is_string($codeChallengeMethod) ? $codeChallengeMethod : null,
            is_string($nonce) ? $nonce : null,
        );
    }

    public function completeAuthorizationRequest(AuthorizationResult $result): ResponseInterface
    {
        $request = $result->request;

        if (!$result->approved) {
            $query = http_build_query(array_filter([
                'error' => 'access_denied',
                'error_description' => 'The user denied the authorization request',
                'state' => $request->state,
            ]));
            return $this->responseFactory->createResponse(302)
                ->withHeader('Location', $request->redirectUri . '?' . $query);
        }

        $scopes = $result->approvedScopes ?? $request->scopes;
        $code = bin2hex(random_bytes(32));

        $authCode = new AuthorizationCode(
            $code,
            $request->client->clientId,
            $result->identityId ?? '',
            $request->redirectUri,
            Scope::toSpaceSeparated($scopes),
            $request->codeChallenge,
            $request->codeChallengeMethod,
            $request->nonce,
            new DateTimeImmutable('+10 minutes'),
        );
        $this->authCodeRepository->persist($authCode);

        $query = http_build_query(array_filter([
            'code' => $code,
            'state' => $request->state,
        ]));

        return $this->responseFactory->createResponse(302)
            ->withHeader('Location', $request->redirectUri . '?' . $query);
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        try {
            $authRequest = $this->validateAuthorizationRequest($request);
            return $this->responseFactory->createResponse(200)
                ->withHeader('Content-Type', 'application/json;charset=UTF-8')
                ->withBody($this->streamFactory->createStream(json_encode([
                    'client_id' => $authRequest->client->clientId,
                    'client_name' => $authRequest->client->clientName,
                    'scopes' => array_map(fn(Scope $s) => $s->identifier, $authRequest->scopes),
                    'state' => $authRequest->state,
                ], JSON_THROW_ON_ERROR)));
        } catch (OAuthException $e) {
            return ErrorResponse::toResponse($e, $this->responseFactory, $this->streamFactory);
        }
    }
}
