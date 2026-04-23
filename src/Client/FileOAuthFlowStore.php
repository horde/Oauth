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

namespace Horde\OAuth\Client;

use RuntimeException;

final class FileOAuthFlowStore implements OAuthFlowStore
{
    public function __construct(
        private readonly string $dir = '/tmp',
        private readonly string $prefix = 'horde_oauth_',
    ) {}

    public function save(string $state, OAuthFlowData $data): void
    {
        if (!is_dir($this->dir) && !mkdir($this->dir, 0o750, true)) {
            throw new RuntimeException('Cannot create flow store directory: ' . $this->dir);
        }

        $path = $this->path($state);
        $json = json_encode($data->toArray(), JSON_THROW_ON_ERROR);
        if (file_put_contents($path, $json, LOCK_EX) === false) {
            throw new RuntimeException('Cannot write flow file: ' . $path);
        }
    }

    public function consume(string $state): ?OAuthFlowData
    {
        $path = $this->path($state);

        if (!is_file($path)) {
            return null;
        }

        $json = file_get_contents($path);
        unlink($path);

        if ($json === false) {
            return null;
        }

        $data = json_decode($json, true);
        if (!is_array($data)) {
            return null;
        }

        return OAuthFlowData::fromArray($data);
    }

    private function path(string $state): string
    {
        return $this->dir . '/' . $this->prefix . hash('sha256', $state);
    }
}
