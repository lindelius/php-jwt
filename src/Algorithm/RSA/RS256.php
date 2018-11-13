<?php

namespace Lindelius\JWT\Algorithm\RSA;

/**
 * Trait RS256
 */
trait RS256
{
    /**
     * Encodes the given data with a given key.
     *
     * @param  string $data
     * @param  mixed  $key
     * @return string|null
     */
    protected function encodeRS256(string $data, $key): ?string
    {
        $signature = null;

        openssl_sign($data, $signature, $key, 'SHA256');

        return $signature;
    }

    /**
     * Verifies a given signature.
     *
     * @param  string $signature
     * @param  string $data
     * @param  mixed  $key
     * @return bool
     */
    protected function verifyRS256(string $signature, string $data, $key): bool
    {
        if (openssl_verify($data, $signature, $key, 'SHA256') === 1) {
            return true;
        }

        return false;
    }
}
