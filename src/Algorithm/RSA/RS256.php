<?php

namespace Lindelius\JWT\Algorithm\RSA;

/**
 * Trait RS256
 */
trait RS256
{
    /**
     * Encodes given data using a given key.
     *
     * @param  string $data
     * @param  mixed  $key
     * @return string|null
     */
    protected function encodeWithRS256(string $data, $key): ?string
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
    protected function verifyWithRS256(string $signature, string $data, $key): bool
    {
        return openssl_verify($data, $signature, $key, 'SHA256') === 1;
    }
}
