<?php

namespace Lindelius\JWT\Algorithm\RSA;

/**
 * Trait RS512
 */
trait RS512
{
    /**
     * Encodes the given data with a given key.
     *
     * @param  string $data
     * @param  mixed  $key
     * @return string|null
     */
    protected function encodeRS512(string $data, $key): ?string
    {
        $signature = null;

        openssl_sign($data, $signature, $key, 'SHA512');

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
    protected function verifyRS512(string $signature, string $data, $key): bool
    {
        if (openssl_verify($data, $signature, $key, 'SHA512') === 1) {
            return true;
        }

        return false;
    }
}
