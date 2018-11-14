<?php

namespace Lindelius\JWT\Algorithm\RSA;

/**
 * Trait RS512
 */
trait RS512
{
    /**
     * Encodes given data using a given key.
     *
     * @param  string $data
     * @param  mixed  $key
     * @return string|null
     */
    protected function encodeWithRS512(string $data, $key): ?string
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
    protected function verifyWithRS512(string $signature, string $data, $key): bool
    {
        return openssl_verify($data, $signature, $key, 'SHA512') === 1;
    }
}
