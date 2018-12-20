<?php

namespace Lindelius\JWT\Algorithm\RSA;

/**
 * Trait RS512
 */
trait RS512
{
    /**
     * Encode given data using a given key.
     *
     * @param  mixed  $key
     * @param  string $dataToSign
     * @return string|null
     */
    protected function encodeWithRS512($key, string $dataToSign): ?string
    {
        $signature = null;

        openssl_sign($dataToSign, $signature, $key, 'SHA512');

        return $signature;
    }

    /**
     * Verify a given signature using a given key.
     *
     * @param  mixed  $key
     * @param  string $dataToSign
     * @param  string $signature
     * @return bool
     */
    protected function verifyWithRS512($key, string $dataToSign, string $signature): bool
    {
        return openssl_verify($dataToSign, $signature, $key, 'SHA512') === 1;
    }
}
