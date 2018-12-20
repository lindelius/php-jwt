<?php

namespace Lindelius\JWT\Algorithm\RSA;

/**
 * Trait RS384
 */
trait RS384
{
    /**
     * Encode given data using a given key.
     *
     * @param  mixed  $key
     * @param  string $dataToSign
     * @return string|null
     */
    protected function encodeWithRS384($key, string $dataToSign): ?string
    {
        $signature = null;

        openssl_sign($dataToSign, $signature, $key, 'SHA384');

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
    protected function verifyWithRS384($key, string $dataToSign, string $signature): bool
    {
        return openssl_verify($dataToSign, $signature, $key, 'SHA384') === 1;
    }
}
