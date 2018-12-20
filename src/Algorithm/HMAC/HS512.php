<?php

namespace Lindelius\JWT\Algorithm\HMAC;

/**
 * Trait HS512
 */
trait HS512
{
    /**
     * Encode given data using a given key.
     *
     * @param  mixed  $key
     * @param  string $dataToSign
     * @return string|null
     */
    protected function encodeWithHS512($key, string $dataToSign): ?string
    {
        return hash_hmac('SHA512', $dataToSign, $key, true);
    }

    /**
     * Verify a given signature using a given key.
     *
     * @param  mixed  $key
     * @param  string $dataToSign
     * @param  string $signature
     * @return bool
     */
    protected function verifyWithHS512($key, string $dataToSign, string $signature): bool
    {
        return hash_equals($signature, $this->encodeWithHS512($key, $dataToSign));
    }
}
