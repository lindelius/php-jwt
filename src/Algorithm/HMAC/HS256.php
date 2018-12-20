<?php

namespace Lindelius\JWT\Algorithm\HMAC;

/**
 * Trait HS256
 */
trait HS256
{
    /**
     * Encode given data using a given key.
     *
     * @param  mixed  $key
     * @param  string $dataToSign
     * @return string|null
     */
    protected function encodeWithHS256($key, string $dataToSign): ?string
    {
        return hash_hmac('SHA256', $dataToSign, $key, true);
    }

    /**
     * Verify a given signature using a given key.
     *
     * @param  mixed  $key
     * @param  string $dataToSign
     * @param  string $signature
     * @return bool
     */
    protected function verifyWithHS256($key, string $dataToSign, string $signature): bool
    {
        return hash_equals($signature, $this->encodeWithHS256($key, $dataToSign));
    }
}
