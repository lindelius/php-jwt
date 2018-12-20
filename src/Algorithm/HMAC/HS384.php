<?php

namespace Lindelius\JWT\Algorithm\HMAC;

/**
 * Trait HS384
 */
trait HS384
{
    /**
     * Encode given data using a given key.
     *
     * @param  mixed  $key
     * @param  string $dataToSign
     * @return string|null
     */
    protected function encodeWithHS384($key, string $dataToSign): ?string
    {
        return hash_hmac('SHA384', $dataToSign, $key, true);
    }

    /**
     * Verify a given signature using a given key.
     *
     * @param  mixed  $key
     * @param  string $dataToSign
     * @param  string $signature
     * @return bool
     */
    protected function verifyWithHS384($key, string $dataToSign, string $signature): bool
    {
        return hash_equals($signature, $this->encodeWithHS384($key, $dataToSign));
    }
}
