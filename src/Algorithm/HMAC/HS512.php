<?php

namespace Lindelius\JWT\Algorithm\HMAC;

use Lindelius\JWT\Exception\InvalidKeyException;

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
     * @throws InvalidKeyException
     */
    protected function encodeWithHS512($key, string $dataToSign): ?string
    {
        if (empty($key) || !is_string($key)) {
            throw new InvalidKeyException('Invalid key.');
        }

        return hash_hmac('SHA512', $dataToSign, $key, true);
    }

    /**
     * Verify a given signature using a given key.
     *
     * @param  mixed  $key
     * @param  string $dataToSign
     * @param  string $signature
     * @return bool
     * @throws InvalidKeyException
     */
    protected function verifyWithHS512($key, string $dataToSign, string $signature): bool
    {
        if (empty($key) || !is_string($key)) {
            throw new InvalidKeyException('Invalid key.');
        }

        return hash_equals($signature, $this->encodeWithHS512($key, $dataToSign));
    }
}
