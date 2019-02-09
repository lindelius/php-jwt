<?php

namespace Lindelius\JWT\Algorithm\HMAC;

use Lindelius\JWT\Exception\InvalidKeyException;

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
     * @throws InvalidKeyException
     */
    protected function encodeWithHS256($key, string $dataToSign): ?string
    {
        if (empty($key) || !is_string($key)) {
            throw new InvalidKeyException('Invalid key.');
        }

        return hash_hmac('SHA256', $dataToSign, $key, true);
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
    protected function verifyWithHS256($key, string $dataToSign, string $signature): bool
    {
        if (empty($key) || !is_string($key)) {
            throw new InvalidKeyException('Invalid key.');
        }

        return hash_equals($signature, $this->encodeWithHS256($key, $dataToSign));
    }
}
