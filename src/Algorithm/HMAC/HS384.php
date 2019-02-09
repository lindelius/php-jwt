<?php

namespace Lindelius\JWT\Algorithm\HMAC;

use Lindelius\JWT\Exception\InvalidKeyException;

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
     * @throws InvalidKeyException
     */
    protected function encodeWithHS384($key, string $dataToSign): ?string
    {
        if (empty($key) || !is_string($key)) {
            throw new InvalidKeyException('Invalid key.');
        }

        return hash_hmac('SHA384', $dataToSign, $key, true);
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
    protected function verifyWithHS384($key, string $dataToSign, string $signature): bool
    {
        if (empty($key) || !is_string($key)) {
            throw new InvalidKeyException('Invalid key.');
        }

        return hash_equals($signature, $this->encodeWithHS384($key, $dataToSign));
    }
}
