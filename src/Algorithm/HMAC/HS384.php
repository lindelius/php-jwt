<?php

namespace Lindelius\JWT\Algorithm\HMAC;

/**
 * Trait HS384
 */
trait HS384
{
    /**
     * Encodes the given data with a given key.
     *
     * @param  string $data
     * @param  mixed  $key
     * @return string|null
     */
    protected function encodeHS384(string $data, $key): ?string
    {
        return hash_hmac('SHA384', $data, $key, true);
    }

    /**
     * Verifies a given signature.
     *
     * @param  string $signature
     * @param  string $data
     * @param  mixed  $key
     * @return bool
     */
    protected function verifyHS384(string $signature, string $data, $key): bool
    {
        if (hash_equals($signature, hash_hmac('SHA384', $data, $key, true))) {
            return true;
        }

        return false;
    }
}
