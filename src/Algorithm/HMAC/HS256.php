<?php

namespace Lindelius\JWT\Algorithm\HMAC;

/**
 * Trait HS256
 */
trait HS256
{
    /**
     * Encodes given data using a given key.
     *
     * @param  string $data
     * @param  mixed  $key
     * @return string|null
     */
    protected function encodeWithHS256(string $data, $key): ?string
    {
        return hash_hmac('SHA256', $data, $key, true);
    }

    /**
     * Verifies a given signature.
     *
     * @param  string $signature
     * @param  string $data
     * @param  mixed  $key
     * @return bool
     */
    protected function verifyWithHS256(string $signature, string $data, $key): bool
    {
        return hash_equals($signature, hash_hmac('SHA256', $data, $key, true));
    }
}
