<?php

namespace Lindelius\JWT;

use Lindelius\JWT\Algorithm\HMAC\HS256;

/**
 * A standard JWT model implementation.
 */
final class StandardJWT extends JWT
{
    use HS256;

    /**
     * Construct a standard JWT object.
     *
     * @param  string      $algorithm
     * @param  array       $header
     * @param  string|null $signature
     * @return void
     */
    public function __construct(string $algorithm = 'HS256', array $header = [], ?string $signature = null)
    {
        parent::__construct($algorithm, $header, $signature);
    }
}
