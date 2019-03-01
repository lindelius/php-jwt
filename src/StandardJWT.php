<?php

namespace Lindelius\JWT;

use Lindelius\JWT\Algorithm\HMAC\HS256;

/**
 * Class StandardJWT
 */
class StandardJWT extends JWT
{
    use HS256;

    /**
     * StandardJWT constructor.
     *
     * @param string      $algorithm
     * @param array       $header
     * @param string|null $signature
     */
    public function __construct(string $algorithm = 'HS256', array $header = [], ?string $signature = null)
    {
        parent::__construct($algorithm, $header, $signature);
    }
}
