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
     * @param array       $header
     * @param string|null $signature
     */
    public function __construct(array $header = [], ?string $signature = null)
    {
        parent::__construct('HS256', $header, $signature);
    }
}
