<?php

namespace Lindelius\JWT\Tests\JWT;

use Lindelius\JWT\JWT;

/**
 * Class RestrictedAlgorithmsJWT
 */
class RestrictedAlgorithmsJWT extends JWT
{
    /**
     * The allowed hashing algorithms. If empty, all supported algorithms are
     * considered allowed.
     *
     * @var string[]
     */
    protected static $allowedAlgorithms = ['HS256'];
}
