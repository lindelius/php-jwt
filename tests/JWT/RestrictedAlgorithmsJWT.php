<?php

namespace Lindelius\JWT\Tests\JWT;

/**
 * Class RestrictedAlgorithmsJWT
 */
class RestrictedAlgorithmsJWT extends TestJWT
{
    /**
     * The allowed hashing algorithms. If empty, all supported algorithms are
     * considered allowed.
     *
     * @var string[]
     */
    protected static $allowedAlgorithms = ['HS256'];
}
