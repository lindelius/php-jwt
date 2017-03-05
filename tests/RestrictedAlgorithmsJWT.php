<?php

namespace Lindelius\JWT\Tests;

use Lindelius\JWT\JWT;

/**
 * Class RestrictedAlgorithmsJWT
 *
 * @author  Tom Lindelius <tom.lindelius@gmail.com>
 * @version 2017-03-05
 */
class RestrictedAlgorithmsJWT extends JWT
{
    /**
     * The allowed hashing algorithms. If empty, all supported algorithms are
     * considered allowed.
     *
     * @var array
     */
    protected static $allowedAlgorithms = ['HS256'];
}
