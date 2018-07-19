<?php

namespace Lindelius\JWT\Tests\JWT;

use Lindelius\JWT\JWT;

/**
 * Class LeewayJWT
 *
 * @author  Tom Lindelius <tom.lindelius@gmail.com>
 * @version 2018-07-19
 */
class LeewayJWT extends JWT
{
    /**
     * Leeway time (in seconds) to account for clock skew.
     *
     * @var int
     */
    protected static $leeway = 90;
}
