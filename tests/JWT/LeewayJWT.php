<?php

namespace Lindelius\JWT\Tests\JWT;

/**
 * Class LeewayJWT
 */
class LeewayJWT extends TestJWT
{
    /**
     * Leeway time (in seconds) to account for clock skew.
     *
     * @var int
     */
    protected static $leeway = 90;
}
