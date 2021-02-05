<?php

namespace Lindelius\JWT\Tests\JWT;

class LeewayJWT extends TestJWT
{
    /**
     * Leeway time (in seconds) to account for clock skew between servers.
     *
     * @var int
     */
    public static $leeway = 90;
}
