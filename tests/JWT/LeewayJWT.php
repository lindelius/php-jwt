<?php

namespace Lindelius\JWT\Tests\JWT;

/**
 * A JWT model that makes use of the leeway time functionality.
 */
class LeewayJWT extends TestJWT
{
    /**
     * Leeway time (in seconds) to account for clock skew between servers.
     *
     * @var int
     */
    public static $leeway = 90;
}
