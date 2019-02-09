<?php

namespace Lindelius\JWT\Tests\JWT;

use Lindelius\JWT\Algorithm\HMAC\HS256;
use Lindelius\JWT\Algorithm\HMAC\HS384;
use Lindelius\JWT\Algorithm\HMAC\HS512;
use Lindelius\JWT\Algorithm\RSA\RS256;
use Lindelius\JWT\Algorithm\RSA\RS384;
use Lindelius\JWT\Algorithm\RSA\RS512;
use Lindelius\JWT\JWT;

/**
 * Class TestJWT
 */
class TestJWT extends JWT
{
    use HS256, HS384, HS512, RS256, RS384, RS512;
}
