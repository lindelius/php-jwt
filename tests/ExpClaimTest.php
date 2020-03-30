<?php

namespace Lindelius\JWT\Tests;

use Lindelius\JWT\Tests\JWT\LeewayJWT;
use PHPUnit\Framework\TestCase;

/**
 * Class ExpClaimTest
 */
class ExpClaimTest extends TestCase
{
    /**
     * @throws \Lindelius\JWT\Exception\JwtException
     * @throws \RuntimeException
     * @throws \SebastianBergmann\RecursionContext\Exception
     */
    public function testDecodeWithExpWithinLeewayTime()
    {
        $jwt = LeewayJWT::create(LeewayJWT::HS256);
        $jwt->setClaim('exp', time() - 30);

        $decodedJwt = LeewayJWT::decode($jwt->encode('my_key'));
        $decodedJwt->verify('my_key');

        $this->assertInstanceOf(LeewayJWT::class, $decodedJwt);
    }

    /**
     * @throws \Lindelius\JWT\Exception\JwtException
     * @expectedException \Lindelius\JWT\Exception\ExpiredJwtException
     */
    public function testDecodeWithExpOutsideOfLeewayTime()
    {
        $jwt = LeewayJWT::create(LeewayJWT::HS256);
        $jwt->setClaim('exp', time() - 100);

        $decodedJwt = LeewayJWT::decode($jwt->encode('my_key'));
        $decodedJwt->verify('my_key');
    }
}
