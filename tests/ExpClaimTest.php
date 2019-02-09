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
     * @throws \Lindelius\JWT\Exception\Exception
     * @throws \RuntimeException
     * @throws \SebastianBergmann\RecursionContext\Exception
     */
    public function testDecodeWithExpWithinLeewayTime()
    {
        $jwt = new LeewayJWT('HS256');
        $jwt->setClaim('exp', time() - 30);

        $decodedJwt = LeewayJWT::decode($jwt->encode('my_key'));
        $decodedJwt->verify('my_key');

        $this->assertInstanceOf(LeewayJWT::class, $decodedJwt);
    }

    /**
     * @throws \Lindelius\JWT\Exception\Exception
     * @expectedException \Lindelius\JWT\Exception\ExpiredJwtException
     */
    public function testDecodeWithExpOutsideOfLeewayTime()
    {
        $jwt = new LeewayJWT('HS256');
        $jwt->setClaim('exp', time() - 100);

        $decodedJwt = LeewayJWT::decode($jwt->encode('my_key'));
        $decodedJwt->verify('my_key');
    }
}
