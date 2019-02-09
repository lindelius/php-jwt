<?php

namespace Lindelius\JWT\Tests;

use Lindelius\JWT\Tests\JWT\LeewayJWT;
use PHPUnit\Framework\TestCase;

/**
 * Class IatClaimTest
 */
class IatClaimTest extends TestCase
{
    /**
     * @throws \Lindelius\JWT\Exception\Exception
     * @throws \RuntimeException
     * @throws \SebastianBergmann\RecursionContext\Exception
     */
    public function testDecodeWithIatWithinLeewayTime()
    {
        $jwt = new LeewayJWT('HS256');
        $jwt->setClaim('iat', time() + 30);

        $decodedJwt = LeewayJWT::decode($jwt->encode('my_key'));
        $decodedJwt->verify('my_key');

        $this->assertInstanceOf(LeewayJWT::class, $decodedJwt);
    }

    /**
     * @throws \Lindelius\JWT\Exception\Exception
     * @throws \RuntimeException
     * @expectedException \Lindelius\JWT\Exception\BeforeValidException
     */
    public function testDecodeWithIatOutsideOfLeewayTime()
    {
        $jwt = new LeewayJWT('HS256');
        $jwt->setClaim('iat', time() + 100);

        $decodedJwt = LeewayJWT::decode($jwt->encode('my_key'));
        $decodedJwt->verify('my_key');
    }
}
