<?php

namespace Lindelius\JWT\Tests;

use Lindelius\JWT\Tests\JWT\LeewayJWT;
use PHPUnit\Framework\TestCase;

/**
 * Class IatClaimTest
 *
 * @author  Tom Lindelius <tom.lindelius@gmail.com>
 * @version 2018-07-24
 */
class IatClaimTest extends TestCase
{
    /**
     * @throws \Lindelius\JWT\Exception\InvalidJwtException
     */
    public function testDecodeWithIatWithinLeewayTime()
    {
        $jwt = new LeewayJWT();
        $jwt->setClaim('iat', time() + 30);

        $decodedJwt = LeewayJWT::decode($jwt->encode('my_key'));
        $decodedJwt->verify('my_key');

        $this->assertInstanceOf(
            LeewayJWT::class,
            $decodedJwt
        );
    }

    /**
     * @throws \Lindelius\JWT\Exception\InvalidJwtException
     * @expectedException \Lindelius\JWT\Exception\BeforeValidException
     */
    public function testDecodeWithIatOutsideOfLeewayTime()
    {
        $jwt = new LeewayJWT();
        $jwt->setClaim('iat', time() + 100);

        $decodedJwt = LeewayJWT::decode($jwt->encode('my_key'));
        $decodedJwt->verify('my_key');
    }
}
