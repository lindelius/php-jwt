<?php

namespace Lindelius\JWT\Tests;

use Lindelius\JWT\Tests\JWT\LeewayJWT;
use PHPUnit\Framework\TestCase;

/**
 * Class ExpClaimTest
 *
 * @author  Tom Lindelius <tom.lindelius@gmail.com>
 * @version 2018-07-24
 */
class ExpClaimTest extends TestCase
{
    /**
     * @throws \Lindelius\JWT\Exception\InvalidJwtException
     */
    public function testDecodeWithExpWithinLeewayTime()
    {
        $jwt = new LeewayJWT();
        $jwt->setClaim('exp', time() - 30);

        $decodedJwt = LeewayJWT::decode($jwt->encode('my_key'));
        $decodedJwt->verify('my_key');

        $this->assertInstanceOf(
            LeewayJWT::class,
            $decodedJwt
        );
    }

    /**
     * @throws \Lindelius\JWT\Exception\InvalidJwtException
     * @expectedException \Lindelius\JWT\Exception\ExpiredJwtException
     */
    public function testDecodeWithExpOutsideOfLeewayTime()
    {
        $jwt = new LeewayJWT();
        $jwt->setClaim('exp', time() - 100);

        $decodedJwt = LeewayJWT::decode($jwt->encode('my_key'));
        $decodedJwt->verify('my_key');
    }
}
