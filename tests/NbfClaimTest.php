<?php

namespace Lindelius\JWT\Tests;

use PHPUnit\Framework\TestCase;

/**
 * Class NbfClaimTest
 *
 * @author  Tom Lindelius <tom.lindelius@gmail.com>
 * @version 2018-07-19
 */
class NbfClaimTest extends TestCase
{
    /**
     * @throws \Lindelius\JWT\Exception\InvalidJwtException
     */
    public function testDecodeWithNbfWithinLeewayTime()
    {
        $jwt = new LeewayJWT();
        $jwt->setClaim('nbf', time() + 30);

        $decodedJwt = LeewayJWT::decode($jwt->encode('my_key'));
        $decodedJwt->verify('my_key');

        $this->assertInstanceOf(
            LeewayJWT::class,
            $decodedJwt
        );
    }

    /**
     * @expectedException \Lindelius\JWT\Exception\BeforeValidException
     * @throws \Lindelius\JWT\Exception\InvalidJwtException
     */
    public function testDecodeWithNbfOutsideOfLeewayTime()
    {
        $jwt = new LeewayJWT();
        $jwt->setClaim('nbf', time() + 100);

        $decodedJwt = LeewayJWT::decode($jwt->encode('my_key'));
        $decodedJwt->verify('my_key');
    }
}
