<?php

namespace Lindelius\JWT\Tests;

use Lindelius\JWT\Tests\JWT\LeewayJWT;
use PHPUnit\Framework\TestCase;

/**
 * Class NbfClaimTest
 */
class NbfClaimTest extends TestCase
{
    /**
     * @throws \Lindelius\JWT\Exception\Exception
     * @throws \RuntimeException
     * @throws \SebastianBergmann\RecursionContext\Exception
     */
    public function testDecodeWithNbfWithinLeewayTime()
    {
        $jwt = new LeewayJWT('HS256');
        $jwt->setClaim('nbf', time() + 30);

        $decodedJwt = LeewayJWT::decode($jwt->encode('my_key'));
        $decodedJwt->verify('my_key');

        $this->assertInstanceOf(LeewayJWT::class, $decodedJwt);
    }

    /**
     * @throws \Lindelius\JWT\Exception\Exception
     * @expectedException \Lindelius\JWT\Exception\BeforeValidException
     */
    public function testDecodeWithNbfOutsideOfLeewayTime()
    {
        $jwt = new LeewayJWT('HS256');
        $jwt->setClaim('nbf', time() + 100);

        $decodedJwt = LeewayJWT::decode($jwt->encode('my_key'));
        $decodedJwt->verify('my_key');
    }
}
