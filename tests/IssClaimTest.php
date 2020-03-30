<?php

namespace Lindelius\JWT\Tests;

use Lindelius\JWT\Tests\JWT\TestJWT;
use PHPUnit\Framework\TestCase;

/**
 * Class IssClaimTest
 */
class IssClaimTest extends TestCase
{
    /**
     * The value of the "iss" claim, if included, MUST be a string.
     *
     * @return array
     */
    public function invalidIssuerProvider()
    {
        return [

            [1],
            [0.07],
            [new \stdClass()],
            [false],
            [['array']]

        ];
    }

    /**
     * @param  mixed $iss
     * @throws \Lindelius\JWT\Exception\JwtException
     * @throws \RuntimeException
     * @expectedException \Lindelius\JWT\Exception\InvalidJwtException
     * @expectedExceptionMessage Invalid "iss" value.
     * @dataProvider             invalidIssuerProvider
     */
    public function testDecodeWithInvalidIssValue($iss)
    {
        $jwt = TestJWT::create(TestJWT::HS256);
        $jwt->setClaim('iss', $iss);

        $decodedJwt = TestJWT::decode($jwt->encode('my_key'));
        $decodedJwt->verify('my_key', ['iss' => 'Expected Issuer']);
    }

    /**
     * @throws \Lindelius\JWT\Exception\JwtException
     * @expectedException \Lindelius\JWT\Exception\InvalidJwtException
     */
    public function testDecodeWithInvalidIssuer()
    {
        $jwt = TestJWT::create(TestJWT::HS256);
        $jwt->setClaim('iss', 'Actual Issuer');

        $decodedJwt = TestJWT::decode($jwt->encode('my_key'));
        $decodedJwt->verify('my_key', ['iss' => 'Expected Issuer']);
    }

    /**
     * @throws \Lindelius\JWT\Exception\JwtException
     * @expectedException \Lindelius\JWT\Exception\InvalidJwtException
     */
    public function testDecodeWithInvalidIssuerAmongSeveral()
    {
        $jwt = TestJWT::create(TestJWT::HS256);
        $jwt->setClaim('iss', 'Actual Issuer');

        $decodedJwt = TestJWT::decode($jwt->encode('my_key'));
        $decodedJwt->verify('my_key', ['iss' => ['Expected Issuer', 'Alternate Issuer']]);
    }

    /**
     * @throws \Lindelius\JWT\Exception\JwtException
     * @throws \RuntimeException
     * @throws \SebastianBergmann\RecursionContext\Exception
     */
    public function testDecodeWithValidIssuer()
    {
        $jwt = TestJWT::create(TestJWT::HS256);
        $jwt->setClaim('iss', 'Expected Issuer');

        $decodedJwt = TestJWT::decode($jwt->encode('my_key'));
        $this->assertEquals(true, $decodedJwt->verify('my_key', ['iss' => 'Expected Issuer']));
    }

    /**
     * @throws \Lindelius\JWT\Exception\JwtException
     * @throws \RuntimeException
     * @throws \SebastianBergmann\RecursionContext\Exception
     */
    public function testDecodeWithValidIssuerAmongSeveral()
    {
        $jwt = TestJWT::create(TestJWT::HS256);
        $jwt->setClaim('iss', 'Expected Issuer');

        $decodedJwt = TestJWT::decode($jwt->encode('my_key'));
        $this->assertEquals(true, $decodedJwt->verify('my_key', ['iss' => ['Expected Issuer', 'Alternate Issuer']]));
    }
}
