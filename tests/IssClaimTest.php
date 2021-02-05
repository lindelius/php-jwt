<?php

namespace Lindelius\JWT\Tests;

use Lindelius\JWT\Exception\InvalidJwtException;
use Lindelius\JWT\Exception\JwtException;
use Lindelius\JWT\Tests\JWT\TestJWT;
use PHPUnit\Framework\TestCase;

final class IssClaimTest extends TestCase
{
    /**
     * The value of the "iss" claim, if included, MUST be a string.
     *
     * @return array
     */
    public function invalidIssuerProvider(): array
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
     * @dataProvider invalidIssuerProvider
     * @param mixed $iss
     * @return void
     * @throws JwtException
     */
    public function testDecodeWithInvalidIssValue($iss): void
    {
        $this->expectException(InvalidJwtException::class);
        $this->expectExceptionMessage('Invalid "iss" value.');

        $jwt = TestJWT::create(TestJWT::HS256);
        $jwt->setClaim('iss', $iss);

        $decodedJwt = TestJWT::decode($jwt->encode('my_key'));
        $decodedJwt->verify('my_key', ['iss' => 'Expected Issuer']);
    }

    /**
     * @return void
     * @throws JwtException
     */
    public function testDecodeWithInvalidIssuer(): void
    {
        $this->expectException(InvalidJwtException::class);

        $jwt = TestJWT::create(TestJWT::HS256);
        $jwt->setClaim('iss', 'Actual Issuer');

        $decodedJwt = TestJWT::decode($jwt->encode('my_key'));
        $decodedJwt->verify('my_key', ['iss' => 'Expected Issuer']);
    }

    /**
     * @return void
     * @throws JwtException
     */
    public function testDecodeWithInvalidIssuerAmongSeveral(): void
    {
        $this->expectException(InvalidJwtException::class);

        $jwt = TestJWT::create(TestJWT::HS256);
        $jwt->setClaim('iss', 'Actual Issuer');

        $decodedJwt = TestJWT::decode($jwt->encode('my_key'));
        $decodedJwt->verify('my_key', ['iss' => ['Expected Issuer', 'Alternate Issuer']]);
    }

    /**
     * @return void
     * @throws JwtException
     */
    public function testDecodeWithValidIssuer(): void
    {
        $jwt = TestJWT::create(TestJWT::HS256);
        $jwt->setClaim('iss', 'Expected Issuer');

        $decodedJwt = TestJWT::decode($jwt->encode('my_key'));
        $this->assertEquals(true, $decodedJwt->verify('my_key', ['iss' => 'Expected Issuer']));
    }

    /**
     * @return void
     * @throws JwtException
     */
    public function testDecodeWithValidIssuerAmongSeveral(): void
    {
        $jwt = TestJWT::create(TestJWT::HS256);
        $jwt->setClaim('iss', 'Expected Issuer');

        $decodedJwt = TestJWT::decode($jwt->encode('my_key'));
        $this->assertEquals(true, $decodedJwt->verify('my_key', ['iss' => ['Expected Issuer', 'Alternate Issuer']]));
    }
}
