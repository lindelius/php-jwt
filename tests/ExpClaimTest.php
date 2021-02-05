<?php

namespace Lindelius\JWT\Tests;

use Lindelius\JWT\Exception\ExpiredJwtException;
use Lindelius\JWT\Exception\JwtException;
use Lindelius\JWT\Tests\JWT\LeewayJWT;
use PHPUnit\Framework\TestCase;

final class ExpClaimTest extends TestCase
{
    /**
     * @return void
     * @throws JwtException
     */
    public function testDecodeWithExpWithinLeewayTime(): void
    {
        $jwt = LeewayJWT::create(LeewayJWT::HS256);
        $jwt->setClaim('exp', time() - 30);

        $decodedJwt = LeewayJWT::decode($jwt->encode('my_key'));
        $decodedJwt->verify('my_key');

        $this->assertInstanceOf(LeewayJWT::class, $decodedJwt);
    }

    /**
     * @return void
     * @throws JwtException
     */
    public function testDecodeWithExpOutsideOfLeewayTime(): void
    {
        $this->expectException(ExpiredJwtException::class);

        $jwt = LeewayJWT::create(LeewayJWT::HS256);
        $jwt->setClaim('exp', time() - 100);

        $decodedJwt = LeewayJWT::decode($jwt->encode('my_key'));
        $decodedJwt->verify('my_key');
    }
}
