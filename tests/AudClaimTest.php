<?php

namespace Lindelius\JWT\Tests;

use Lindelius\JWT\Exception\InvalidJwtException;
use Lindelius\JWT\Exception\JwtException;
use Lindelius\JWT\Tests\JWT\TestJWT;
use PHPUnit\Framework\TestCase;
use stdClass;

final class AudClaimTest extends TestCase
{
    /**
     * The value of the "aud" claim, if included, MUST be either a string or an
     * array of strings.
     *
     * @return array
     */
    public function invalidAudienceProvider(): array
    {
        return [

            [1],
            [0.07],
            [new stdClass()],
            [false],

            [[1]],
            [[0.07]],
            [[null]],
            [[new stdClass()]],
            [[false]],
            [[[]]],
            [[7 => 'value']],
            [['key' => 'value']],

        ];
    }

    /**
     * @dataProvider invalidAudienceProvider
     * @param  mixed $aud
     * @return void
     * @throws JwtException
     */
    public function testDecodeWithInvalidAudValue($aud): void
    {
        $this->expectException(InvalidJwtException::class);
        $this->expectExceptionMessage('Invalid "aud" value.');

        $jwt = TestJWT::create(TestJWT::HS256);
        $jwt->setClaim('aud', $aud);

        $decodedJwt = TestJWT::decode($jwt->encode('my_key'));
        $decodedJwt->verify('my_key', ['aud' => 'https://myapp.tld']);
    }

    /**
     * @return void
     * @throws JwtException
     */
    public function testDecodeWithInvalidAudience(): void
    {
        $this->expectException(InvalidJwtException::class);

        $decodedJwt = TestJWT::decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJodHRwczpcL1wvbXlhcHAudGxkIn0.kfXUmztf59REc6YAHNS7J1SleE_ufiWK7bTgSqM_buo');
        $decodedJwt->verify('my_key', ['aud' => 'https://unknownapp.tld']);
    }

    /**
     * @return void
     * @throws JwtException
     */
    public function testDecodeWithInvalidAudienceAmongSeveral(): void
    {
        $this->expectException(InvalidJwtException::class);

        $decodedJwt = TestJWT::decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOlsiaHR0cHM6XC9cL215YXBwLnRsZCIsImh0dHBzOlwvXC95b3VyYXBwLnRsZCJdfQ.Yxa674OTihi3i3pp00DEa_BAPMmcIgTwQmbEaN-sNfA');
        $decodedJwt->verify('my_key', ['aud' => 'https://unknownapp.tld']);
    }

    /**
     * @return void
     * @throws JwtException
     */
    public function testDecodeWithValidAudience(): void
    {
        $decodedJwt = TestJWT::decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJodHRwczpcL1wvbXlhcHAudGxkIn0.kfXUmztf59REc6YAHNS7J1SleE_ufiWK7bTgSqM_buo');

        $this->assertEquals(true, $decodedJwt->verify('my_key', ['aud' => 'https://myapp.tld']));
    }

    /**
     * @return void
     * @throws JwtException
     */
    public function testDecodeWithValidAudienceAmongSeveral(): void
    {
        $decodedJwt = TestJWT::decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOlsiaHR0cHM6XC9cL215YXBwLnRsZCIsImh0dHBzOlwvXC95b3VyYXBwLnRsZCJdfQ.Yxa674OTihi3i3pp00DEa_BAPMmcIgTwQmbEaN-sNfA');

        $this->assertEquals(true, $decodedJwt->verify('my_key', ['aud' => 'https://myapp.tld']));
    }
}
