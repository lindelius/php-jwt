<?php

namespace Lindelius\JWT\Tests;

use Lindelius\JWT\JWT;
use PHPUnit\Framework\TestCase;

/**
 * Class AudClaimTest
 *
 * @author  Tom Lindelius <tom.lindelius@gmail.com>
 * @version 2018-07-24
 */
class AudClaimTest extends TestCase
{
    /**
     * The value of the "aud" claim, if included, MUST be either a string or an
     * array of strings.
     *
     * @return array
     */
    public function invalidAudienceProvider()
    {
        return [

            [1],
            [0.07],
            [new \stdClass()],
            [false],

            [[1]],
            [[0.07]],
            [[null]],
            [[new \stdClass()]],
            [[false]],
            [[[]]],
            [[7 => 'value']],
            [['key' => 'value']],

        ];
    }

    /**
     * @param mixed $aud
     * @expectedException \Lindelius\JWT\Exception\InvalidJwtException
     * @expectedExceptionMessage Invalid "aud" value.
     * @dataProvider             invalidAudienceProvider
     */
    public function testDecodeWithInvalidAudValue($aud)
    {
        $jwt = new JWT('HS256');
        $jwt->setClaim('aud', $aud);

        $decodedJwt = JWT::decode($jwt->encode('my_key'));
        $decodedJwt->verify('my_key', 'https://myapp.tld');
    }

    /**
     * @throws \Lindelius\JWT\Exception\InvalidJwtException
     * @expectedException \Lindelius\JWT\Exception\InvalidAudienceException
     */
    public function testDecodeWithInvalidAudience()
    {
        $decodedJwt = JWT::decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJodHRwczpcL1wvbXlhcHAudGxkIn0.kfXUmztf59REc6YAHNS7J1SleE_ufiWK7bTgSqM_buo');
        $decodedJwt->verify('my_key', 'https://unknownapp.tld');
    }

    /**
     * @throws \Lindelius\JWT\Exception\InvalidJwtException
     * @expectedException \Lindelius\JWT\Exception\InvalidAudienceException
     */
    public function testDecodeWithInvalidAudienceAmongSeveral()
    {
        $decodedJwt = JWT::decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOlsiaHR0cHM6XC9cL215YXBwLnRsZCIsImh0dHBzOlwvXC95b3VyYXBwLnRsZCJdfQ.Yxa674OTihi3i3pp00DEa_BAPMmcIgTwQmbEaN-sNfA');
        $decodedJwt->verify('my_key', 'https://unknownapp.tld');
    }

    /**
     * @throws \Lindelius\JWT\Exception\InvalidJwtException
     */
    public function testDecodeWithValidAudience()
    {
        $decodedJwt = JWT::decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJodHRwczpcL1wvbXlhcHAudGxkIn0.kfXUmztf59REc6YAHNS7J1SleE_ufiWK7bTgSqM_buo');

        $this->assertEquals(
            true,
            $decodedJwt->verify('my_key', 'https://myapp.tld')
        );
    }

    /**
     * @throws \Lindelius\JWT\Exception\InvalidJwtException
     */
    public function testDecodeWithValidAudienceAmongSeveral()
    {
        $decodedJwt = JWT::decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOlsiaHR0cHM6XC9cL215YXBwLnRsZCIsImh0dHBzOlwvXC95b3VyYXBwLnRsZCJdfQ.Yxa674OTihi3i3pp00DEa_BAPMmcIgTwQmbEaN-sNfA');

        $this->assertEquals(
            true,
            $decodedJwt->verify('my_key', 'https://myapp.tld')
        );
    }
}
