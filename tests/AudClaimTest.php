<?php

namespace Lindelius\JWT\Tests;

use Lindelius\JWT\Tests\JWT\TestJWT;
use PHPUnit\Framework\TestCase;

/**
 * Class AudClaimTest
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
     * @throws \Lindelius\JWT\Exception\Exception
     * @throws \RuntimeException
     * @expectedException \Lindelius\JWT\Exception\InvalidJwtException
     * @expectedExceptionMessage Invalid "aud" value.
     * @dataProvider             invalidAudienceProvider
     */
    public function testDecodeWithInvalidAudValue($aud)
    {
        $jwt = new TestJWT('HS256');
        $jwt->setClaim('aud', $aud);

        $decodedJwt = TestJWT::decode($jwt->encode('my_key'));
        $decodedJwt->verify('my_key', 'https://myapp.tld');
    }

    /**
     * @throws \Lindelius\JWT\Exception\Exception
     * @expectedException \Lindelius\JWT\Exception\InvalidAudienceException
     */
    public function testDecodeWithInvalidAudience()
    {
        $decodedJwt = TestJWT::decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJodHRwczpcL1wvbXlhcHAudGxkIn0.kfXUmztf59REc6YAHNS7J1SleE_ufiWK7bTgSqM_buo');
        $decodedJwt->verify('my_key', 'https://unknownapp.tld');
    }

    /**
     * @throws \Lindelius\JWT\Exception\Exception
     * @expectedException \Lindelius\JWT\Exception\InvalidAudienceException
     */
    public function testDecodeWithInvalidAudienceAmongSeveral()
    {
        $decodedJwt = TestJWT::decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOlsiaHR0cHM6XC9cL215YXBwLnRsZCIsImh0dHBzOlwvXC95b3VyYXBwLnRsZCJdfQ.Yxa674OTihi3i3pp00DEa_BAPMmcIgTwQmbEaN-sNfA');
        $decodedJwt->verify('my_key', 'https://unknownapp.tld');
    }

    /**
     * @throws \Lindelius\JWT\Exception\Exception
     * @throws \RuntimeException
     * @throws \SebastianBergmann\RecursionContext\Exception
     */
    public function testDecodeWithValidAudience()
    {
        $decodedJwt = TestJWT::decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJodHRwczpcL1wvbXlhcHAudGxkIn0.kfXUmztf59REc6YAHNS7J1SleE_ufiWK7bTgSqM_buo');

        $this->assertEquals(
            true,
            $decodedJwt->verify('my_key', 'https://myapp.tld')
        );
    }

    /**
     * @throws \Lindelius\JWT\Exception\Exception
     * @throws \RuntimeException
     * @throws \SebastianBergmann\RecursionContext\Exception
     */
    public function testDecodeWithValidAudienceAmongSeveral()
    {
        $decodedJwt = TestJWT::decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOlsiaHR0cHM6XC9cL215YXBwLnRsZCIsImh0dHBzOlwvXC95b3VyYXBwLnRsZCJdfQ.Yxa674OTihi3i3pp00DEa_BAPMmcIgTwQmbEaN-sNfA');

        $this->assertEquals(
            true,
            $decodedJwt->verify('my_key', 'https://myapp.tld')
        );
    }
}
