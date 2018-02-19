<?php

namespace Lindelius\JWT\Tests;

use Lindelius\JWT\JWT;
use PHPUnit\Framework\TestCase;

/**
 * Class JWTTest
 *
 * @author  Tom Lindelius <tom.lindelius@gmail.com>
 * @version 2017-09-25
 */
class JWTTest extends TestCase
{
    /**
     * @return array
     */
    public function invalidKeyProvider()
    {
        return [
            [1],
            [0.07],
            [null],
            [new \stdClass()],
            [''],
            [false]
        ];
    }

    /**
     * @return array
     */
    public function invalidHashProvider()
    {
        return [
            [['an_array']],
            [1],
            [0.07],
            [null],
            [new \stdClass()],
            [''],
            [false],
            [curl_init()]
        ];
    }

    /**
     * @return array
     */
    public function invalidAlgorithmProvider()
    {
        return [
            [['an_array']],
            [1],
            [0.07],
            [new \stdClass()],
            [false],
            [curl_init()]
        ];
    }

    /**
     * @expectedException \DomainException
     * @expectedExceptionMessage Unsupported hashing algorithm.
     */
    public function testCreateWithUnsupportedAlgorithm()
    {
        new JWT('ABC123');
    }

    /**
     * @expectedException \DomainException
     * @expectedExceptionMessage Unsupported hashing algorithm.
     */
    public function testDecodeWithUnsupportedAlgorithm()
    {
        $jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJBQkMxMjMifQ.eyJzb21lX2ZpZWxkIjoiYW55X3ZhbHVlIn0.92nuM1zI5H8lARijnJS_NOEe1at9C38kxJxpgHc9D6Q';

        JWT::decode($jwt, 'my_key', true);
    }

    /**
     * @expectedException \DomainException
     * @expectedExceptionMessage Unsupported hashing algorithm.
     */
    public function testCreateWithDisallowedAlgorithm()
    {
        new RestrictedAlgorithmsJWT('HS512');
    }

    /**
     * @expectedException \DomainException
     * @expectedExceptionMessage Unsupported hashing algorithm.
     */
    public function testDecodeWithDisallowedAlgorithm()
    {
        $jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJzb21lX2ZpZWxkIjoiYW55X3ZhbHVlIn0.Up6KufPyr5SQVacgwVRfrcPRg1uav5cMsn2z41XxZ7s';

        RestrictedAlgorithmsJWT::decode($jwt, 'my_key', true);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid key.
     * @dataProvider invalidKeyProvider
     * @param mixed $key
     */
    public function testDecodeWithInvalidKey($key)
    {
        $jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lX2ZpZWxkIjoiYW55X3ZhbHVlIn0.yQz7d3ZjXJ508tZedOxG3aZPEUVltphXrGFz6lE6Jhk';

        JWT::decode($jwt, $key, true);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid key.
     * @dataProvider invalidKeyProvider
     * @param mixed $key
     */
    public function testEncodeWithInvalidKey($key)
    {
        $jwt = new JWT();
        $jwt->setClaim('some_field', 'any_value');
        $jwt->encode($key);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid hashing algorithm.
     * @dataProvider invalidAlgorithmProvider
     * @param mixed $algorithm
     */
    public function testCreateWithInvalidAlgorithm($algorithm)
    {
        new JWT($algorithm);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid hashing algorithm.
     */
    public function testDecodeWithInvalidAlgorithm()
    {
        $jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOjEzMzd9.eyJzb21lX2ZpZWxkIjoiYW55X3ZhbHVlIn0.q4UyVTIKIamLj8ZvlaQMO_yUblMXHwJ_k3qgeGzrnO0';

        JWT::decode($jwt, 'my_key', true);
    }

    /**
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Invalid JWT.
     * @dataProvider invalidHashProvider
     * @param mixed $hash
     */
    public function testDecodeWithInvalidHash($hash)
    {
        JWT::decode($hash, 'my_key', true);
    }

    /**
     * @expectedException \Lindelius\JWT\Exception\InvalidJwtException
     * @expectedExceptionMessage Unexpected number of JWT segments.
     */
    public function testDecodeMalformedJWT()
    {
        $jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lX2ZpZWxkIjoiYW55X3ZhbHVlIn0';

        JWT::decode($jwt, 'my_key', true);
    }

    /**
     * @expectedException \Lindelius\JWT\Exception\InvalidJwtException
     * @expectedExceptionMessage Invalid "kid" value.
     */
    public function testDecodeWithInvalidKeyId()
    {
        $keys = ['correct_kid' => 'my_key'];

        $jwt = new JWT(null, ['kid' => 'wrong_kid']);
        $jwt->setClaim('some_field', 'any_value');

        JWT::decode($jwt->encode('my_key'), $keys, true);
    }

    public function testFullLifeCycleHS256()
    {
        $jwt = new JWT('HS256');
        $jwt->setClaim('some_field', 'any_value');
        $jwt->encode('my_key');

        $decodedJwt = JWT::decode($jwt->getHash(), 'my_key', false);
        $decodedJwt->verify('my_key');

        $this->assertEquals('any_value', $decodedJwt->getClaim('some_field'));
    }

    public function testFullLifeCycleHS384()
    {
        $jwt = new JWT('HS384');
        $jwt->setClaim('some_field', 'any_value');
        $jwt->encode('my_key');

        $decodedJwt = JWT::decode($jwt->getHash(), 'my_key', false);
        $decodedJwt->verify('my_key');

        $this->assertEquals('any_value', $decodedJwt->getClaim('some_field'));
    }

    public function testFullLifeCycleHS512()
    {
        $jwt = new JWT('HS512');
        $jwt->setClaim('some_field', 'any_value');
        $jwt->encode('my_key');

        $decodedJwt = JWT::decode($jwt->getHash(), 'my_key', false);
        $decodedJwt->verify('my_key');

        $this->assertEquals('any_value', $decodedJwt->getClaim('some_field'));
    }

    public function testFullLifeCycleRS256()
    {
        $privateKey = null;
        $resource   = openssl_pkey_new();

        openssl_pkey_export($resource, $privateKey);

        $publicKey = openssl_pkey_get_details($resource)['key'];

        $jwt = new JWT('RS256');
        $jwt->setClaim('some_field', 'any_value');
        $jwt->encode($privateKey);

        $decodedJwt = JWT::decode($jwt->getHash(), $publicKey, false);
        $decodedJwt->verify($publicKey);

        $this->assertEquals('any_value', $decodedJwt->getClaim('some_field'));
    }

    public function testFullLifeCycleRS384()
    {
        $privateKey = null;
        $resource   = openssl_pkey_new();

        openssl_pkey_export($resource, $privateKey);

        $publicKey = openssl_pkey_get_details($resource)['key'];

        $jwt = new JWT('RS384');
        $jwt->setClaim('some_field', 'any_value');
        $jwt->encode($privateKey);

        $decodedJwt = JWT::decode($jwt->getHash(), $publicKey, false);
        $decodedJwt->verify($publicKey);

        $this->assertEquals('any_value', $decodedJwt->getClaim('some_field'));
    }

    public function testFullLifeCycleRS512()
    {
        $privateKey = null;
        $resource   = openssl_pkey_new();

        openssl_pkey_export($resource, $privateKey);

        $publicKey = openssl_pkey_get_details($resource)['key'];

        $jwt = new JWT('RS512');
        $jwt->setClaim('some_field', 'any_value');
        $jwt->encode($privateKey);

        $decodedJwt = JWT::decode($jwt->getHash(), $publicKey, false);
        $decodedJwt->verify($publicKey);

        $this->assertEquals('any_value', $decodedJwt->getClaim('some_field'));
    }

    public function testDecodeAndVerifyWithValidSignature()
    {
        $hash = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lX2ZpZWxkIjoiYW55X3ZhbHVlIn0.yQz7d3ZjXJ508tZedOxG3aZPEUVltphXrGFz6lE6Jhk';
        $jwt  = JWT::decode($hash, 'my_key', true);

        $this->assertEquals('any_value', $jwt->getClaim('some_field'));
    }

    /**
     * @expectedException \Lindelius\JWT\Exception\InvalidSignatureException
     */
    public function testDecodeAndVerifyWithInvalidSignature()
    {
        $jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lX2ZpZWxkIjoiYW55X3ZhbHVlIn0.JUKQhsQPFfq8fQMkOmJ2x_w3NrEhVZNcYg52vn-GREE';

        JWT::decode($jwt, 'my_key', true);
    }

    public function testDecodeWithExpWithinLeewayTime()
    {
        $jwt = new LeewayJWT();
        $jwt->setClaim('exp', time() - 30);

        $this->assertInstanceOf(
            LeewayJWT::class,
            LeewayJWT::decode($jwt->encode('my_key'), 'my_key', true)
        );
    }

    /**
     * @expectedException \Lindelius\JWT\Exception\ExpiredJwtException
     */
    public function testDecodeWithExpOutsideOfLeewayTime()
    {
        $jwt = new LeewayJWT();
        $jwt->setClaim('exp', time() - 100);

        LeewayJWT::decode($jwt->encode('my_key'), 'my_key', true);
    }

    public function testDecodeWithIatWithinLeewayTime()
    {
        $jwt = new LeewayJWT();
        $jwt->setClaim('iat', time() + 30);

        $this->assertInstanceOf(
            LeewayJWT::class,
            LeewayJWT::decode($jwt->encode('my_key'), 'my_key', true)
        );
    }

    /**
     * @expectedException \Lindelius\JWT\Exception\BeforeValidException
     */
    public function testDecodeWithIatOutsideOfLeewayTime()
    {
        $jwt = new LeewayJWT();
        $jwt->setClaim('iat', time() + 100);

        LeewayJWT::decode($jwt->encode('my_key'), 'my_key', true);
    }

    public function testDecodeWithNbfWithinLeewayTime()
    {
        $jwt = new LeewayJWT();
        $jwt->setClaim('nbf', time() + 30);

        $this->assertInstanceOf(
            LeewayJWT::class,
            LeewayJWT::decode($jwt->encode('my_key'), 'my_key', true)
        );
    }

    /**
     * @expectedException \Lindelius\JWT\Exception\BeforeValidException
     */
    public function testDecodeWithNbfOutsideOfLeewayTime()
    {
        $jwt = new LeewayJWT();
        $jwt->setClaim('nbf', time() + 100);

        LeewayJWT::decode($jwt->encode('my_key'), 'my_key', true);
    }

    /**
     * @expectedException \Lindelius\JWT\Exception\JsonException
     * @expectedExceptionMessage Unable to decode the given JSON string
     */
    public function testDecodeTokenWithInvalidJson()
    {
        $jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.U29tZXRoaW5nIG90aGVyIHRoYW4gSlNPTg.yQz7d3ZjXJ508tZedOxG3aZPEUVltphXrGFz6lE6Jhk';

        JWT::decode($jwt, 'my_key', true);
    }
}
