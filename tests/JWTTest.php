<?php

namespace Lindelius\JWT\Tests;

use Lindelius\JWT\Tests\JWT\RestrictedAlgorithmsJWT;
use Lindelius\JWT\JWT;
use PHPUnit\Framework\TestCase;

/**
 * Class JWTTest
 *
 * @author  Tom Lindelius <tom.lindelius@gmail.com>
 * @version 2018-07-24
 */
class JWTTest extends TestCase
{
    use TestDataProviders;

    /**
     * @expectedException \Lindelius\Jwt\Exception\DomainException
     * @expectedExceptionMessage Unsupported hashing algorithm.
     */
    public function testCreateWithUnsupportedAlgorithm()
    {
        new JWT('ABC123');
    }

    /**
     * @throws \Lindelius\JWT\Exception\InvalidJwtException
     * @expectedException \Lindelius\Jwt\Exception\DomainException
     * @expectedExceptionMessage Unsupported hashing algorithm.
     */
    public function testDecodeWithUnsupportedAlgorithm()
    {
        JWT::decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJBQkMxMjMifQ.eyJzb21lX2ZpZWxkIjoiYW55X3ZhbHVlIn0.92nuM1zI5H8lARijnJS_NOEe1at9C38kxJxpgHc9D6Q');
    }

    /**
     * @expectedException \Lindelius\Jwt\Exception\DomainException
     * @expectedExceptionMessage Disallowed hashing algorithm.
     */
    public function testCreateWithDisallowedAlgorithm()
    {
        new RestrictedAlgorithmsJWT('HS512');
    }

    /**
     * @throws \Lindelius\JWT\Exception\InvalidJwtException
     * @expectedException \Lindelius\Jwt\Exception\DomainException
     * @expectedExceptionMessage Disallowed hashing algorithm.
     */
    public function testDecodeWithDisallowedAlgorithm()
    {
        RestrictedAlgorithmsJWT::decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJzb21lX2ZpZWxkIjoiYW55X3ZhbHVlIn0.Up6KufPyr5SQVacgwVRfrcPRg1uav5cMsn2z41XxZ7s');
    }

    /**
     * @param mixed $key
     * @expectedException \Lindelius\JWT\Exception\InvalidJwtException
     * @expectedExceptionMessage Invalid key.
     * @dataProvider             invalidKeyProvider
     */
    public function testDecodeWithInvalidKey($key)
    {
        $decodedJwt = JWT::decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lX2ZpZWxkIjoiYW55X3ZhbHVlIn0.yQz7d3ZjXJ508tZedOxG3aZPEUVltphXrGFz6lE6Jhk');
        $decodedJwt->verify($key);
    }

    /**
     * @param mixed $key
     * @expectedException \Lindelius\JWT\Exception\InvalidJwtException
     * @expectedExceptionMessage Invalid key.
     * @dataProvider             invalidKeyProvider
     */
    public function testEncodeWithInvalidKey($key)
    {
        $jwt = new JWT();
        $jwt->setClaim('some_field', 'any_value');
        $jwt->encode($key);
    }

    /**
     * @param mixed $algorithm
     * @expectedException \Lindelius\JWT\Exception\InvalidArgumentException
     * @expectedExceptionMessage Invalid hashing algorithm.
     * @dataProvider             invalidAlgorithmProvider
     */
    public function testCreateWithInvalidAlgorithm($algorithm)
    {
        new JWT($algorithm);
    }

    /**
     * @throws \Lindelius\JWT\Exception\InvalidJwtException
     * @expectedException \Lindelius\JWT\Exception\InvalidArgumentException
     * @expectedExceptionMessage Invalid hashing algorithm.
     */
    public function testDecodeWithInvalidAlgorithm()
    {
        JWT::decode('eyJ0eXAiOiJKV1QiLCJhbGciOjEzMzd9.eyJzb21lX2ZpZWxkIjoiYW55X3ZhbHVlIn0.q4UyVTIKIamLj8ZvlaQMO_yUblMXHwJ_k3qgeGzrnO0');
    }

    /**
     * @param  mixed $hash
     * @throws \Lindelius\JWT\Exception\InvalidJwtException
     * @expectedException \Lindelius\JWT\Exception\InvalidArgumentException
     * @expectedExceptionMessage Invalid JWT.
     * @dataProvider             invalidHashProvider
     */
    public function testDecodeWithInvalidHash($hash)
    {
        JWT::decode($hash);
    }

    /**
     * @expectedException \Lindelius\JWT\Exception\InvalidJwtException
     * @expectedExceptionMessage Unexpected number of JWT segments.
     */
    public function testDecodeMalformedJWT()
    {
        JWT::decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lX2ZpZWxkIjoiYW55X3ZhbHVlIn0');
    }

    /**
     * @expectedException \Lindelius\JWT\Exception\InvalidJwtException
     * @expectedExceptionMessage Invalid key.
     */
    public function testDecodeWithIncorrectKeyId()
    {
        $keys = ['correct_kid' => 'my_key'];

        $jwt = new JWT(null, ['kid' => 'wrong_kid']);
        $jwt->setClaim('some_field', 'any_value');

        $decodedJwt = JWT::decode($jwt->encode('my_key'));
        $decodedJwt->verify($keys);
    }

    /**
     * @throws \Lindelius\JWT\Exception\InvalidJwtException
     */
    public function testFullLifeCycleHS256()
    {
        $jwt = new JWT('HS256');
        $jwt->setClaim('some_field', 'any_value');
        $jwt->encode('my_key');

        $decodedJwt = JWT::decode($jwt->getHash());
        $decodedJwt->verify('my_key');

        $this->assertEquals('any_value', $decodedJwt->getClaim('some_field'));
    }

    /**
     * @throws \Lindelius\JWT\Exception\InvalidJwtException
     */
    public function testFullLifeCycleHS384()
    {
        $jwt = new JWT('HS384');
        $jwt->setClaim('some_field', 'any_value');
        $jwt->encode('my_key');

        $decodedJwt = JWT::decode($jwt->getHash());
        $decodedJwt->verify('my_key');

        $this->assertEquals('any_value', $decodedJwt->getClaim('some_field'));
    }

    /**
     * @throws \Lindelius\JWT\Exception\InvalidJwtException
     */
    public function testFullLifeCycleHS512()
    {
        $jwt = new JWT('HS512');
        $jwt->setClaim('some_field', 'any_value');
        $jwt->encode('my_key');

        $decodedJwt = JWT::decode($jwt->getHash());
        $decodedJwt->verify('my_key');

        $this->assertEquals('any_value', $decodedJwt->getClaim('some_field'));
    }

    /**
     * @throws \Lindelius\JWT\Exception\InvalidJwtException
     */
    public function testFullLifeCycleRS256()
    {
        $privateKey = null;
        $resource   = openssl_pkey_new();

        openssl_pkey_export($resource, $privateKey);

        $publicKey = openssl_pkey_get_details($resource)['key'];

        $jwt = new JWT('RS256');
        $jwt->setClaim('some_field', 'any_value');
        $jwt->encode($privateKey);

        $decodedJwt = JWT::decode($jwt->getHash());
        $decodedJwt->verify($publicKey);

        $this->assertEquals('any_value', $decodedJwt->getClaim('some_field'));
    }

    /**
     * @throws \Lindelius\JWT\Exception\InvalidJwtException
     */
    public function testFullLifeCycleRS384()
    {
        $privateKey = null;
        $resource   = openssl_pkey_new();

        openssl_pkey_export($resource, $privateKey);

        $publicKey = openssl_pkey_get_details($resource)['key'];

        $jwt = new JWT('RS384');
        $jwt->setClaim('some_field', 'any_value');
        $jwt->encode($privateKey);

        $decodedJwt = JWT::decode($jwt->getHash());
        $decodedJwt->verify($publicKey);

        $this->assertEquals('any_value', $decodedJwt->getClaim('some_field'));
    }

    /**
     * @throws \Lindelius\JWT\Exception\InvalidJwtException
     */
    public function testFullLifeCycleRS512()
    {
        $privateKey = null;
        $resource   = openssl_pkey_new();

        openssl_pkey_export($resource, $privateKey);

        $publicKey = openssl_pkey_get_details($resource)['key'];

        $jwt = new JWT('RS512');
        $jwt->setClaim('some_field', 'any_value');
        $jwt->encode($privateKey);

        $decodedJwt = JWT::decode($jwt->getHash());
        $decodedJwt->verify($publicKey);

        $this->assertEquals('any_value', $decodedJwt->getClaim('some_field'));
    }

    /**
     * @throws \Lindelius\JWT\Exception\InvalidJwtException
     */
    public function testDecodeAndVerifyWithValidSignature()
    {
        $jwt = JWT::decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lX2ZpZWxkIjoiYW55X3ZhbHVlIn0.yQz7d3ZjXJ508tZedOxG3aZPEUVltphXrGFz6lE6Jhk');
        $jwt->verify('my_key');

        $this->assertEquals('any_value', $jwt->getClaim('some_field'));
    }

    /**
     * @throws \Lindelius\JWT\Exception\InvalidJwtException
     * @expectedException \Lindelius\JWT\Exception\InvalidSignatureException
     */
    public function testDecodeAndVerifyWithInvalidSignature()
    {
        $jwt = JWT::decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lX2ZpZWxkIjoiYW55X3ZhbHVlIn0.JUKQhsQPFfq8fQMkOmJ2x_w3NrEhVZNcYg52vn-GREE');
        $jwt->verify('my_key');
    }

    /**
     * @throws \Lindelius\JWT\Exception\InvalidJwtException
     * @expectedException \Lindelius\JWT\Exception\JsonException
     * @expectedExceptionMessage Unable to decode the given JSON string
     */
    public function testDecodeTokenWithInvalidJson()
    {
        JWT::decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.U29tZXRoaW5nIG90aGVyIHRoYW4gSlNPTg.yQz7d3ZjXJ508tZedOxG3aZPEUVltphXrGFz6lE6Jhk');
    }

    public function testIteratorImplementation()
    {
        $jwt = new JWT();

        $jwt->setClaim('a', 1);
        $jwt->setClaim('b', 2);
        $jwt->setClaim('c', 3);

        /**
         * Get all of the JWT's claims using the iterator implementation.
         */
        $claims = [];

        foreach ($jwt as $claim => $value) {
            $claims[$claim] = $value;
        }

        $this->assertEquals($jwt->a, $claims['a'] ?? 'missing_value');
        $this->assertEquals($jwt->b, $claims['b'] ?? 'missing_value');
        $this->assertEquals($jwt->c, $claims['c'] ?? 'missing_value');
    }
}
