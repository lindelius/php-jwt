<?php

namespace Lindelius\JWT\Tests;

use Lindelius\JWT\Tests\JWT\TestJWT;
use PHPUnit\Framework\TestCase;

/**
 * Class JWTTest
 */
class JWTTest extends TestCase
{
    use TestDataProviders;

    /**
     * @throws \Lindelius\JWT\Exception\Exception
     * @expectedException \Lindelius\Jwt\Exception\DomainException
     * @expectedExceptionMessage Unsupported hashing algorithm.
     */
    public function testCreateWithUnsupportedAlgorithm()
    {
        $jwt = new TestJWT('ABC123');
        $jwt->encode('my_key');
    }

    /**
     * @throws \Lindelius\JWT\Exception\Exception
     * @expectedException \Lindelius\Jwt\Exception\DomainException
     * @expectedExceptionMessage Unsupported hashing algorithm.
     */
    public function testDecodeWithUnsupportedAlgorithm()
    {
        $jwt = TestJWT::decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJBQkMxMjMifQ.eyJzb21lX2ZpZWxkIjoiYW55X3ZhbHVlIn0.92nuM1zI5H8lARijnJS_NOEe1at9C38kxJxpgHc9D6Q');
        $jwt->verify('my_key');
    }

    /**
     * @param mixed $key
     * @throws \Lindelius\JWT\Exception\Exception
     * @expectedException \Lindelius\JWT\Exception\InvalidJwtException
     * @expectedExceptionMessage Invalid key.
     * @dataProvider             invalidKeyProvider
     */
    public function testDecodeWithInvalidKey($key)
    {
        $decodedJwt = TestJWT::decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lX2ZpZWxkIjoiYW55X3ZhbHVlIn0.yQz7d3ZjXJ508tZedOxG3aZPEUVltphXrGFz6lE6Jhk');
        $decodedJwt->verify($key);
    }

    /**
     * @param mixed $key
     * @throws \Lindelius\JWT\Exception\Exception
     * @expectedException \Lindelius\JWT\Exception\InvalidJwtException
     * @expectedExceptionMessage Invalid key.
     * @dataProvider             invalidKeyProvider
     */
    public function testEncodeWithInvalidKey($key)
    {
        $jwt = new TestJWT('HS256');
        $jwt->setClaim('some_field', 'any_value');
        $jwt->encode($key);
    }

    /**
     * @param mixed $algorithm
     * @throws \Lindelius\JWT\Exception\Exception
     * @expectedException \TypeError
     * @dataProvider invalidAlgorithmProvider
     */
    public function testCreateWithInvalidAlgorithm($algorithm)
    {
        $jwt = new TestJWT($algorithm);
        $jwt->encode('my_key');
    }

    /**
     * @throws \Lindelius\JWT\Exception\Exception
     * @expectedException \Lindelius\JWT\Exception\DomainException
     * @expectedExceptionMessage Unsupported hashing algorithm.
     */
    public function testDecodeWithInvalidAlgorithm()
    {
        $jwt = TestJWT::decode('eyJ0eXAiOiJKV1QiLCJhbGciOjEzMzd9.eyJzb21lX2ZpZWxkIjoiYW55X3ZhbHVlIn0.q4UyVTIKIamLj8ZvlaQMO_yUblMXHwJ_k3qgeGzrnO0');
        $jwt->verify('my_key');
    }

    /**
     * @param  mixed $hash
     * @throws \Lindelius\JWT\Exception\Exception
     * @expectedException \TypeError
     * @dataProvider invalidHashProvider
     */
    public function testDecodeWithInvalidHash($hash)
    {
        TestJWT::decode($hash);
    }

    /**
     * @throws \Lindelius\JWT\Exception\Exception
     * @expectedException \Lindelius\JWT\Exception\InvalidJwtException
     * @expectedExceptionMessage Unexpected number of JWT segments.
     */
    public function testDecodeMalformedJWT()
    {
        TestJWT::decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lX2ZpZWxkIjoiYW55X3ZhbHVlIn0');
    }

    /**
     * @throws \Lindelius\JWT\Exception\Exception
     * @expectedException \Lindelius\JWT\Exception\InvalidJwtException
     * @expectedExceptionMessage Invalid key.
     */
    public function testDecodeWithIncorrectKeyId()
    {
        $keys = ['correct_kid' => 'my_key'];

        $jwt = new TestJWT('HS256', ['kid' => 'wrong_kid']);
        $jwt->setClaim('some_field', 'any_value');

        $decodedJwt = TestJWT::decode($jwt->encode('my_key'));
        $decodedJwt->verify($keys);
    }

    /**
     * @throws \Lindelius\JWT\Exception\Exception
     * @throws \RuntimeException
     * @throws \SebastianBergmann\RecursionContext\Exception
     */
    public function testFullLifeCycleHS256()
    {
        $jwt = new TestJWT('HS256');
        $jwt->setClaim('some_field', 'any_value');
        $jwt->encode('my_key');

        $decodedJwt = TestJWT::decode($jwt->getHash());
        $decodedJwt->verify('my_key');

        $this->assertEquals('any_value', $decodedJwt->getClaim('some_field'));
    }

    /**
     * @throws \Lindelius\JWT\Exception\Exception
     * @throws \RuntimeException
     * @throws \SebastianBergmann\RecursionContext\Exception
     */
    public function testFullLifeCycleHS384()
    {
        $jwt = new TestJWT('HS384');
        $jwt->setClaim('some_field', 'any_value');
        $jwt->encode('my_key');

        $decodedJwt = TestJWT::decode($jwt->getHash());
        $decodedJwt->verify('my_key');

        $this->assertEquals('any_value', $decodedJwt->getClaim('some_field'));
    }

    /**
     * @throws \Lindelius\JWT\Exception\Exception
     * @throws \RuntimeException
     * @throws \SebastianBergmann\RecursionContext\Exception
     */
    public function testFullLifeCycleHS512()
    {
        $jwt = new TestJWT('HS512');
        $jwt->setClaim('some_field', 'any_value');
        $jwt->encode('my_key');

        $decodedJwt = TestJWT::decode($jwt->getHash());
        $decodedJwt->verify('my_key');

        $this->assertEquals('any_value', $decodedJwt->getClaim('some_field'));
    }

    /**
     * @throws \Lindelius\JWT\Exception\Exception
     * @throws \RuntimeException
     * @throws \SebastianBergmann\RecursionContext\Exception
     */
    public function testFullLifeCycleRS256()
    {
        $privateKey = null;
        $resource   = openssl_pkey_new();

        openssl_pkey_export($resource, $privateKey);

        $publicKey = openssl_pkey_get_details($resource)['key'];

        $jwt = new TestJWT('RS256');
        $jwt->setClaim('some_field', 'any_value');
        $jwt->encode($privateKey);

        $decodedJwt = TestJWT::decode($jwt->getHash());
        $decodedJwt->verify($publicKey);

        $this->assertEquals('any_value', $decodedJwt->getClaim('some_field'));
    }

    /**
     * @throws \Lindelius\JWT\Exception\Exception
     * @throws \RuntimeException
     * @throws \SebastianBergmann\RecursionContext\Exception
     */
    public function testFullLifeCycleRS384()
    {
        $privateKey = null;
        $resource   = openssl_pkey_new();

        openssl_pkey_export($resource, $privateKey);

        $publicKey = openssl_pkey_get_details($resource)['key'];

        $jwt = new TestJWT('RS384');
        $jwt->setClaim('some_field', 'any_value');
        $jwt->encode($privateKey);

        $decodedJwt = TestJWT::decode($jwt->getHash());
        $decodedJwt->verify($publicKey);

        $this->assertEquals('any_value', $decodedJwt->getClaim('some_field'));
    }

    /**
     * @throws \Lindelius\JWT\Exception\Exception
     * @throws \RuntimeException
     * @throws \SebastianBergmann\RecursionContext\Exception
     */
    public function testFullLifeCycleRS512()
    {
        $privateKey = null;
        $resource   = openssl_pkey_new();

        openssl_pkey_export($resource, $privateKey);

        $publicKey = openssl_pkey_get_details($resource)['key'];

        $jwt = new TestJWT('RS512');
        $jwt->setClaim('some_field', 'any_value');
        $jwt->encode($privateKey);

        $decodedJwt = TestJWT::decode($jwt->getHash());
        $decodedJwt->verify($publicKey);

        $this->assertEquals('any_value', $decodedJwt->getClaim('some_field'));
    }

    /**
     * @throws \Lindelius\JWT\Exception\Exception
     * @throws \RuntimeException
     * @throws \SebastianBergmann\RecursionContext\Exception
     */
    public function testDecodeAndVerifyWithValidSignature()
    {
        $jwt = TestJWT::decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lX2ZpZWxkIjoiYW55X3ZhbHVlIn0.yQz7d3ZjXJ508tZedOxG3aZPEUVltphXrGFz6lE6Jhk');
        $jwt->verify('my_key');

        $this->assertEquals('any_value', $jwt->getClaim('some_field'));
    }

    /**
     * @throws \Lindelius\JWT\Exception\Exception
     * @throws \RuntimeException
     * @expectedException \Lindelius\JWT\Exception\InvalidSignatureException
     */
    public function testDecodeAndVerifyWithInvalidSignature()
    {
        $jwt = TestJWT::decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lX2ZpZWxkIjoiYW55X3ZhbHVlIn0.JUKQhsQPFfq8fQMkOmJ2x_w3NrEhVZNcYg52vn-GREE');
        $jwt->verify('my_key');
    }

    /**
     * @throws \Lindelius\JWT\Exception\Exception
     * @throws \RuntimeException
     * @expectedException \Lindelius\JWT\Exception\JsonException
     * @expectedExceptionMessage Unable to decode the given JSON string
     */
    public function testDecodeTokenWithInvalidJson()
    {
        TestJWT::decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.U29tZXRoaW5nIG90aGVyIHRoYW4gSlNPTg.yQz7d3ZjXJ508tZedOxG3aZPEUVltphXrGFz6lE6Jhk');
    }

    /**
     * @throws \RuntimeException
     * @throws \SebastianBergmann\RecursionContext\Exception
     */
    public function testIteratorImplementation()
    {
        $jwt = new TestJWT('HS256');

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
