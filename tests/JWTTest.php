<?php

namespace Lindelius\JWT\Tests;

use Lindelius\JWT\Exception\InvalidJwtException;
use Lindelius\JWT\Exception\InvalidSignatureException;
use Lindelius\JWT\Exception\JwtException;
use Lindelius\JWT\Tests\JWT\TestJWT;
use PHPUnit\Framework\TestCase;
use TypeError;

final class JWTTest extends TestCase
{
    use TestDataProviders;

    /**
     * @return void
     * @throws JwtException
     */
    public function testCreateWithUnsupportedAlgorithm(): void
    {
        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('Unsupported algorithm ("ABC123").');

        $jwt = TestJWT::create('ABC123');
        $jwt->encode('my_key');
    }

    /**
     * @return void
     * @throws JwtException
     */
    public function testDecodeWithUnsupportedAlgorithm(): void
    {
        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('Unsupported algorithm ("ABC123").');

        $jwt = TestJWT::decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJBQkMxMjMifQ.eyJzb21lX2ZpZWxkIjoiYW55X3ZhbHVlIn0.92nuM1zI5H8lARijnJS_NOEe1at9C38kxJxpgHc9D6Q');
        $jwt->verify('my_key');
    }

    /**
     * @dataProvider invalidKeyProvider
     * @param  mixed $key
     * @return void
     * @throws JwtException
     */
    public function testDecodeWithInvalidKey($key): void
    {
        $this->expectException(InvalidJwtException::class);
        $this->expectExceptionMessage('Invalid key.');

        $decodedJwt = TestJWT::decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lX2ZpZWxkIjoiYW55X3ZhbHVlIn0.yQz7d3ZjXJ508tZedOxG3aZPEUVltphXrGFz6lE6Jhk');
        $decodedJwt->verify($key);
    }

    /**
     * @dataProvider invalidKeyProvider
     * @param  mixed $key
     * @return void
     * @throws JwtException
     */
    public function testEncodeWithInvalidKey($key): void
    {
        $this->expectException(InvalidJwtException::class);
        $this->expectExceptionMessage('Invalid key.');

        $jwt = TestJWT::create(TestJWT::HS256);
        $jwt->setClaim('some_field', 'any_value');
        $jwt->encode($key);
    }

    /**
     * @dataProvider invalidAlgorithmProvider
     * @param  mixed $algorithm
     * @return void
     * @throws JwtException
     */
    public function testCreateWithInvalidAlgorithm($algorithm): void
    {
        $this->expectException(TypeError::class);

        $jwt = TestJWT::create($algorithm);
        $jwt->encode('my_key');
    }

    /**
     * @return void
     * @throws JwtException
     */
    public function testDecodeWithInvalidAlgorithm(): void
    {
        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('Unsupported algorithm ("1337").');

        $jwt = TestJWT::decode('eyJ0eXAiOiJKV1QiLCJhbGciOjEzMzd9.eyJzb21lX2ZpZWxkIjoiYW55X3ZhbHVlIn0.q4UyVTIKIamLj8ZvlaQMO_yUblMXHwJ_k3qgeGzrnO0');
        $jwt->verify('my_key');
    }

    /**
     * @dataProvider invalidHashProvider
     * @param  mixed $hash
     * @return void
     * @throws JwtException
     */
    public function testDecodeWithInvalidHash($hash): void
    {
        $this->expectException(TypeError::class);

        TestJWT::decode($hash);
    }

    /**
     * @return void
     * @throws JwtException
     */
    public function testDecodeMalformedJWT(): void
    {
        $this->expectException(InvalidJwtException::class);
        $this->expectExceptionMessage('Unexpected number of JWT segments.');

        TestJWT::decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lX2ZpZWxkIjoiYW55X3ZhbHVlIn0');
    }

    /**
     * @return void
     * @throws JwtException
     */
    public function testDecodeWithIncorrectKeyId(): void
    {
        $this->expectException(InvalidJwtException::class);
        $this->expectExceptionMessage('Unable to find the correct decode key.');

        $keys = ['correct_kid' => 'my_key'];

        $jwt = TestJWT::create(TestJWT::HS256);
        $jwt->setHeaderField('kid', 'wrong_kid');
        $jwt->setClaim('some_field', 'any_value');

        $decodedJwt = TestJWT::decode($jwt->encode('my_key'));
        $decodedJwt->verify($keys);
    }

    /**
     * @return void
     * @throws JwtException
     */
    public function testFullLifeCycleHS256(): void
    {
        $jwt = TestJWT::create(TestJWT::HS256);
        $jwt->setClaim('some_field', 'any_value');
        $jwt->encode('my_key');

        $decodedJwt = TestJWT::decode($jwt->getHash());
        $decodedJwt->verify('my_key');

        $this->assertEquals('any_value', $decodedJwt->getClaim('some_field'));
    }

    /**
     * @return void
     * @throws JwtException
     */
    public function testFullLifeCycleHS384(): void
    {
        $jwt = TestJWT::create(TestJWT::HS384);
        $jwt->setClaim('some_field', 'any_value');
        $jwt->encode('my_key');

        $decodedJwt = TestJWT::decode($jwt->getHash());
        $decodedJwt->verify('my_key');

        $this->assertEquals('any_value', $decodedJwt->getClaim('some_field'));
    }

    /**
     * @return void
     * @throws JwtException
     */
    public function testFullLifeCycleHS512(): void
    {
        $jwt = TestJWT::create(TestJWT::HS512);
        $jwt->setClaim('some_field', 'any_value');
        $jwt->encode('my_key');

        $decodedJwt = TestJWT::decode($jwt->getHash());
        $decodedJwt->verify('my_key');

        $this->assertEquals('any_value', $decodedJwt->getClaim('some_field'));
    }

    /**
     * @return void
     * @throws JwtException
     */
    public function testFullLifeCycleRS256(): void
    {
        $privateKey = null;
        $resource = openssl_pkey_new();

        openssl_pkey_export($resource, $privateKey);

        $publicKey = openssl_pkey_get_details($resource)['key'];

        $jwt = TestJWT::create(TestJWT::RS256);
        $jwt->setClaim('some_field', 'any_value');
        $jwt->encode($privateKey);

        $decodedJwt = TestJWT::decode($jwt->getHash());
        $decodedJwt->verify($publicKey);

        $this->assertEquals('any_value', $decodedJwt->getClaim('some_field'));
    }

    /**
     * @return void
     * @throws JwtException
     */
    public function testFullLifeCycleRS384(): void
    {
        $privateKey = null;
        $resource = openssl_pkey_new();

        openssl_pkey_export($resource, $privateKey);

        $publicKey = openssl_pkey_get_details($resource)['key'];

        $jwt = TestJWT::create(TestJWT::RS384);
        $jwt->setClaim('some_field', 'any_value');
        $jwt->encode($privateKey);

        $decodedJwt = TestJWT::decode($jwt->getHash());
        $decodedJwt->verify($publicKey);

        $this->assertEquals('any_value', $decodedJwt->getClaim('some_field'));
    }

    /**
     * @return void
     * @throws JwtException
     */
    public function testFullLifeCycleRS512(): void
    {
        $privateKey = null;
        $resource = openssl_pkey_new();

        openssl_pkey_export($resource, $privateKey);

        $publicKey = openssl_pkey_get_details($resource)['key'];

        $jwt = TestJWT::create(TestJWT::RS512);
        $jwt->setClaim('some_field', 'any_value');
        $jwt->encode($privateKey);

        $decodedJwt = TestJWT::decode($jwt->getHash());
        $decodedJwt->verify($publicKey);

        $this->assertEquals('any_value', $decodedJwt->getClaim('some_field'));
    }

    /**
     * @return void
     * @throws JwtException
     */
    public function testDecodeAndVerifyWithValidSignature(): void
    {
        $jwt = TestJWT::decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lX2ZpZWxkIjoiYW55X3ZhbHVlIn0.yQz7d3ZjXJ508tZedOxG3aZPEUVltphXrGFz6lE6Jhk');
        $jwt->verify('my_key');

        $this->assertEquals('any_value', $jwt->getClaim('some_field'));
    }

    /**
     * @return void
     * @throws JwtException
     */
    public function testDecodeAndVerifyWithInvalidSignature(): void
    {
        $this->expectException(InvalidSignatureException::class);

        $jwt = TestJWT::decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzb21lX2ZpZWxkIjoiYW55X3ZhbHVlIn0.JUKQhsQPFfq8fQMkOmJ2x_w3NrEhVZNcYg52vn-GREE');
        $jwt->verify('my_key');
    }

    /**
     * @return void
     * @throws JwtException
     */
    public function testDecodeTokenWithInvalidJson(): void
    {
        $this->expectException(JwtException::class);
        $this->expectExceptionMessage('Unable to decode the given JSON string');

        TestJWT::decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.U29tZXRoaW5nIG90aGVyIHRoYW4gSlNPTg.yQz7d3ZjXJ508tZedOxG3aZPEUVltphXrGFz6lE6Jhk');
    }
}
