<?php

namespace Lindelius\JWT\Benchmarks;

use Lindelius\JWT\Exception\Exception as JwtException;
use Lindelius\JWT\JWT;

/**
 * Class Benchmark
 */
abstract class Benchmark
{
    /**
     * @var string
     */
    public static $algorithm;

    /**
     * @var string
     */
    public static $audience = 'https://myapp.tld';

    /**
     * @var string
     */
    public static $encodedJwt;

    /**
     * @var string
     */
    public static $publicKey;

    /**
     * @var string
     */
    public static $privateKey;

    /**
     * Benchmarks the decoding process.
     *
     * @return void
     * @throws JwtException
     */
    public function benchDecode()
    {
        $decodedJwt = JWT::decode(static::$encodedJwt);
        $decodedJwt->verify(static::$publicKey, static::$audience);
    }

    /**
     * Benchmarks the encoding process.
     *
     * @return void
     * @throws JwtException
     */
    public function benchEncode()
    {
        static::getEncodedJwt(static::$algorithm, static::$privateKey);
    }

    /**
     * @return void
     * @throws JwtException
     */
    public function init()
    {
        /**
         * Create an encoded JWT to use when benchmarking the decoding process.
         */
        if (empty(static::$encodedJwt)) {
            static::$encodedJwt = static::getEncodedJwt(
                static::$algorithm,
                static::$privateKey
            );
        }
    }

    /**
     * Creates and encodes a JWT using a given algorithm and a given key.
     *
     * @param  string $algorithm
     * @param  string $key
     * @return string
     * @throws JwtException
     */
    public static function getEncodedJwt($algorithm, $key)
    {
        $jwt = new JWT($algorithm);

        $jwt->aud = static::$audience;
        $jwt->exp = time() + (60 * 20);
        $jwt->iat = time();
        $jwt->nbf = time();
        $jwt->sub = '0a1b2c3d4e5f6a7b8c9d0e1f';

        return $jwt->encode($key);
    }
}
