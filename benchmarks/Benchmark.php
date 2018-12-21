<?php

namespace Lindelius\JWT\Benchmarks;

use Lindelius\JWT\Exception\Exception as JwtException;

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
     * Benchmark the decoding process.
     *
     * @return void
     * @throws JwtException
     */
    public function benchDecode(): void
    {
        $decodedJwt = BenchmarkJWT::decode(static::$encodedJwt);
        $decodedJwt->verify(static::$publicKey, static::$audience);
    }

    /**
     * Benchmark the encoding process.
     *
     * @return void
     * @throws JwtException
     */
    public function benchEncode(): void
    {
        static::getEncodedJwt(static::$algorithm, static::$privateKey);
    }

    /**
     * Initialize the benchmark.
     *
     * @return void
     * @throws JwtException
     */
    public function init(): void
    {
        // Create an encoded JWT to use when benchmarking the decoding process
        if (empty(static::$encodedJwt)) {
            static::$encodedJwt = static::getEncodedJwt(
                static::$algorithm,
                static::$privateKey
            );
        }
    }

    /**
     * Create and encode a JWT using a given algorithm and a given key.
     *
     * @param  string $algorithm
     * @param  string $key
     * @return string
     * @throws JwtException
     */
    public static function getEncodedJwt($algorithm, $key): string
    {
        $jwt = new BenchmarkJWT($algorithm);

        $jwt->aud = static::$audience;
        $jwt->exp = time() + (60 * 20);
        $jwt->iat = time();
        $jwt->nbf = time();
        $jwt->sub = '0a1b2c3d4e5f6a7b8c9d0e1f';

        return $jwt->encode($key);
    }
}
