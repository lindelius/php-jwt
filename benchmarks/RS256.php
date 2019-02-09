<?php

namespace Lindelius\JWT\Benchmarks;

use Lindelius\JWT\Exception\Exception as JwtException;

/**
 * Class RS256
 *
 * @BeforeMethods({"init"})
 * @Iterations(3)
 * @Revs(1000)
 * @Warmup(10)
 */
class RS256 extends Benchmark
{
    /**
     * @var string
     */
    public static $algorithm = 'RS256';

    /**
     * Initialize the benchmark.
     *
     * @return void
     * @throws JwtException
     */
    public function init(): void
    {
        // Generate RSA keys to use when benchmarking
        if (empty(static::$privateKey) || empty(static::$publicKey)) {
            $resource = openssl_pkey_new();

            openssl_pkey_export($resource, static::$privateKey);

            static::$publicKey = openssl_pkey_get_details($resource)['key'];
        }

        parent::init();
    }
}
