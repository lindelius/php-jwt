<?php

namespace Lindelius\JWT\Benchmarks;

use Lindelius\JWT\Exception\Exception as JwtException;

/**
 * Class HS512
 *
 * @BeforeMethods({"init"})
 * @Iterations(3)
 * @Revs(1000)
 * @Warmup(10)
 */
class HS512 extends Benchmark
{
    /**
     * @var string
     */
    public static $algorithm = 'HS512';

    /**
     * Initialize the benchmark.
     *
     * @return void
     * @throws JwtException
     */
    public function init(): void
    {
        // Set HMAC keys to use when benchmarking
        if (empty(static::$privateKey) || empty(static::$publicKey)) {
            static::$privateKey = 'MySuperSecretEncryptionKey';
            static::$publicKey  = 'MySuperSecretEncryptionKey';
        }

        parent::init();
    }
}
