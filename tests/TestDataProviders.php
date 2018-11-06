<?php

namespace Lindelius\JWT\Tests;

/**
 * Trait TestDataProviders
 */
trait TestDataProviders
{
    /**
     * Gets invalid key values.
     *
     * @return array[]
     */
    public function invalidKeyProvider()
    {
        return [
            [1],
            [0.07],
            [null],
            [new \stdClass()],
            [''],
            [false],
        ];
    }

    /**
     * Gets invalid hash values.
     *
     * @return array[]
     */
    public function invalidHashProvider()
    {
        return [
            [['an_array']],
            [null],
            [new \stdClass()],
            [curl_init()],
        ];
    }

    /**
     * Gets invalid algorithm values.
     *
     * @return array[]
     */
    public function invalidAlgorithmProvider()
    {
        return [
            [['an_array']],
            [new \stdClass()],
            [curl_init()],
        ];
    }
}
