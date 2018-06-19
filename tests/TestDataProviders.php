<?php

namespace Lindelius\JWT\Tests;

/**
 * Trait TestDataProviders
 *
 * @author  Tom Lindelius <tom.lindelius@gmail.com>
 * @version 2018-06-16
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
            [1],
            [0.07],
            [null],
            [new \stdClass()],
            [''],
            [false],
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
            [1],
            [0.07],
            [new \stdClass()],
            [false],
            [curl_init()],
        ];
    }
}
