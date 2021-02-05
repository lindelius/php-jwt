<?php

namespace Lindelius\JWT\Tests;

use stdClass;

trait TestDataProviders
{
    /**
     * Gets invalid key values.
     *
     * @return array[]
     */
    public function invalidKeyProvider(): array
    {
        return [
            [1],
            [0.07],
            [null],
            [new stdClass()],
            [false],
        ];
    }

    /**
     * Gets invalid hash values.
     *
     * @return array[]
     */
    public function invalidHashProvider(): array
    {
        return [
            [['an_array']],
            [null],
            [new stdClass()],
        ];
    }

    /**
     * Gets invalid algorithm values.
     *
     * @return array[]
     */
    public function invalidAlgorithmProvider(): array
    {
        return [
            [['an_array']],
            [new stdClass()],
        ];
    }
}
