<?php

define('HMAC_KEY', 'my_key');
define('ITERATIONS', 100000);

require __DIR__ . '/vendor/autoload.php';

$averageTimes = [];
$encodedJwts  = [];

/**
 * Generate the RSA keys needed for performance testing the OpenSSL algorithms.
 */
if (!extension_loaded('openssl')) {
    die('The required PHP extension "openssl" is not enabled.');
}

$privateKey = null;
$resource   = openssl_pkey_new();

openssl_pkey_export($resource, $privateKey);

$publicKey = openssl_pkey_get_details($resource)['key'];

unset($resource);

/**
 * For each of the supported algorithms, find the average time (in milliseconds)
 * for populating and encoding a JWT.
 */
foreach (Lindelius\JWT\JWT::getSupportedAlgorithms() as $algorithm) {

    /**
     * Select the correct key for the current algorithm.
     */
    if (strpos($algorithm, 'RS') !== false) {
        $key = $privateKey;
    } else {
        $key = HMAC_KEY;
    }

    $averageTime = null;

    for ($i = 1; $i <= ITERATIONS; $i++) {

        $startTime = microtime(true);

        $jwt = new Lindelius\JWT\JWT($algorithm);

        $jwt->aud = 'https://myapp.tld';
        $jwt->exp = time() + (60 * 20);
        $jwt->iat = time();
        $jwt->nbf = time();
        $jwt->sub = '0a1b2c3d4e5f6a7b8c9d0e1f';

        $jwt->encode($key);

        $milliseconds = 1000 * (microtime(true) - $startTime);

        /**
         * Update the average time for the current algorithm.
         */
        if ($averageTime === null) {
            $averageTime = $milliseconds;
        } else {
            $averageTime = $averageTime + (($milliseconds - $averageTime) / $i);
        }

        /**
         * Save the encoded JWT so that we can use it when performance testing
         * the decode and verify functionality.
         */
        if (empty($encodedJwts[$algorithm])) {
            $encodedJwts[$algorithm] = $jwt->getHash();
        }

    }

    $averageTimes[$algorithm]['encoding'] = round($averageTime, 4);
    $averageTimes[$algorithm]['total']    = round($averageTime, 4);

}

/**
 * For each of the supported algorithms, find the average time (in milliseconds)
 * for decoding and verifying a JWT.
 */
foreach ($encodedJwts as $algorithm => $jwt) {

    /**
     * Select the correct key for the current algorithm.
     */
    if (strpos($algorithm, 'RS') !== false) {
        $key = $publicKey;
    } else {
        $key = HMAC_KEY;
    }

    $averageTime = null;

    for ($i = 1; $i <= ITERATIONS; $i++) {

        $startTime = microtime(true);

        $decodedJwt = Lindelius\JWT\JWT::decode($jwt);
        $decodedJwt->verify($key, 'https://myapp.tld');

        $milliseconds = 1000 * (microtime(true) - $startTime);

        /**
         * Update the average time for the current algorithm.
         */
        if ($averageTime === null) {
            $averageTime = $milliseconds;
        } else {
            $averageTime = $averageTime + (($milliseconds - $averageTime) / $i);
        }

    }

    $averageTimes[$algorithm]['decoding'] = round($averageTime, 4);
    $averageTimes[$algorithm]['total']    = round(
        $averageTimes[$algorithm]['total'] + $averageTime,
        4
    );

}

/**
 * Sort the results by average total time.
 */
uasort($averageTimes, function ($a, $b) {

    if ($a['total'] == $b['total']) {
        return 0;
    }

    return ($a['total'] < $b['total']) ? -1 : 1;

});

/**
 * Print out the results.
 */
echo "\nLINDELIUS/PHP-JWT";
echo "\nAverage execution times (in milliseconds).\n";

foreach ($averageTimes as $algorithm => $timeData) {

    echo "\n- " . $algorithm;
    echo sprintf(
        "\n  Encoding: %f ms    Decoding: %f ms\n",
        $timeData['encoding'],
        $timeData['decoding']
    );

}

echo "\n";
