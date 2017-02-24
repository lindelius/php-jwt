<?php

namespace Lindelius\JWT;

use DomainException;
use InvalidArgumentException;
use Lindelius\JWT\Exception\BeforeValidException;
use Lindelius\JWT\Exception\ExpiredException;
use Lindelius\JWT\Exception\InvalidException;
use Lindelius\JWT\Exception\InvalidSignatureException;
use Lindelius\JWT\Exception\JsonException;
use Lindelius\JWT\Exception\RuntimeException;

/**
 * Class JWT
 *
 * @author  Tom Lindelius <tom.lindelius@vivamedia.se>
 * @version 2017-02-24
 */
class JWT
{
    /**
     * The hashing algorithm to use when encoding the JWT.
     *
     * @var string
     */
    private $algorithm;

    /**
     * The default hashing algorithm.
     *
     * @var string
     */
    protected static $defaultAlgorithm = 'HS256';

    /**
     * The JWT hash.
     *
     * @var string|null
     */
    private $hash = null;

    /**
     * The JWT header.
     *
     * @var array
     */
    private $header = [];

    /**
     * The secret key used when signing the JWT.
     *
     * @var string|resource
     */
    private $key;

    /**
     * Leeway time (in seconds) to account for clock skew.
     *
     * @var int
     */
    protected static $leeway = 0;

    /**
     * The JWT payload.
     *
     * @var array
     */
    private $payload = [];

    /**
     * Supported hashing algorithms.
     *
     * @var array
     */
    protected static $supportedAlgorithms = [
        'HS256' => ['hash_hmac', 'SHA256'],
        'HS512' => ['hash_hmac', 'SHA512'],
        'HS384' => ['hash_hmac', 'SHA384'],
        'RS256' => ['openssl', 'SHA256']
    ];

    /**
     * Constructor for JWT objects.
     *
     * @param string|resource $key
     * @param string|null     $algorithm
     * @param array           $header
     * @throws DomainException
     * @throws InvalidArgumentException
     */
    public function __construct($key, $algorithm = null, array $header = [])
    {
        if (empty($key) || (!is_string($key) && !is_resource($key))) {
            throw new InvalidArgumentException('Invalid key.');
        }

        $this->key = $key;

        if (empty($algorithm)) {
            $algorithm = static::$defaultAlgorithm;
        }

        if (empty(static::$supportedAlgorithms[$algorithm])) {
            throw new DomainException('Unsupported algorithm.');
        }

        $this->algorithm = $algorithm;
        $this->header    = array_merge([
            'typ' => 'JWT',
            'alg' => $algorithm
        ], $header);
    }

    /**
     * Gets the current value for a given payload field.
     *
     * @param  string $field
     * @return mixed
     * @see    http://php.net/manual/en/language.oop5.overloading.php#object.get
     */
    public function __get($field)
    {
        if (strpos($field, '.') === false) {
            return isset($this->payload[$field]) ? $this->payload[$field] : null;
        }

        $data     = $this->payload;
        $segments = explode('.', $field);

        foreach ($segments as $segment) {
            if (!array_key_exists($segment, $data)) {
                return null;
            }

            $data = $data[$segment];
        }

        return $data;
    }

    /**
     * Sets a new value for a given payload field.
     *
     * @param  string $field
     * @param  mixed  $newValue
     * @see    http://php.net/manual/en/language.oop5.overloading.php#object.set
     * @throws InvalidArgumentException
     */
    public function __set($field, $newValue)
    {
        $newPayload    = &$this->payload;
        $segments      = explode('.', $field);
        $firstSegment  = $segments[0];
        $payloadBackup = isset($this->payload[$firstSegment]) ? $this->payload[$firstSegment] : null;

        try {
            foreach ($segments as $segment) {
                if (trim($segment) === '') {
                    throw new InvalidArgumentException('The payload field name is invalid.');
                }

                if (isset($newPayload) && !is_array($newPayload)) {
                    $newPayload = [];
                }

                $newPayload = &$newPayload[$segment];
            }

            $newPayload = $newValue;
            $this->hash = null;
        } catch (InvalidArgumentException $e) {
            $this->payload[$firstSegment] = $payloadBackup;
            throw $e;
        }
    }

    /**
     * Decodes a JWT hash and returns the resulting object.
     *
     * @param string          $jwt
     * @param string|resource $key
     * @param array           $allowedAlgorithms
     * @return static
     * @throws BeforeValidException
     * @throws ExpiredException
     * @throws InvalidArgumentException
     * @throws InvalidException
     * @throws InvalidSignatureException
     */
    public static function decode($jwt, $key, array $allowedAlgorithms = [])
    {
        if (empty($jwt) || !is_string($jwt)) {
            throw new InvalidArgumentException('Invalid JWT.');
        }

        if (empty($key) || (!is_string($key) && !is_resource($key))) {
            throw new InvalidArgumentException('Invalid key.');
        }

        $segments = explode('.', $jwt);

        if (count($segments) !== 3) {
            throw new InvalidException('Unexpected number of JWT segments.');
        }

        /**
         * Decode the JWT.
         */
        $dataToSign = sprintf('%s.%s', $segments[0], $segments[1]);
        $header     = static::jsonDecode(url_safe_base64_decode($segments[0]));
        $payload    = static::jsonDecode(url_safe_base64_decode($segments[1]));
        $signature  = url_safe_base64_decode($segments[2]);

        if (empty($header)) {
            throw new InvalidException('Invalid JWT header.');
        }

        if (empty($payload)) {
            throw new InvalidException('Invalid JWT payload.');
        }

        if (empty($allowedAlgorithms)) {
            $allowedAlgorithms = array_keys(static::$supportedAlgorithms);
        }

        if (empty($header['alg']) || !in_array($header['alg'], $allowedAlgorithms)) {
            throw new InvalidException('Invalid hashing algorithm.');
        }

        /**
         * Verify the JWT signature.
         */
        $functionName      = static::$supportedAlgorithms[$header['alg']][0];
        $functionAlgorithm = static::$supportedAlgorithms[$header['alg']][1];
        $verified          = false;

        if ($functionName === 'hash_hmac') {
            $hash     = hash_hmac($functionAlgorithm, $dataToSign, $key, true);
            $verified = hash_equals($signature, $hash);
        } elseif ($functionName === 'openssl') {
            $success = openssl_verify($dataToSign, $signature, $key, $functionAlgorithm);

            if ($success === 1) {
                $verified = true;
            } elseif ($success === -1) {
                throw new RuntimeException('OpenSSL failed to verify the signature.');
            }
        }

        if (!$verified) {
            throw new InvalidSignatureException('Invalid JWT signature.');
        }

        /**
         * Verify any time restriction that may have been set for the JWT.
         */
        $timestamp = time();

        if (isset($payload['nbf']) && is_numeric($payload['nbf']) && (float) $payload['nbf'] > ($timestamp + static::$leeway)) {
            throw new BeforeValidException('The JWT is not yet valid.');
        }

        if (isset($payload['iat']) && is_numeric($payload['iat']) && (float) $payload['nbf'] > ($timestamp + static::$leeway)) {
            throw new BeforeValidException('The JWT is not yet valid.');
        }

        if (isset($payload['exp']) && is_numeric($payload['exp']) && (float) $payload['exp'] <= ($timestamp - static::$leeway)) {
            throw new ExpiredException('The JWT has expired.');
        }

        return static::newInstance($key, $header, $payload);
    }

    /**
     * Encodes the JWT object and returns the resulting hash.
     *
     * @return string
     * @throws JsonException
     * @throws RuntimeException
     */
    public function encode()
    {
        $segments   = [];
        $segments[] = url_safe_base64_encode(static::jsonEncode($this->header));
        $segments[] = url_safe_base64_encode(static::jsonEncode($this->payload));

        /**
         * Sign the JWT.
         */
        $dataToSign        = implode('.', $segments);
        $functionName      = static::$supportedAlgorithms[$this->algorithm][0];
        $functionAlgorithm = static::$supportedAlgorithms[$this->algorithm][1];
        $signature         = null;

        if ($functionName === 'hash_hmac') {
            $signature = hash_hmac($functionAlgorithm, $dataToSign, $this->key, true);
        } elseif ($functionName === 'openssl') {
            openssl_sign($dataToSign, $signature, $this->key, $functionAlgorithm);
        }

        if (empty($signature)) {
            throw new RuntimeException('Unable to sign the JWT.');
        }

        $segments[] = url_safe_base64_encode($signature);

        $this->hash = implode('.', $segments);

        return $this->hash;
    }

    /**
     * Gets the JWT hash, if the JWT has been encoded.
     *
     * @return string|null
     */
    public function getHash()
    {
        return $this->hash;
    }

    /**
     * Encodes the given data to a JSON string.
     *
     * @param mixed $data
     * @return string
     * @throws JsonException
     */
    protected function jsonEncode($data)
    {
        $json = json_encode($data);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new JsonException(sprintf(
                'Unable to encode the given data (%s).',
                json_last_error()
            ));
        }

        return $json;
    }

    /**
     * Decodes a given JSON string.
     *
     * @param string $json
     * @return mixed
     * @throws JsonException
     */
    protected function jsonDecode($json)
    {
        $data = json_decode($json, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new JsonException(sprintf(
                'Unable to decode the given JSON string (%s).',
                json_last_error()
            ));
        }

        return $data;
    }

    /**
     * Gets a new instance of the model.
     *
     * @param string|resource $key
     * @param array           $header
     * @param array           $payload
     * @return static
     * @throws InvalidArgumentException
     */
    public static function newInstance($key, array $header = [], array $payload = [])
    {
        if (empty($header['alg']) || !is_string($header['alg']) || empty(static::$supportedAlgorithms[$header['alg']])) {
            throw new InvalidArgumentException('Invalid hashing algorithm.');
        }

        $jwt = new static($key, $header['alg'], $header);

        foreach ($payload as $field => $value) {
            $jwt->{$field} = $value;
        }

        return $jwt;
    }
}
