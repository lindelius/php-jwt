<?php

namespace Lindelius\JWT;

use ArrayAccess;
use Iterator;
use Lindelius\JWT\Exception\BeforeValidException;
use Lindelius\JWT\Exception\DomainException;
use Lindelius\JWT\Exception\ExpiredJwtException;
use Lindelius\JWT\Exception\InvalidArgumentException;
use Lindelius\JWT\Exception\InvalidJwtException;
use Lindelius\JWT\Exception\InvalidSignatureException;
use Lindelius\JWT\Exception\JsonException;
use Lindelius\JWT\Exception\RuntimeException;

/**
 * Class JWT
 *
 * @author  Tom Lindelius <tom.lindelius@gmail.com>
 * @version 2017-09-25
 */
class JWT implements Iterator
{
    /**
     * The hashing algorithm to use when encoding the JWT.
     *
     * @var string
     */
    private $algorithm;

    /**
     * The allowed hashing algorithms. If empty, all supported algorithms are
     * considered allowed.
     *
     * @var array
     */
    protected static $allowedAlgorithms = [];

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

        if ($algorithm !== null && !is_string($algorithm)) {
            throw new InvalidArgumentException('Invalid hashing algorithm.');
        }

        if (empty($algorithm)) {
            $algorithm = static::$defaultAlgorithm;
        }

        if (empty(static::$supportedAlgorithms[$algorithm]) || !in_array($algorithm, static::getAllowedAlgorithms())) {
            throw new DomainException('Unsupported hashing algorithm.');
        }

        $this->algorithm = $algorithm;

        unset($header['alg']);
        $this->header = array_merge([
            'typ' => 'JWT',
            'alg' => $algorithm
        ], $header);
    }

    /**
     * Gets the current value for a given claim.
     *
     * @param string $claimName
     * @return mixed
     * @see http://php.net/manual/en/language.oop5.overloading.php#object.get
     */
    public function __get($claimName)
    {
        return $this->getClaim($claimName);
    }

    /**
     * Checks whether a given claim has been set.
     *
     * @param string $claimName
     * @return bool
     * @see http://php.net/manual/en/language.oop5.overloading.php#object.isset
     */
    public function __isset($claimName)
    {
        return isset($this->payload[$claimName]);
    }

    /**
     * Sets a new value for a given claim.
     *
     * @param string $claimName
     * @param mixed  $newValue
     * @see http://php.net/manual/en/language.oop5.overloading.php#object.set
     */
    public function __set($claimName, $newValue)
    {
        $this->setClaim($claimName, $newValue);
    }

    /**
     * Convert the JWT to its string representation.
     *
     * @return string
     */
    public function __toString()
    {
        return (string) $this->getHash();
    }

    /**
     * Unsets a given claim.
     *
     * @param string $claimName
     * @see http://php.net/manual/en/language.oop5.overloading.php#object.unset
     */
    public function __unset($claimName)
    {
        unset($this->payload[$claimName]);
    }

    /**
     * Creates a new instance of the model.
     *
     * @param string|resource $key
     * @param array           $header
     * @param array           $payload
     * @return static
     * @throws DomainException
     * @throws InvalidArgumentException
     */
    public static function create($key, array $header = [], array $payload = [])
    {
        $algorithm = isset($header['alg']) ? $header['alg'] : null;
        $jwt       = new static($key, $algorithm, $header);

        foreach ($payload as $claimName => $claimValue) {
            $jwt->{$claimName} = $claimValue;
        }

        return $jwt;
    }

    /**
     * Gets the value of the "current" claim in the payload array.
     *
     * @return mixed
     * @see http://php.net/manual/en/iterator.current.php
     */
    public function current()
    {
        return current($this->payload);
    }

    /**
     * Decodes a JWT hash and returns the resulting object.
     *
     * @param string          $jwt
     * @param string|resource $key
     * @param bool            $verify
     * @return static
     * @throws DomainException
     * @throws InvalidArgumentException
     * @throws InvalidJwtException
     * @throws JsonException
     */
    public static function decode($jwt, $key, $verify = true)
    {
        if (empty($jwt) || !is_string($jwt)) {
            throw new InvalidArgumentException('Invalid JWT.');
        }

        $segments = explode('.', $jwt);

        if (count($segments) !== 3) {
            throw new InvalidJwtException('Unexpected number of JWT segments.');
        }

        $header  = static::jsonDecode(url_safe_base64_decode($segments[0]));
        $payload = static::jsonDecode(url_safe_base64_decode($segments[1]));

        if (empty($header)) {
            throw new InvalidJwtException('Invalid JWT header.');
        }

        if (empty($payload)) {
            throw new InvalidJwtException('Invalid JWT payload.');
        }

        if (is_array($key) || $key instanceof ArrayAccess) {
            if (isset($header['kid']) && isset($key[$header['kid']])) {
                $key = $key[$header['kid']];
            } else {
                throw new InvalidJwtException('Invalid "kid" value. Unable to lookup secret key.');
            }
        }

        if (empty($key) || (!is_string($key) && !is_resource($key))) {
            throw new InvalidArgumentException('Invalid key.');
        }

        $jwt = static::create($key, $header, $payload);

        if ($verify) {
            $jwt->verify($segments[2]);
        }

        return $jwt;
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
     * Gets the allowed hashing algorithms.
     *
     * @return array
     */
    public static function getAllowedAlgorithms()
    {
        if (empty(static::$allowedAlgorithms)) {
            return array_keys(static::$supportedAlgorithms);
        }

        return static::$allowedAlgorithms;
    }

    /**
     * Gets the current value of a given claim.
     *
     * @param string $name
     * @return mixed|null
     */
    public function getClaim($name)
    {
        if (isset($this->payload[$name])) {
            return $this->payload[$name];
        }

        return null;
    }

    /**
     * Gets the set of claims included in the JWT.
     *
     * @return array
     */
    public function getClaims()
    {
        return $this->getPayload();
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
     * Gets the JWT header.
     *
     * @return array
     */
    public function getHeader()
    {
        return $this->header;
    }

    /**
     * Gets the current value for a given header field.
     *
     * @param string $name
     * @return mixed|null
     */
    public function getHeaderField($name)
    {
        if (isset($this->header[$name])) {
            return $this->header[$name];
        }

        return null;
    }

    /**
     * Gets the JWT payload.
     *
     * @return array
     */
    public function getPayload()
    {
        return $this->payload;
    }

    /**
     * Encodes the given data to a JSON string.
     *
     * @param mixed $data
     * @return string
     * @throws JsonException
     */
    protected static function jsonEncode($data)
    {
        $json  = json_encode($data);
        $error = json_last_error();

        if ($error !== JSON_ERROR_NONE) {
            throw new JsonException(sprintf(
                'Unable to encode the given data (%s).',
                $error
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
    protected static function jsonDecode($json)
    {
        $data  = json_decode($json, true);
        $error = json_last_error();

        if ($error !== JSON_ERROR_NONE) {
            throw new JsonException(sprintf(
                'Unable to decode the given JSON string (%s).',
                $error
            ));
        }

        return $data;
    }

    /**
     * Gets the name of the "current" claim in the payload array.
     *
     * @return string
     * @see http://php.net/manual/en/iterator.key.php
     */
    public function key()
    {
        return key($this->payload);
    }

    /**
     * Advances the iterator to the "next" claim in the payload array.
     *
     * @see http://php.net/manual/en/iterator.next.php
     */
    public function next()
    {
        next($this->payload);
    }

    /**
     * Rewinds the payload iterator.
     *
     * @see http://php.net/manual/en/iterator.rewind.php
     */
    public function rewind()
    {
        reset($this->payload);
    }

    /**
     * Sets a new value for a given claim.
     *
     * @param string $name
     * @param mixed  $value
     */
    public function setClaim($name, $value)
    {
        $this->payload[$name] = $value;

        /**
         * If the JWT has been previously encoded, clear the generated hash
         * since it's no longer valid.
         */
        $this->hash = null;
    }

    /**
     * Checks whether the current position in the payload array is valid.
     *
     * @return bool
     * @see http://php.net/manual/en/iterator.valid.php
     */
    public function valid()
    {
        $key = key($this->payload);

        return $key !== null && $key !== false;
    }

    /**
     * Verifies that the JWT is correctly formatted and that a given signature
     * is valid.
     *
     * @param string $rawSignature
     * @return bool
     * @throws BeforeValidException
     * @throws ExpiredJwtException
     * @throws InvalidSignatureException
     * @throws JsonException
     */
    public function verify($rawSignature)
    {
        $dataToSign = sprintf(
            '%s.%s',
            url_safe_base64_encode(static::jsonEncode($this->getHeader())),
            url_safe_base64_encode(static::jsonEncode($this->getPayload()))
        );

        $functionName      = static::$supportedAlgorithms[$this->algorithm][0];
        $functionAlgorithm = static::$supportedAlgorithms[$this->algorithm][1];
        $signature         = url_safe_base64_decode($rawSignature);
        $verified          = false;

        if ($functionName === 'hash_hmac') {
            $hash     = hash_hmac($functionAlgorithm, $dataToSign, $this->key, true);
            $verified = hash_equals($signature, $hash);
        } elseif ($functionName === 'openssl') {
            $success = openssl_verify($dataToSign, $signature, $this->key, $functionAlgorithm);

            if ($success === 1) {
                $verified = true;
            }
        }

        if (!$verified) {
            throw new InvalidSignatureException('Invalid JWT signature.');
        }

        $now = time();

        if (isset($this->nbf) && is_numeric($this->nbf) && (float) $this->nbf > ($now + static::$leeway)) {
            throw new BeforeValidException('The JWT is not yet valid.');
        }

        if (isset($this->iat) && is_numeric($this->iat) && (float) $this->iat > ($now + static::$leeway)) {
            throw new BeforeValidException('The JWT is not yet valid.');
        }

        if (isset($this->exp) && is_numeric($this->exp) && (float) $this->exp <= ($now - static::$leeway)) {
            throw new ExpiredJwtException('The JWT has expired.');
        }

        return true;
    }
}
