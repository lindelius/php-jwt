<?php

namespace Lindelius\JWT;

use ArrayAccess;
use Iterator;
use Lindelius\JWT\Exception\BeforeValidException;
use Lindelius\JWT\Exception\DomainException;
use Lindelius\JWT\Exception\ExpiredJwtException;
use Lindelius\JWT\Exception\InvalidArgumentException;
use Lindelius\JWT\Exception\InvalidAudienceException;
use Lindelius\JWT\Exception\InvalidJwtException;
use Lindelius\JWT\Exception\InvalidKeyException;
use Lindelius\JWT\Exception\InvalidSignatureException;
use Lindelius\JWT\Exception\JsonException;
use Lindelius\JWT\Exception\RuntimeException;

/**
 * Class JWT
 *
 * @author  Tom Lindelius <tom.lindelius@gmail.com>
 * @version 2018-07-24
 */
class JWT implements Iterator
{
    /**
     * The allowed hashing algorithms. If empty, all supported algorithms are
     * considered allowed.
     *
     * @var string[]
     */
    protected static $allowedAlgorithms = [];

    /**
     * The default hashing algorithm.
     *
     * @var string
     */
    protected static $defaultAlgorithm = 'HS256';

    /**
     * Leeway time (in seconds) to account for clock skew.
     *
     * @var int
     */
    protected static $leeway = 0;

    /**
     * Supported hashing algorithms.
     *
     * @var array[]
     */
    protected static $supportedAlgorithms = [
        'HS256' => ['hash_hmac', 'SHA256'],
        'HS384' => ['hash_hmac', 'SHA384'],
        'HS512' => ['hash_hmac', 'SHA512'],
        'RS256' => ['openssl', 'SHA256'],
        'RS384' => ['openssl', 'SHA384'],
        'RS512' => ['openssl', 'SHA512'],
    ];

    /**
     * The hashing algorithm to use when encoding the JWT.
     *
     * @var string
     */
    private $algorithm;

    /**
     * The JWT's hash.
     *
     * @var string|null
     */
    private $hash = null;

    /**
     * The JWT's header.
     *
     * @var array
     */
    private $header = [];

    /**
     * The JWT's payload.
     *
     * @var array
     */
    private $payload = [];

    /**
     * The JWT's signature.
     *
     * @var string|null
     */
    private $signature = null;

    /**
     * JWT constructor.
     *
     * @param  string|null $algorithm
     * @param  array       $header
     * @param  string|null $signature
     * @throws DomainException
     * @throws InvalidArgumentException
     */
    public function __construct($algorithm = null, array $header = [], $signature = null)
    {
        if ($signature !== null && !is_string($signature)) {
            throw new InvalidArgumentException('Invalid signature.');
        }

        if ($algorithm !== null && !is_string($algorithm)) {
            throw new InvalidArgumentException('Invalid hashing algorithm.');
        }

        if (empty($algorithm)) {
            $algorithm = static::$defaultAlgorithm;
        }

        if (!in_array($algorithm, static::getSupportedAlgorithms())) {
            throw new DomainException('Unsupported hashing algorithm.');
        }

        if (!in_array($algorithm, static::getAllowedAlgorithms())) {
            throw new DomainException('Disallowed hashing algorithm.');
        }

        $this->algorithm = $algorithm;
        $this->signature = $signature;

        /**
         * Make sure the JWT's header include the required fields.
         */
        unset($header['alg']);
        $this->header = array_merge(
            [
                'typ' => 'JWT',
                'alg' => $algorithm,
            ],
            $header
        );
    }

    /**
     * Gets the current value for a given claim.
     *
     * @param  string $claim
     * @return mixed
     * @see    http://php.net/manual/en/language.oop5.overloading.php#object.get
     */
    public function __get($claim)
    {
        return $this->getClaim($claim);
    }

    /**
     * Checks whether a given claim has been set.
     *
     * @param  string $claim
     * @return bool
     * @see    http://php.net/manual/en/language.oop5.overloading.php#object.isset
     */
    public function __isset($claim)
    {
        return isset($this->payload[$claim]);
    }

    /**
     * Sets a new value for a given claim.
     *
     * @param string $claim
     * @param mixed  $value
     * @see   http://php.net/manual/en/language.oop5.overloading.php#object.set
     */
    public function __set($claim, $value)
    {
        $this->setClaim($claim, $value);
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
     * @see   http://php.net/manual/en/language.oop5.overloading.php#object.unset
     */
    public function __unset($claimName)
    {
        if (array_key_exists($claimName, $this->payload)) {
            /**
             * If the claim exists and the JWT has been previously encoded,
             * clear the generated hash since it is no longer valid.
             */
            $this->hash = null;
        }

        unset($this->payload[$claimName]);
    }

    /**
     * Gets the value of the "current" claim in the payload array.
     *
     * @return mixed
     * @see    http://php.net/manual/en/iterator.current.php
     */
    public function current()
    {
        return current($this->payload);
    }

    /**
     * Encodes the JWT object and returns the resulting hash.
     *
     * @param  mixed $key
     * @return string
     * @throws InvalidKeyException
     * @throws JsonException
     * @throws RuntimeException
     */
    public function encode($key)
    {
        if (empty($key) || (!is_string($key) && !is_resource($key))) {
            throw new InvalidKeyException('Invalid key.');
        }

        $segments   = [];
        $segments[] = url_safe_base64_encode(static::jsonEncode($this->header));
        $segments[] = url_safe_base64_encode(static::jsonEncode($this->payload));

        /**
         * Sign the JWT with the given key.
         */
        $dataToSign = implode('.', $segments);
        $function   = static::$supportedAlgorithms[$this->algorithm][0];
        $algorithm  = static::$supportedAlgorithms[$this->algorithm][1];

        $this->signature = null;

        if ($function === 'hash_hmac') {
            $this->signature = hash_hmac($algorithm, $dataToSign, $key, true);
        } elseif ($function === 'openssl') {
            openssl_sign($dataToSign, $this->signature, $key, $algorithm);
        }

        if (empty($this->signature)) {
            throw new RuntimeException('Unable to sign the JWT.');
        }

        $segments[] = url_safe_base64_encode($this->signature);

        /**
         * If the JWT was successfully signed, piece together the segments and
         * return the resulting hash.
         */
        $this->hash = implode('.', $segments);

        return $this->hash;
    }

    /**
     * Gets the current value of a given claim.
     *
     * @param  string $name
     * @return mixed
     */
    public function getClaim($name)
    {
        if (isset($this->payload[$name])) {
            return $this->payload[$name];
        }

        return null;
    }

    /**
     * Gets the entire set of claims included in the JWT.
     *
     * @return array
     * @see    JWT::getPayload()
     */
    public function getClaims()
    {
        return $this->getPayload();
    }

    /**
     * Gets the JWT hash.
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
     * @param  string $name
     * @return mixed
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
     * Gets the name of the "current" claim in the payload array.
     *
     * @return string
     * @see    http://php.net/manual/en/iterator.key.php
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
         * since it is no longer valid.
         */
        $this->hash = null;
    }

    /**
     * Checks whether the current position in the payload array is valid.
     *
     * @return bool
     * @see    http://php.net/manual/en/iterator.valid.php
     */
    public function valid()
    {
        return $this->key() !== null && $this->key() !== false;
    }

    /**
     * Verifies that the JWT is correctly formatted and that the given signature
     * is valid.
     *
     * @param  mixed       $key
     * @param  string|null $audience
     * @return bool
     * @throws BeforeValidException
     * @throws ExpiredJwtException
     * @throws InvalidAudienceException
     * @throws InvalidJwtException
     * @throws InvalidKeyException
     * @throws InvalidSignatureException
     * @throws JsonException
     */
    public function verify($key, $audience = null)
    {
        /**
         * If the application is using multiple secret keys, attempt to look up
         * the correct key using the "kid" header field.
         */
        if (is_array($key) || $key instanceof ArrayAccess) {
            $kid = $this->getHeaderField('kid');

            if ($kid !== null) {
                if (!is_string($kid) && !is_numeric($kid)) {
                    throw new InvalidJwtException('Invalid "kid" value. Unable to lookup secret key.');
                }

                $key = array_key_exists($kid, $key) ? $key[$kid] : null;
            }
        }

        if (empty($key) || (!is_string($key) && !is_resource($key))) {
            throw new InvalidKeyException('Invalid key.');
        }

        /**
         * Validate the JWT's signature using the given key.
         */
        if (empty($this->signature)) {
            throw new InvalidSignatureException('Invalid signature.');
        }

        $dataToSign = sprintf(
            '%s.%s',
            url_safe_base64_encode(static::jsonEncode($this->getHeader())),
            url_safe_base64_encode(static::jsonEncode($this->getPayload()))
        );

        $algorithm = static::$supportedAlgorithms[$this->algorithm][1];
        $function  = static::$supportedAlgorithms[$this->algorithm][0];
        $verified  = false;

        if ($function === 'hash_hmac') {
            $hash = hash_hmac($algorithm, $dataToSign, $key, true);

            if (hash_equals($this->signature, $hash)) {
                $verified = true;
            }
        } elseif ($function === 'openssl') {
            $success = openssl_verify($dataToSign, $this->signature, $key, $algorithm);

            if ($success === 1) {
                $verified = true;
            }
        }

        if (!$verified) {
            throw new InvalidSignatureException('Invalid JWT signature.');
        }

        /**
         * Validate the audience constraint, if included.
         */
        if (isset($this->aud)) {
            /**
             * Make sure that the value of the audience claim is either a string
             * or an array of strings.
             */
            if (is_array($this->aud)) {
                $expectedKey = 0;

                foreach ($this->aud as $key => $aud) {
                    if ($key !== $expectedKey || !is_string($aud)) {
                        throw new InvalidJwtException('Invalid "aud" value.');
                    }

                    $expectedKey++;
                }

                $validAudiences = $this->aud;
            } elseif (is_string($this->aud)) {
                $validAudiences = [$this->aud];
            } else {
                throw new InvalidJwtException('Invalid "aud" value.');
            }

            if (!in_array($audience, $validAudiences)) {
                throw new InvalidAudienceException('Invalid JWT audience.');
            }
        }

        /**
         * Validate time constraints, if included.
         */
        if (isset($this->nbf)) {
            if (!is_numeric($this->nbf)) {
                throw new InvalidJwtException('Invalid "nbf" value.');
            } elseif ((time() + static::$leeway) < (float) $this->nbf) {
                throw new BeforeValidException('The JWT is not yet valid.');
            }
        }

        if (isset($this->iat)) {
            if (!is_numeric($this->iat)) {
                throw new InvalidJwtException('Invalid "iat" value.');
            } elseif ((time() + static::$leeway) < (float) $this->iat) {
                throw new BeforeValidException('The JWT is not yet valid.');
            }
        }

        if (isset($this->exp)) {
            if (!is_numeric($this->exp)) {
                throw new InvalidJwtException('Invalic "exp" value.');
            } elseif ((time() - static::$leeway) >= (float) $this->exp) {
                throw new ExpiredJwtException('The JWT has expired.');
            }
        }

        return true;
    }

    /**
     * Creates a new JWT instance.
     *
     * @param  array|object $header
     * @param  array|object $payload
     * @param  string|null  $signature
     * @return static
     * @throws DomainException
     * @throws InvalidArgumentException
     */
    public static function create($header = [], $payload = [], $signature = null)
    {
        /**
         * Make sure that both the header and the payload are given as either
         * arrays or objects, and, if they are objects, that they are converted
         * into associative arrays.
         */
        if (!is_array($header) && !is_object($header)) {
            throw new InvalidArgumentException('Invalid JWT header.');
        } else {
            $header = (array) $header;
        }

        if (!is_array($payload) && !is_object($payload)) {
            throw new InvalidArgumentException('Invalid JWT payload.');
        } else {
            $payload = (array) $payload;
        }

        /**
         * Create, populate, and then return the resulting JWT object.
         */
        $jwt = new static(
            isset($header['alg']) ? $header['alg'] : null,
            $header,
            $signature
        );

        foreach ($payload as $claim => $value) {
            $jwt->{$claim} = $value;
        }

        return $jwt;
    }

    /**
     * Decodes a JWT hash and returns the resulting object.
     *
     * @param  string $jwt
     * @return static
     * @throws DomainException
     * @throws InvalidArgumentException
     * @throws InvalidJwtException
     * @throws JsonException
     */
    public static function decode($jwt)
    {
        if (empty($jwt) || !is_string($jwt)) {
            throw new InvalidArgumentException('Invalid JWT.');
        }

        $segments = explode('.', $jwt);

        if (count($segments) !== 3) {
            throw new InvalidJwtException('Unexpected number of JWT segments.');
        }

        /**
         * If the format looks good, attempt to decode its individual segments.
         */
        if (false === ($decodedHeader = url_safe_base64_decode($segments[0]))) {
            throw new InvalidJwtException('Invalid header encoding.');
        }

        if (false === ($decodedPayload = url_safe_base64_decode($segments[1]))) {
            throw new InvalidJwtException('Invalid payload encoding.');
        }

        if (false === ($decodedSignature = url_safe_base64_decode($segments[2]))) {
            throw new InvalidJwtException('Invalid signature encoding.');
        }

        $header  = static::jsonDecode($decodedHeader);
        $payload = static::jsonDecode($decodedPayload);

        if (empty($header)) {
            throw new InvalidJwtException('Invalid JWT header.');
        }

        if (empty($payload)) {
            throw new InvalidJwtException('Invalid JWT payload.');
        }

        /**
         * If the entire JWT was successfully decoded, create and return a new
         * JWT instance populated with the decoded data.
         */
        return static::create($header, $payload, $decodedSignature);
    }

    /**
     * Gets the allowed hashing algorithms.
     *
     * @return array
     */
    public static function getAllowedAlgorithms()
    {
        if (empty(static::$allowedAlgorithms)) {
            return static::getSupportedAlgorithms();
        }

        return static::$allowedAlgorithms;
    }

    /**
     * Gets the leeway time (in seconds).
     *
     * @return int
     */
    public static function getLeewayTime()
    {
        return static::$leeway;
    }

    /**
     * Gets the supported hashing algorithms.
     *
     * @return array
     */
    public static function getSupportedAlgorithms()
    {
        return array_keys(static::$supportedAlgorithms);
    }

    /**
     * Decodes a given JSON string.
     *
     * @param  string $json
     * @return mixed
     * @throws JsonException
     */
    protected static function jsonDecode($json)
    {
        $data  = json_decode($json);
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
     * Encodes the given data to a JSON string.
     *
     * @param  mixed $data
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
}
