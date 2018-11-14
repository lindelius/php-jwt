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
 */
abstract class JWT implements Iterator
{
    /**
     * Leeway time (in seconds) to account for clock skew between servers.
     *
     * @var int
     */
    protected static $leeway = 0;

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
     * @param  string      $algorithm
     * @param  array       $header
     * @param  string|null $signature
     * @return void
     */
    public function __construct(string $algorithm, array $header = [], ?string $signature = null)
    {
        $this->algorithm = strtoupper(trim($algorithm));
        $this->signature = $signature;

        // Make sure the JWT's header include all of the required fields
        $this->header = array_merge(
            $header,
            [
                'typ' => 'JWT',
                'alg' => $algorithm,
            ]
        );
    }

    /**
     * Gets the current value for a given claim.
     *
     * @param  string $claim
     * @return mixed
     */
    public function __get(string $claim)
    {
        return $this->getClaim($claim);
    }

    /**
     * Checks whether a given claim has been set.
     *
     * @param  string $claim
     * @return bool
     */
    public function __isset(string $claim): bool
    {
        return isset($this->payload[$claim]);
    }

    /**
     * Sets a new value for a given claim.
     *
     * @param  string $claim
     * @param  mixed  $value
     * @return void
     */
    public function __set(string $claim, $value): void
    {
        $this->setClaim($claim, $value);
    }

    /**
     * Convert the JWT to its string representation, i.e. return its hash.
     *
     * @return string
     */
    public function __toString(): string
    {
        return (string) $this->getHash();
    }

    /**
     * Unsets a given claim.
     *
     * @param  string $claimName
     * @return void
     */
    public function __unset(string $claimName): void
    {
        if (array_key_exists($claimName, $this->payload)) {
            // Clear the hash since it will no longer be valid
            $this->hash = null;
        }

        unset($this->payload[$claimName]);
    }

    /**
     * Gets the value of the "current" claim in the payload array.
     *
     * @return mixed
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
     * @throws DomainException
     * @throws InvalidKeyException
     * @throws JsonException
     * @throws RuntimeException
     */
    public function encode($key): string
    {
        if (empty($key) || (!is_string($key) && !is_resource($key))) {
            throw new InvalidKeyException('Invalid key.');
        }

        $segments = [];

        // Build the JWT's main segments
        $segments[] = url_safe_base64_encode(static::jsonEncode($this->header));
        $segments[] = url_safe_base64_encode(static::jsonEncode($this->payload));

        // Sign the JWT with the given key
        $dataToSign = implode('.', $segments);

        if (!method_exists($this, 'encodeWith' . $this->algorithm)) {
            throw new DomainException('Unsupported hashing algorithm.');
        }

        $this->signature = call_user_func_array(
            [$this, 'encodeWith' . $this->algorithm],
            [$dataToSign, $key]
        );

        if (empty($this->signature)) {
            throw new RuntimeException('Unable to sign the JWT.');
        }

        $segments[] = url_safe_base64_encode($this->signature);

        // Piece together the segments and return the resulting hash
        $this->hash = implode('.', $segments);

        return $this->hash;
    }

    /**
     * Gets the current value of a given claim.
     *
     * @param  string $name
     * @return mixed
     */
    public function getClaim(string $name)
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
    public function getClaims(): array
    {
        return $this->getPayload();
    }

    /**
     * Gets the JWT's hash.
     *
     * @return string|null
     */
    public function getHash(): ?string
    {
        return $this->hash;
    }

    /**
     * Gets the JWT's header.
     *
     * @return array
     */
    public function getHeader(): array
    {
        return $this->header;
    }

    /**
     * Gets the current value for a given header field.
     *
     * @param  string $name
     * @return mixed
     */
    public function getHeaderField(string $name)
    {
        if (isset($this->header[$name])) {
            return $this->header[$name];
        }

        return null;
    }

    /**
     * Gets the JWT's payload.
     *
     * @return array
     */
    public function getPayload(): array
    {
        return $this->payload;
    }

    /**
     * Gets the name of the "current" claim in the payload array.
     *
     * @return string|null
     */
    public function key(): ?string
    {
        return key($this->payload);
    }

    /**
     * Advances the iterator to the "next" claim in the payload array.
     *
     * @return void
     */
    public function next(): void
    {
        next($this->payload);
    }

    /**
     * Rewinds the payload iterator.
     *
     * @return void
     */
    public function rewind(): void
    {
        reset($this->payload);
    }

    /**
     * Sets a new value for a given claim.
     *
     * @param  string $name
     * @param  mixed  $value
     * @return void
     */
    public function setClaim(string $name, $value): void
    {
        $this->payload[$name] = $value;

        // Clear the generated hash since it's no longer valid
        $this->hash = null;
    }

    /**
     * Checks whether the current position in the payload array is valid.
     *
     * @return bool
     */
    public function valid(): bool
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
     * @throws DomainException
     * @throws InvalidJwtException
     * @throws JsonException
     */
    public function verify($key, ?string $audience = null): bool
    {
        // If the app is using multiple keys, attempt to find the correct one
        if (is_array($key) || $key instanceof ArrayAccess) {
            $kid = $this->getHeaderField('kid');

            if ($kid !== null) {
                if (!is_string($kid) && !is_numeric($kid)) {
                    throw new InvalidJwtException(
                        'Invalid "kid" value. Unable to lookup secret key.'
                    );
                }

                $key = array_key_exists($kid, $key) ? $key[$kid] : null;
            }
        }

        if (empty($key) || (!is_string($key) && !is_resource($key))) {
            throw new InvalidKeyException('Invalid key.');
        }

        // Verify the given signature
        if (empty($this->signature)) {
            throw new InvalidSignatureException('Invalid signature.');
        }

        $dataToSign = sprintf(
            '%s.%s',
            url_safe_base64_encode(static::jsonEncode($this->getHeader())),
            url_safe_base64_encode(static::jsonEncode($this->getPayload()))
        );

        if (!method_exists($this, 'verifyWith' . $this->algorithm)) {
            throw new DomainException('Unsupported hashing algorithm.');
        }

        $verified = call_user_func_array(
            [$this, 'verifyWith' . $this->algorithm],
            [$this->signature, $dataToSign, $key]
        );

        if (!$verified) {
            throw new InvalidSignatureException('Invalid JWT signature.');
        }

        // Validate the audience constraint, if included
        if (isset($this->aud)) {
            // Make sure the audience claim is set to a valid value
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

        // Validate the "expires at" time constraint, if included
        if (isset($this->exp)) {
            if (!is_numeric($this->exp)) {
                throw new InvalidJwtException('Invalic "exp" value.');
            } elseif ((time() - static::$leeway) >= (float) $this->exp) {
                throw new ExpiredJwtException('The JWT has expired.');
            }
        }

        // Validate the "issued at" time constraint, if included
        if (isset($this->iat)) {
            if (!is_numeric($this->iat)) {
                throw new InvalidJwtException('Invalid "iat" value.');
            } elseif ((time() + static::$leeway) < (float) $this->iat) {
                throw new BeforeValidException('The JWT is not yet valid.');
            }
        }

        // Validate the "not before" time constraint, if included
        if (isset($this->nbf)) {
            if (!is_numeric($this->nbf)) {
                throw new InvalidJwtException('Invalid "nbf" value.');
            } elseif ((time() + static::$leeway) < (float) $this->nbf) {
                throw new BeforeValidException('The JWT is not yet valid.');
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
     * @throws InvalidArgumentException
     */
    public static function create($header = [], $payload = [], ?string $signature = null)
    {
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

        // Create, populate, and then return the resulting JWT object
        $jwt = new static(
            $header['alg'] ?? null,
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
     * @throws InvalidArgumentException
     * @throws InvalidJwtException
     * @throws JsonException
     */
    public static function decode(string $jwt)
    {
        $segments = explode('.', $jwt);

        if (count($segments) !== 3) {
            throw new InvalidJwtException('Unexpected number of JWT segments.');
        }

        // Decode the JWT's segments
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

        // Validate the decoded values
        if (empty($header)) {
            throw new InvalidJwtException('Invalid JWT header.');
        }

        if ($header->typ !== 'JWT') {
            throw new InvalidJwtException('Invalid JWT type.');
        }

        if (empty($payload)) {
            throw new InvalidJwtException('Invalid JWT payload.');
        }

        return static::create($header, $payload, $decodedSignature);
    }

    /**
     * Gets the leeway time (in seconds).
     *
     * @return int
     */
    public static function getLeewayTime(): int
    {
        return static::$leeway;
    }

    /**
     * Decodes a given JSON string.
     *
     * @param  string $json
     * @return mixed
     * @throws JsonException
     */
    protected static function jsonDecode(string $json)
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
     * Converts the given data to its JSON representation.
     *
     * @param  mixed $data
     * @return string
     * @throws JsonException
     */
    protected static function jsonEncode($data): string
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
