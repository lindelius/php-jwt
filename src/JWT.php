<?php

namespace Lindelius\JWT;

use Lindelius\JWT\Exception\BeforeValidException;
use Lindelius\JWT\Exception\ExpiredJwtException;
use Lindelius\JWT\Exception\InvalidJwtException;
use Lindelius\JWT\Exception\InvalidKeyException;
use Lindelius\JWT\Exception\InvalidSignatureException;
use Lindelius\JWT\Exception\JwtException;
use Lindelius\JWT\Exception\UnsupportedAlgorithmException;

/**
 * An abstract base class for JWT models.
 */
abstract class JWT
{
    public const HS256 = 'HS256';
    public const HS384 = 'HS384';
    public const HS512 = 'HS512';

    public const RS256 = 'RS256';
    public const RS384 = 'RS384';
    public const RS512 = 'RS512';

    /**
     * Leeway time (in seconds) to account for clock skew between servers.
     *
     * @var int
     */
    public static $leeway = 0;

    /**
     * The algorithm to use when signing the JWT.
     *
     * @var string|null
     */
    private $algorithm;

    /**
     * The set of claims included with the JWT.
     *
     * @var array
     */
    private $claims = [];

    /**
     * The hash representation of the JWT.
     *
     * @var string|null
     */
    private $hash;

    /**
     * The header data included with the JWT.
     *
     * @var array
     */
    private $header = [];

    /**
     * Get the current value for a given claim.
     *
     * @param  string $claim
     * @return mixed
     */
    public function __get(string $claim)
    {
        return $this->getClaim($claim);
    }

    /**
     * Check whether a given claim has been set.
     *
     * @param  string $claim
     * @return bool
     */
    public function __isset(string $claim): bool
    {
        return isset($this->claims[$claim]);
    }

    /**
     * Set a new value for a given claim.
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
     * Get the string representation of the JWT (i.e. its hash).
     *
     * @return string
     */
    public function __toString(): string
    {
        return (string) $this->hash;
    }

    /**
     * Unset a given claim.
     *
     * @param  string $claimName
     * @return void
     */
    public function __unset(string $claimName): void
    {
        // If the claim exists, clear the hash since it will no longer be valid
        if (array_key_exists($claimName, $this->claims)) {
            $this->hash = null;
        }

        unset($this->claims[$claimName]);
    }

    /**
     * Encode the JWT object and return the resulting hash.
     *
     * @param  mixed $key
     * @return string
     * @throws JwtException
     * @throws UnsupportedAlgorithmException
     */
    public function encode($key): string
    {
        $segments = [];

        // Build the main segments of the JWT
        $segments[] = url_safe_base64_encode(static::jsonEncode($this->header));
        $segments[] = url_safe_base64_encode(static::jsonEncode($this->claims));

        // Sign the JWT with the given key
        $segments[] = url_safe_base64_encode(
            $this->generateSignature($key, implode('.', $segments))
        );

        return $this->hash = implode('.', $segments);
    }

    /**
     * Get the current value of a given claim.
     *
     * @param  string $name
     * @return mixed
     */
    public function getClaim(string $name)
    {
        return $this->claims[$name] ?? null;
    }

    /**
     * Get the entire set of claims included in the JWT.
     *
     * @return array
     */
    public function getClaims(): array
    {
        return $this->claims;
    }

    /**
     * Get the hash representation of the JWT, or null if it has not yet been
     * signed.
     *
     * @return string|null
     */
    public function getHash(): ?string
    {
        return $this->hash;
    }

    /**
     * Get the header data included with the JWT.
     *
     * @return array
     */
    public function getHeader(): array
    {
        return $this->header;
    }

    /**
     * Get the current value of a given header field.
     *
     * @param  string $field
     * @return mixed
     */
    public function getHeaderField(string $field)
    {
        return $this->header[$field] ?? null;
    }

    /**
     * Set a new value for a given claim.
     *
     * @param  string $name
     * @param  mixed  $value
     * @return void
     */
    public function setClaim(string $name, $value): void
    {
        $this->claims[$name] = $value;

        // Clear the generated hash since it's no longer valid
        $this->hash = null;
    }

    /**
     * Set a new value for a given header field.
     *
     * @param  string $field
     * @param  mixed  $value
     * @return void
     */
    public function setHeaderField(string $field, $value): void
    {
        $this->header[$field] = $value;

        if ($field === 'alg') {
            $this->algorithm = $value;
        }

        // Clear the generated hash since it's no longer valid
        $this->hash = null;
    }

    /**
     * Verify that the JWT is correctly formatted and that the given signature
     * is valid.
     *
     * @param  mixed $key
     * @param  array $expectedClaims
     * @return bool
     * @throws BeforeValidException
     * @throws ExpiredJwtException
     * @throws InvalidJwtException
     * @throws InvalidKeyException
     * @throws InvalidSignatureException
     * @throws UnsupportedAlgorithmException
     */
    public function verify($key, array $expectedClaims = []): bool
    {
        if (empty($this->hash)) {
            throw new InvalidJwtException('Unable to verify a modified JWT.', $this);
        }

        $segments = explode('.', $this->hash);

        if (count($segments) !== 3) {
            throw new InvalidJwtException('Unable to verify the signature due to an invalid JWT hash.', $this);
        }

        $dataToSign = $segments[0] . '.' . $segments[1];
        $signature  = url_safe_base64_decode($segments[2]);

        $this->verifySignature(
            $this->findDecodeKey($key),
            $dataToSign,
            $signature
        );

        $this->verifyExpClaim();
        $this->verifyIatClaim();
        $this->verifyNbfClaim();

        if (array_key_exists('aud', $expectedClaims)) {
            $this->verifyAudClaim($expectedClaims['aud']);
        }

        if (array_key_exists('iss', $expectedClaims)) {
            $this->verifyIssClaim($expectedClaims['iss']);
        }

        return true;
    }

    /**
     * Decode a given JWT hash and use the decoded data to populate the object.
     *
     * @param  string $hash
     * @return void
     * @throws InvalidJwtException
     * @throws JwtException
     */
    public function decodeAndInitialize(string $hash): void
    {
        $this->reset();

        // Decode the JWT's segments
        $segments = explode('.', $hash);

        if (count($segments) !== 3) {
            throw new InvalidJwtException('Unexpected number of JWT segments.', $this);
        }

        if (false === ($decodedHeader = url_safe_base64_decode($segments[0]))) {
            throw new InvalidJwtException('Invalid header encoding.', $this);
        }

        if (false === ($decodedClaims = url_safe_base64_decode($segments[1]))) {
            throw new InvalidJwtException('Invalid claims encoding.', $this);
        }

        if (false === url_safe_base64_decode($segments[2])) {
            throw new InvalidJwtException('Invalid signature encoding.', $this);
        }

        // Validate the decoded data
        $claims = static::jsonDecode($decodedClaims);
        $header = static::jsonDecode($decodedHeader);

        if (is_object($claims)) {
            $claims = (array) $claims;
        } elseif (!is_array($claims)) {
            throw new InvalidJwtException('Invalid set of JWT claims.', $this);
        }

        if (is_object($header)) {
            $header = (array) $header;
        } elseif (!is_array($header)) {
            throw new InvalidJwtException('Invalid JWT header.', $this);
        }

        // Populate the JWT with the decoded data
        foreach ($header as $field => $value) {
            $this->setHeaderField($field, $value);
        }

        foreach ($claims as $name => $value) {
            $this->setClaim($name, $value);
        }

        // Use the original hash to prevent verification failures due to encoding discrepancies
        $this->hash = $hash;
    }

    /**
     * Reset the internal state of the JWT object.
     *
     * @return void
     */
    public function reset(): void
    {
        $this->algorithm = null;
        $this->claims    = [];
        $this->hash      = null;
        $this->header    = [];
    }

    /**
     * Find the correct decode key to use when verifying the JWT.
     *
     * @param  mixed $key
     * @return mixed
     * @throws InvalidJwtException
     * @throws InvalidKeyException
     */
    protected function findDecodeKey($key)
    {
        if (is_array($key)) {
            $keyId = $this->header['kid'] ?? null;

            if (!is_string($keyId)) {
                throw new InvalidJwtException('Unable to find decode key due to an invalid "kid" value.', $this);
            }

            if (!array_key_exists($keyId, $key)) {
                throw new InvalidKeyException('Unable to find the correct decode key.', $this);
            }

            return $key[$keyId];
        }

        return $key;
    }

    /**
     * Generate a signature for the JWT using a given key.
     *
     * @param  mixed  $key
     * @param  string $dataToSign
     * @return string
     * @throws JwtException
     * @throws UnsupportedAlgorithmException
     */
    protected function generateSignature($key, string $dataToSign): string
    {
        $method = 'encodeWith' . $this->algorithm;

        if (!method_exists($this, $method)) {
            throw new UnsupportedAlgorithmException(sprintf('Unsupported algorithm ("%s").', $this->algorithm), $this);
        }

        $signature = call_user_func_array(
            [$this, $method],
            [$key, $dataToSign]
        );

        if (empty($signature) || !is_string($signature)) {
            throw new JwtException('Unable to sign the JWT.', $this);
        }

        return $signature;
    }

    /**
     * Verify the "aud" (audience) claim, if included.
     *
     * @param  string|string[] $audience
     * @return void
     * @throws InvalidJwtException
     */
    protected function verifyAudClaim($audience): void
    {
        if (array_key_exists('aud', $this->claims)) {
            $audience = is_array($audience) ? $audience : [$audience];

            // Make sure the audience claim is set to a valid value
            $foundAudience = is_array($this->claims['aud']) ? $this->claims['aud'] : [$this->claims['aud']];
            $expectedIndex = 0;

            foreach ($foundAudience as $index => $value) {
                if (is_string($value) && $index === $expectedIndex) {
                    $expectedIndex++;
                } else {
                    throw new InvalidJwtException('Invalid "aud" value.', $this);
                }
            }

            // Make sure the JWT is intended for any of the expected audiences
            foreach ($audience as $expectedAudience) {
                if (in_array($expectedAudience, $foundAudience)) {
                    return;
                }
            }

            throw new InvalidJwtException('Invalid JWT audience.', $this);
        }
    }

    /**
     * Verify the "exp" (expiration time) claim, if included.
     *
     * @return void
     * @throws ExpiredJwtException
     * @throws InvalidJwtException
     */
    protected function verifyExpClaim(): void
    {
        if (array_key_exists('exp', $this->claims)) {
            $exp = $this->claims['exp'];

            if (is_numeric($exp) && strval($exp) == intval($exp)) {
                if ($exp < (time() - static::$leeway)) {
                    throw new ExpiredJwtException('The JWT has expired.', $this);
                }
            } else {
                throw new InvalidJwtException('Invalid "exp" value.', $this);
            }
        }
    }

    /**
     * Verify the "iat" (issued at) claim, if included.
     *
     * @return void
     * @throws BeforeValidException
     * @throws InvalidJwtException
     */
    protected function verifyIatClaim(): void
    {
        if (array_key_exists('iat', $this->claims)) {
            $iat = $this->claims['iat'];

            if (is_numeric($iat) && strval($iat) == intval($iat)) {
                if ($iat > (time() + static::$leeway)) {
                    throw new BeforeValidException('The JWT is not yet valid.', $this);
                }
            } else {
                throw new InvalidJwtException('Invalid "iat" value.', $this);
            }
        }
    }

    /**
     * Verify the "iss" (issuer) claim, if included.
     *
     * @param  string|string[] $issuer
     * @return void
     * @throws InvalidJwtException
     */
    protected function verifyIssClaim($issuer): void
    {
        if (array_key_exists('iss', $this->claims)) {
            $foundIssuer = $this->claims['iss'];

            if (is_string($foundIssuer)) {
                $issuer = is_array($issuer) ? $issuer : [$issuer];

                if (!in_array($foundIssuer, $issuer)) {
                    throw new InvalidJwtException('Invalid JWT issuer.', $this);
                }
            } else {
                throw new InvalidJwtException('Invalid "iss" value.', $this);
            }
        }
    }

    /**
     * Verify the "nbf" (not before) claim, if included.
     *
     * @return void
     * @throws BeforeValidException
     * @throws InvalidJwtException
     */
    protected function verifyNbfClaim(): void
    {
        if (array_key_exists('nbf', $this->claims)) {
            $nbf = $this->claims['nbf'];

            if (is_numeric($nbf) && strval($nbf) == intval($nbf)) {
                if ($nbf > (time() + static::$leeway)) {
                    throw new BeforeValidException('The JWT is not yet valid.', $this);
                }
            } else {
                throw new InvalidJwtException('Invalid "nbf" value.', $this);
            }
        }
    }

    /**
     * Verify the JWT's signature using a given key.
     *
     * @param  mixed  $key
     * @param  string $dataToSign
     * @param  string $signature
     * @return void
     * @throws InvalidSignatureException
     * @throws UnsupportedAlgorithmException
     */
    protected function verifySignature($key, string $dataToSign, string $signature): void
    {
        $method = 'verifyWith' . $this->algorithm;

        if (!method_exists($this, $method)) {
            throw new UnsupportedAlgorithmException(sprintf('Unsupported algorithm ("%s").', $this->algorithm), $this);
        }

        $verified = call_user_func_array(
            [$this, $method],
            [$key, $dataToSign, $signature]
        );

        if ($verified !== true) {
            throw new InvalidSignatureException('Invalid JWT signature.', $this);
        }
    }

    /**
     * Create a new JWT.
     *
     * @param  string $algorithm
     * @return static
     */
    public static function create(string $algorithm)
    {
        $jwt = new static();
        $jwt->setHeaderField('alg', $algorithm);
        $jwt->setHeaderField('typ', 'JWT');

        return $jwt;
    }

    /**
     * Decode a JWT hash and return the resulting object.
     *
     * @param  string $hash
     * @return static
     * @throws InvalidJwtException
     * @throws JwtException
     */
    public static function decode(string $hash)
    {
        $jwt = new static();
        $jwt->decodeAndInitialize($hash);

        return $jwt;
    }

    /**
     * Decode a given JSON string.
     *
     * @param  string $json
     * @return mixed
     * @throws JwtException
     */
    protected static function jsonDecode(string $json)
    {
        $data  = json_decode($json);
        $error = json_last_error();

        if ($error !== JSON_ERROR_NONE) {
            throw new JwtException(sprintf('Unable to decode the given JSON string (%s).', $error));
        }

        return $data;
    }

    /**
     * Convert given data to its JSON representation.
     *
     * @param  mixed $data
     * @return string
     * @throws JwtException
     */
    protected static function jsonEncode($data): string
    {
        $json  = json_encode($data);
        $error = json_last_error();

        if ($error !== JSON_ERROR_NONE) {
            throw new JwtException(sprintf('Unable to encode the given data (%s).', $error));
        }

        return $json;
    }
}
