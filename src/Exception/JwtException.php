<?php

namespace Lindelius\JWT\Exception;

use Exception;
use Lindelius\JWT\JWT;

/**
 * An exception thrown if a JWT related error is detected.
 */
class JwtException extends Exception
{
    /**
     * The JWT for which the exception was thrown.
     *
     * @var JWT|null
     */
    protected $jwt;

    /**
     * Construct a JWT related exception.
     *
     * @param  string   $message
     * @param  JWT|null $jwt
     * @return void
     */
    public function __construct(string $message = '', JWT $jwt = null)
    {
        $this->jwt = $jwt;

        parent::__construct($message);
    }

    /**
     * Get the JWT for which the exception was thrown.
     *
     * @return JWT|null
     */
    public function getJwt(): ?JWT
    {
        return $this->jwt;
    }
}
