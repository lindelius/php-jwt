<?php

namespace Lindelius\JWT\Exception;

/**
 * An exception thrown when attempting to verify a JWT later than what is
 * allowed by its "exp" (expiration time) claim.
 */
class ExpiredJwtException extends InvalidJwtException
{
}
