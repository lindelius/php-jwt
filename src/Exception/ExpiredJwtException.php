<?php

namespace Lindelius\JWT\Exception;

/**
 * An exception thrown when a JWT is being used later than its "expiration"
 * claim allows it to be.
 */
class ExpiredJwtException extends InvalidJwtException
{
}
