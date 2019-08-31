<?php

namespace Lindelius\JWT\Exception;

/**
 * An exception thrown when a JWT is being used earlier than its "not before"
 * claim allows it to be.
 */
class BeforeValidException extends InvalidJwtException
{
}
