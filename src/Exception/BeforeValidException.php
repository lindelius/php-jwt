<?php

namespace Lindelius\JWT\Exception;

/**
 * An exception thrown when attempting to verify a JWT earlier than what is
 * allowed by its "nbf" (not before) or "iat" (issued at) claim.
 */
class BeforeValidException extends InvalidJwtException
{
}
