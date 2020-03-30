<?php

namespace Lindelius\JWT\Exception;

/**
 * An exception thrown when attempting to sign or verify a JWT using an invalid
 * or incorrect key.
 */
class InvalidKeyException extends InvalidJwtException
{
}
