<?php

namespace Lindelius\JWT\Exception;

/**
 * An exception thrown when attempting to sign or verify a JWT using an
 * unsupported algorithm.
 */
class UnsupportedAlgorithmException extends JwtException
{
}
