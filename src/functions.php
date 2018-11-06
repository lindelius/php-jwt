<?php

if (!function_exists('url_safe_base64_encode')) {
    /**
     * Encodes given data using URL-safe Base64 encoding.
     *
     * @param  string $input
     * @return string
     */
    function url_safe_base64_encode(string $input): string
    {
        return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
    }
}

if (!function_exists('url_safe_base64_decode')) {
    /**
     * Decodes data encoded with URL-safe Base64.
     *
     * @param  string $input
     * @return string|bool
     */
    function url_safe_base64_decode(string $input)
    {
        $remainder = strlen($input) % 4;

        if ($remainder) {
            $paddingLength = 4 - $remainder;

            $input .= str_repeat('=', $paddingLength);
        }

        return base64_decode(strtr($input, '-_', '+/'));
    }
}
