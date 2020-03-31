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
     * @return string|false
     */
    function url_safe_base64_decode(string $input)
    {
        if ($remainder = strlen($input) % 4) {
            $input .= str_repeat('=', 4 - $remainder);
        }

        return base64_decode(strtr($input, '-_', '+/'));
    }
}
