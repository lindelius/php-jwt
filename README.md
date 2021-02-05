# php-jwt

[![CircleCI](https://circleci.com/gh/lindelius/php-jwt.svg?style=shield)](https://circleci.com/gh/lindelius/php-jwt)

A convenience library for working with JSON Web Tokens (JWT) in PHP.

This library conforms to [RFC 7519](https://tools.ietf.org/html/rfc7519), with the exception of not allowing unsigned JWTs (the "none" algorithm), and has built-in support for the following claims:

- The `aud` (audience) claim - [Section 4.1.3](https://tools.ietf.org/html/rfc7519#section-4.1.3)
- The `exp` (expiration time) claim - [Section 4.1.4](https://tools.ietf.org/html/rfc7519#section-4.1.4)
- The `iat` (issued at) claim - [Section 4.1.6](https://tools.ietf.org/html/rfc7519#section-4.1.6)
- The `iss` (issuer) claim - [Section 4.1.1](https://tools.ietf.org/html/rfc7519#section-4.1.1)
- The `nbf` (not before) claim - [Section 4.1.5](https://tools.ietf.org/html/rfc7519#section-4.1.5)

## Requirements

- PHP 7.2
- OpenSSL PHP extension (for certain algorithms)

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
    - [Algorithm Choices](#algorithm-choices)
    - [Leeway Time](#leeway-time)
    - [Multiple Encryption Keys](#multiple-encryption-keys)
- [Benchmarking](#benchmarking)

## Installation

If you're using Composer, you may install this library by running the following command from your project's root folder:

```
composer require "lindelius/php-jwt=^0.9"
```

You may also manually download the library by navigating to the "Releases" page and then expanding the "Assets" section of the latest release.

## Usage

**Step 1.** Extend the abstract `JWT` model and pick an algorithm.

```php
use Lindelius\JWT\Algorithm\HMAC\HS256;
use Lindelius\JWT\JWT;

class MyJWT extends JWT
{
    use HS256;
}
```

**Step 2.** Start creating your JWTs :)

```php
$jwt = MyJWT::create('HS256');

// Include whatever data is required by your use case
$jwt->field = 'value';
$jwt->other = ['nested_field' => 'value'];

// Let the JWT expire after 20 minutes (optional, but recommended)
$jwt->exp = time() + (60 * 20);

// Encode the JWT using a key suitable for the chosen algorithm
$encodedJwtHash = $jwt->encode('YOUR_HMAC_KEY');
```

**Step 3.** Decode and verify the JWTs that are sent back.

```php
$decodedJwt = MyJWT::decode($encodedJwtHash);

// The data is available immediately after decode
$field = $decodedJwt->field;
$other = $decodedJwt->other;

// HOWEVER, do NOT forget to verify the data before trusting it
$decodedJwt->verify('THE_SAME_HMAC_KEY');
```

If you are making use of any of the claims with built-in support (`aud` or `iss`), you may verify them by passing the expected values to the `verify()` method (as seen below).

```php
$decodedJwt->verify('THE_SAME_HMAC_KEY', [

    // Single valid audience
    'aud' => 'https://my-application.tld',

    // Multiple valid issuers
    'iss' => ['Expected Issuer', 'Alternate Issuer'],

]); 
```

### Algorithm Choices

The following algorithms are currently included with the library:

- **HS256**
- **HS384**
- **HS512**
- **RS256** *(requires the OpenSSL extension)*
- **RS384** *(requires the OpenSSL extension)*
- **RS512** *(requires the OpenSSL extension)*

You may use any of the built-in algorithms by simply including the relevant trait(s) in your JWT model.

```php
use Lindelius\JWT\Algorithm\RSA\RS256;
use Lindelius\JWT\JWT;

class MyJWT extends JWT
{
    use RS256;
}

$jwt = MyJWT::create('RS256');
```

If you would like to use an algorithm that is not yet included with the library you can easily add support for it by implementing the required `encodeWithX()` and `verifyWithX()` methods (in the same fashion as the currently included traits).

### Leeway Time

If your application servers suffer from clock skew, you can make use of the `JWT::$leeway` property to give them a couple of extra seconds when verifying certain claims (`exp`, `iat`, and `nbf`).

It's highly recommended to keep the leeway time as low as possible.

```php
use Lindelius\JWT\JWT;

class MyJWT extends JWT
{
    public static $leeway = 60;
}
```

### Multiple Encryption Keys

If your application makes use of multiple encryption keys you will, in one way or another, have to keep track of which key was used for which JWT. One way to do this is to use the `kid` header field to include the "key ID" with the JWT.

```php
$availableKeys = [
    'key_1' => 'J5hZTw1vtee0PGaoAuaW',
    'key_2' => '8zUpiGcaPkNhNGi8oyrq',
    'key_3' => 'RfxRP43BIKoSQ7P1GfeO',
];

// Decide which key to use for the JWT
$keyId = 'key_2';

// Include the key ID ("kid") in the JWT's header
$jwt = MyJWT::create('HS256');
$jwt->setHeaderField('kid', $keyId);

$encodedJwt = $jwt->encode($availableKeys[$keyId]);
```

If you use this approach, all you have to do when verifying the JWT is to provide the `JWT::verify()` method with `$availableKeys` and it will automatically look-up and use the correct key.

```php
$decodedJwt = MyJWT::decode($encodedJwt);
$decodedJwt->verify($availableKeys);
```

## Benchmarking

This library is using [PHPBench](https://github.com/phpbench/phpbench) for benchmarking.

You can benchmark the library on your own system by running the following command from the library's root folder.

```
./vendor/bin/phpbench run benchmarks/ --report=default
```
