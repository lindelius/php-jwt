# php-jwt

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
    - [Audiences](#audiences)
    - [Leeway Time](#leeway-time)
    - [Multiple Encryption Keys](#multiple-encryption-keys)
- [Benchmarking](#benchmarking)

## Installation

In order to install this library, issue the following command from your project's root folder:

```
composer require "lindelius/php-jwt=^0.9"
```

## Usage

Since this library is taking an OOP approach to JWT management, the first step is, unsurprisingly, to create a JWT model. All you have to do, though, is to extend the abstract `Lindelius\JWT\JWT` class and pick an algorithm, and you're good to go.
```php
use Lindelius\JWT\Algorithm\HMAC\HS256;
use Lindelius\JWT\JWT;

class MyJWT extends JWT
{
    use HS256;
}
```

The next step is to start using the JWT model to create JWTs.

Surprisingly quick and easy, wasn't it?

```php
$jwt = MyJWT::create('HS256');

// Include whatever data is required by your use case
$jwt->field = 'value';
$jwt->other = ['field' => 'value'];

// Let the JWT expire after 20 minutes (optional, but recommended)
$jwt->exp = time() + (60 * 20);

// Encode the JWT using a key suitable for the chosen algorithm
$encodedJwt = $jwt->encode('SOME_RANDOM_HMAC_KEY');
```

The final step (unless your application is not actually consuming any JWTs, then the previous step was the last one) is to decode and verify the JWTs that you are given.

```php
$decodedJwt = MyJWT::decode($encodedJwt);

// The data is available immediately after decode
$field = $decodedJwt->field;
$other = $decodedJwt->other;

// HOWEVER, do NOT forget to verify the data before trusting it
$decodedJwt->verify('THE_SAME_HMAC_KEY');
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
