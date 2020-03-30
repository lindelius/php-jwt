# php-jwt

A convenience library for working with JSON Web Tokens (JWT) in PHP.

This library conforms to [RFC 7519](https://tools.ietf.org/html/rfc7519), with the exception of not allowing unsigned JWTs (the "none" algorithm), and has built-in support for the following claims:

- `aud` - The audience(s) for which the token is valid
- `exp` - The token's expiration date
- `iat` - The token's issue date 
- `iss` - The issuer of the token
- `nbf` - The token's "not before" date

## Requirements

- PHP 7.2
- OpenSSL PHP extension (for certain algorithms)

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
    - [Advanced Usage](#advanced-usage)
        - [Algorithm Choices](#algorithm-choices)
        - [Audiences](#audiences)
        - [Leeway Time](#leeway-time)
        - [Multiple Encryption Keys](#multiple-encryption-keys)
    - [Exceptions](#exceptions)
- [Benchmarking](#benchmarking)

## Installation

In order to install this library, issue the following command from your project's root folder:

```
composer require "lindelius/php-jwt=^0.8"
```

## Usage

The following is a very basic example of how to issue JWTs with this library:

```php
use Lindelius\JWT\Algorithm\HMAC\HS256;
use Lindelius\JWT\JWT;

class MyJWT extends JWT
{
    use HS256;
}

$jwt = new MyJWT('HS256');

$jwt->exp = time() + (60 * 20); // Expire after 20 minutes
$jwt->iat = time();
$jwt->sub = $user->id;

$accessToken = $jwt->encode(ENCODE_KEY);
```

After a JWT has been issued by your PHP application it should be included in all future requests (to secured endpoints) by the application making the requests. It is up to you to decide how the JWT should be included, but it is usually done via the "Authorization" header.

```
Authorization: Bearer My.Jwt.Token
```

For all secured endpoints you need to verify that a JWT is included and that it is valid. You can do so by using the included `JWT::decode()` and `JWT::verify()` methods.

```php
$decodedJwt = MyJWT::decode($encodedJwt);

/**
 * You can access the claims as soon as you have decoded the JWT.
 * However, NEVER trust the JWT until you have verified it!
 */
$isAdmin = (bool) $decodedJwt->admin;

$decodedJwt->verify(DECODE_KEY);
```

### Advanced Usage

#### Algorithm Choices

The following algorithms are currently included with the library:

- **HS256**
- **HS384**
- **HS512**
- **RS256** *(requires the OpenSSL extension)*
- **RS384** *(requires the OpenSSL extension)*
- **RS512** *(requires the OpenSSL extension)*

You may use any of the algorithms by simply using the relevant trait in your JWT model.

```php
use Lindelius\JWT\Algorithm\RSA\RS256;
use Lindelius\JWT\JWT;

class MyJWT extends JWT
{
    use RS256;
}

$jwt = new MyJWT('RS256');
```

If you would like to use an algorithm that is not yet included with the library you can add support for it by creating the required `encodeWithX()` and `verifyWithX()` methods in the same fashion as the currently included traits.

#### Audiences

If you would like to restrict a JWT to one or more audiences you can easily do so with the `aud` claim. When you create the JWT, set the `aud` claim to one or more audiences. If the JWT should only be valid for a single audience, you can set the value to a string. If it should be valid for more than one audience, the value must be an array of strings.

```php
$jwt->aud = [
    'https://myapp.tld',
    'https://yourapp.tld',
];
```

When you verify the JWT, just pass the current audience as the second parameter to the `JWT::verify()` method and it will validate it for you.

```php
$decodedJwt->verify(DECODE_KEY, ['aud' => $currentAudience]);
```

#### Leeway Time

If there are time differences between your application servers, you can extend the abstract `JWT` model and make use of the `JWT::$leeway` property to give your servers some extra seconds when verifying certain claims (`iat`, `nbf`, and `exp`). The property's value should be a positive integer representing the number of extra seconds that your servers need.

```php
use Lindelius\JWT\JWT;

class MyJWT extends JWT
{
    protected static $leeway = 90;
}
```

#### Multiple Encryption Keys

If your application supports multiple encryption keys you are going to need to specify this inside the JWT so that you can use the correct key later on when you have to verify that the JWT is valid. The correct way to do this is to use the `kid` field in the JWT header.

```php
$keys = [
    'key_1' => 'J5hZTw1vtee0PGaoAuaW',
    'key_2' => '8zUpiGcaPkNhNGi8oyrq',
    'key_3' => 'RfxRP43BIKoSQ7P1GfeO',
];

$jwt->setHeaderField('kid', 'key_2');

$encodedJwt = $jwt->encode($keys['key_2']);
```

If you use this approach, all you have to do when verifying the JWT is to provide the `JWT::verify()` method with the `$keys` array and it will automatically look-up and use the correct key.

```php
$decodedJwt = MyJWT::decode($encodedJwt);
$decodedJwt->verify($keys);
```

### Exceptions

This library throws a variety of different exceptions in order to allow for different actions to be taken depending on what exactly it was that went wrong. However, all of these exceptions extends `Lindelius\JWT\Exception\JwtException`, making it possible to catch **any** exception thrown by this library without having to list all of them.

```php
try {

    $jwt = MyJWT::decode($encodedJwt);
    $jwt->verify(DECODE_KEY);

} catch (\Lindelius\JWT\Exception\JwtException $exception) {
    // This catches any exception thrown by the library
}
```

## Benchmarking

This library is using [PHPBench](https://github.com/phpbench/phpbench) for benchmarking.

You can easily benchmark the library on your own system by running the following command from the library's root folder.

```
./vendor/bin/phpbench run benchmarks/ --report=default
```
