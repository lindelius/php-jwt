# php-jwt

A convenience library for working with JSON Web Tokens (JWT) in PHP.

This library conforms to [RFC 7519](https://tools.ietf.org/html/rfc7519), with the exception of not allowing unsigned JWTs (the "none" algorithm), and has built-in support for the following claims:

- `aud` - The audience(s) for which the token is valid
- `exp` - The token's expiration date
- `iat` - The token's issue date 
- `nbf` - The token's "not before" date

## Requirements

- PHP 7.1
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
$jwt = new \Lindelius\JWT\StandardJWT();

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
$decodedJwt = \Lindelius\JWT\StandardJWT::decode($encodedJwt);

/**
 * You can access the claims as soon as you have decoded the JWT.
 * However, NEVER trust the JWT until you have verified it!
 */
$isAdmin = (bool) $decodedJwt->admin;

$decodedJwt->verify(DECODE_KEY);
```

### Advanced Usage

#### Algorithm Choices

If you would like to use an algorithm other than "HS256", which is used in the `StandardJWT` model, you may extend the abstract `JWT` model and make use of any of the following algorithms:

- HS256
- HS384
- HS512
- RS256 *(requires the OpenSSL extension)*
- RS384 *(requires the OpenSSL extension)*
- RS512 *(requires the OpenSSL extension)*

Do note that you need to specify which algorithm you want to use when you create the JWTs. This may either be done when you instantiate the objects (like in the example below) or by overriding the constructor (like in the `StandardJWT` implementation).

```php
class MyJWT extends \Lindelius\JWT\JWT
{
    use \Lindelius\JWT\Algorithm\RSA\RS512;
}

$jwt = new MyJWT('RS512');
```

If you would like to use an algorithm that is not yet supported by the library you can easily implement it yourself by creating the required "encodeWith" and "verifyWith" methods. Please see the included algorithm traits for implementation details.

If you do end up implementing support for an algorithm that is not yet supported by the library, concider creating a PR for it so that others may benefit from it, as well.

#### Audiences

If you would like to restrict a JWT to one or more audiences you can easily do so with the `aud` claim. When you create the JWT, set the `aud` claim to one or more audiences. If the JWT should only be valid for a single audience, you can set the value to a string. If it should be valid for more than one audience, the value must be an array of strings.

```php
$jwt = new \Lindelius\JWT\StandardJWT();

$jwt->aud = [
    'https://myapp.tld',
    'https://yourapp.tld',
];

$encodedJwt = $jwt->encode(ENCODE_KEY);
```

When you verify the JWT, just pass the current audience as the second parameter to the `JWT::verify()` method and it will validate it for you.

```php
$decodedJwt = \Lindelius\JWT\StandardJWT::decode($encodedJwt);
$decodedJwt->verify(DECODE_KEY, $currentAudience);
```

#### Leeway Time

If there are time differences between your application servers, you can extend the abstract `JWT` model and make use of the `JWT::$leeway` property to give your servers some extra seconds when verifying certain claims (`iat`, `nbf`, and `exp`). The property's value should be a positive integer representing the number of extra seconds that your servers need.

```php
class MyJWT extends \Lindelius\JWT\JWT
{
    use \Lindelius\JWT\Algorithm\HMAC\HS256;

    /**
     * Leeway time (in seconds) to account for clock skew.
     *
     * @var int
     */
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

$jwt = new \Lindelius\JWT\StandardJWT(['kid' => 'key_2']);

$encodedJwt = $jwt->encode($keys['key_2']);
```

If you use this approach, all you have to do when verifying the JWT is to provide the `JWT::verify()` method with the `$keys` array and it will automatically look-up and use the correct key.

```php
$decodedJwt = \Lindelius\JWT\StandardJWT::decode($encodedJwt);
$decodedJwt->verify($keys);
```

### Exceptions

This library throws a variety of different exceptions in order to allow for different actions to be taken depending on what exactly it was that went wrong. However, all of these exceptions implements the `Lindelius\JWT\Exception\Exception` interface, making it possible to catch **any** exception thrown by this library without having to list all of them.

```php
try {

    $jwt = new \Lindelius\JWT\StandardJWT();

    $jwt->exp = time() + (60 * 60 * 2); // expire after 2 hours
    $jwt->iat = time();
    $jwt->sub = $user->id;

    $accessToken = $jwt->encode(ENCODE_KEY);

} catch (\Lindelius\JWT\Exception\Exception $exception) {
    // This catches any exception thrown by the library
}
```

## Benchmarking

This library is using [PHPBench](https://github.com/phpbench/phpbench) for benchmarking.

You can easily benchmark the library on your own system by running the following command from the library's root folder.

```
./vendor/bin/phpbench run benchmarks/ --report=default
```
