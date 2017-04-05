# php-jwt
Convenience library for working with JSON Web Tokens (JWT) in PHP.

This library is based on the [Firebase PHP-JWT library](https://github.com/firebase/php-jwt) and conforms to [RFC 7519](https://tools.ietf.org/html/rfc7519).

## Requirements
* PHP 5.6, or higher

## Installation
In order to install this library, issue the following command from your project's root folder:

```
composer require "lindelius/php-jwt=^0.2"
```

## Usage

### Basic Usage
The following is a very basic example of how to issue JWTs with this library:

```php
function login($username, $password)
{
    $user = AuthenticationClass::login($username, $password);
        
    if (empty($user)) {
        JsonResponseClass::errorResponse('Invalid credentials.');
    }
    
    $jwt = new JWT(PRIVATE_KEY);
    
    $jwt->exp        = time() + (60 * 60 * 4);
    $jwt->iat        = time();
    $jwt->sub        = $user->id;
    $jwt->user_name  = $user->username;
    $jwt->user_admin = $user->admin;
    
    JsonResponseClass::successResponse(['token' => $jwt->encode()]);
}
```

After a JWT has been issued by your PHP application it should be included in all future requests (to secured endpoints) by the application making the requests. It's up to you to decide how the JWT should be included.

For all secured endpoints you need to verify that a JWT is included and that it's valid. You can do so by using the included `JWT::decode()` method.

```php
$decodedJwt = JWT::decode($jwt, PRIVATE_KEY);
```

This will both decode and verify that the included JWT is actually valid. If you need to do this in two steps, first decode it and then check whether it is valid, you can do so by setting the method's `$verify` flag to `false`. Although, in this case you will have to extract the signature from the included JWT yourself and pass it to the `JWT::verify()` method.

```php
$decodedJwt = JWT::decode($jwt, PRIVATE_KEY, false);

$jwtSegments  = explode('.', $jwt);
$jwtSignature = isset($jwtSegments[2]) ? $jwtSegments[2] : null;

$decodedJwt->verify($jwtSignature);
```
