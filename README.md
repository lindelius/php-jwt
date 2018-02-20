# php-jwt
Convenience library for working with JSON Web Tokens (JWT) in PHP.

This library is based on the [Firebase PHP-JWT library](https://github.com/firebase/php-jwt) and conforms to [RFC 7519](https://tools.ietf.org/html/rfc7519).

## Requirements
* PHP 5.6, or higher

## Installation
In order to install this library, issue the following command from your project's root folder:

```
composer require "lindelius/php-jwt=^0.4"
```

## Usage
The following is a very basic example of how to issue JWTs with this library:

```php
function login($username, $password)
{
    $user = MyAuthenticationClass::login($username, $password);
        
    if (empty($user)) {
        // TODO: return an "Invalid credentials" response
    }
    
    $jwt = new \Lindelius\JWT\JWT();
    
    $jwt->exp      = time() + (60 * 60 * 2); // expire after 2 hours
    $jwt->iat      = time();
    $jwt->sub      = $user->id;
    $jwt->username = $user->username;
    $jwt->admin    = $user->admin;
    
    $token = $jwt->encode(ENCODE_KEY);
    
    // TODO: return the token in a response
}
```

After a JWT has been issued by your PHP application it should be included in all future requests (to secured endpoints) by the application making the requests. It is up to you to decide how the JWT should be included, but it is usually done via the "Authorization" header.

```
Authorization: Bearer My.Jwt.Token
```

For all secured endpoints you need to verify that a JWT is included and that it is valid. You can do so by using the included `JWT::decode()` method.

```php
$decodedJwt = \Lindelius\JWT\JWT::decode($jwt, DECODE_KEY);
```

The example above will both decode and verify that the JWT is valid. If you want to do this in two steps, i.e. first decode the JWT and then check whether it is valid, you can do so by **not** passing the key to the `JWT::decode()` method and instead make a call to the `JWT::verify()` method.

```php
$decodedJwt = \Lindelius\JWT\JWT::decode($jwt);

// TODO: something that requires the JWT payload

$decodedJwt->verify(DECODE_KEY);
```

Never trust the payload of the JWT until you have verified it, though!

### Advanced Usage

#### Algorithm Choices
If you would like to limit the hashing algorithms that can be used for the JWTs, you can do so by extending the model and specifying these algorithms in the `JWT::$allowedAlgorithms` property. You can find all the supported hashing algorithms in the `JWT::$supportedAlgorithms` property.

If you are not going to allow the "HS256" algorithm, or if you would just rather have a different default, then you should also override the `JWT::$defaultAlgorithm` property.

```php
class MyJWT extends \Lindelius\JWT\JWT
{
    protected static $allowedAlgorithms = ['HS512', 'RS256'];
    
    protected static $defaultAlgorithm  = 'RS256';
}
```

#### Leeway Time
If there are time differences between your application servers, you can extend the model and make use of the `JWT::$leeway` property to give your servers some extra seconds when verifying certain claims (`iat`, `nbf`, and `exp`). The property's value should be a positive integer representing the number of extra seconds that your servers need.

```php
class MyJWT extends \Lindelius\JWT\JWT    
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

$jwt = new \Lindelius\JWT\JWT(null, ['kid' => 'key_2']);
```

If you use this approach, all you have to do when verifying the JWT is to provide the `JWT::decode()` (or `JWT::verify()`) method with the `$keys` array and it will automatically look-up and use the correct key.

```php
// Decode and verify
$decodedJwt = \Lindelius\JWT\JWT::decode($encodedJwt, $keys);

// Decode, then verify
$decodedJwt = \Lindelius\JWT\JWT::decode($encodedJwt);
$decodedJwt->verify($keys);
```
