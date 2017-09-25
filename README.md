# php-jwt
Convenience library for working with JSON Web Tokens (JWT) in PHP.

This library is based on the [Firebase PHP-JWT library](https://github.com/firebase/php-jwt) and conforms to [RFC 7519](https://tools.ietf.org/html/rfc7519).

## Requirements
* PHP 5.6, or higher

## Installation
In order to install this library, issue the following command from your project's root folder:

```
composer require "lindelius/php-jwt=^0.3"
```

## Usage
The following is a very basic example of how to issue JWTs with this library:

```php
function login($username, $password)
{
    /**
     * Check the provided user credentials.
     */
    $user = MyAuthenticationClass::login($username, $password);
        
    if (empty($user)) {
        MyJsonResponseClass::errorResponse('Invalid credentials.');
    }
    
    $jwt = new JWT(PRIVATE_KEY);
    
    /**
     * Add payload data (claims) to the JWT.
     */
    $jwt->exp        = time() + (60 * 60 * 4);
    $jwt->iat        = time();
    $jwt->sub        = $user->id;
    $jwt->user_name  = $user->username;
    $jwt->user_admin = $user->admin;
    
    MyJsonResponseClass::successResponse(['token' => $jwt->encode()]);
}
```

After a JWT has been issued by your PHP application it should be included in all future requests (to secured endpoints) by the application making the requests. It is up to you to decide how the JWT should be included.

For all secured endpoints you need to verify that a JWT is included and that it is valid. You can do so by using the included `JWT::decode()` method.

```php
$decodedJwt = JWT::decode($jwt, PRIVATE_KEY);
```

This will both decode and verify that the included JWT is valid. If you need to do this in two steps, first decode it and then check whether it is valid, you can do so by setting the method's `$verify` flag to `false`. Although, in this case you will have to extract the signature from the included JWT yourself and then pass it to the `JWT::verify()` method.

```php
function verify($jwt)
{
    $decodedJwt = JWT::decode($jwt, PRIVATE_KEY, false);
    
    try {
        /**
         * Extract the signature and verify that it's valid.
         */
        $jwtSegments  = explode('.', $jwt);
        $jwtSignature = isset($jwtSegments[2]) ? $jwtSegments[2] : null;
        
        return $decodedJwt->verify($jwtSignature);
    } catch (\Lindelius\JWT\Exception\InvalidException $e) {
        MyLogger::logInvalidToken([
            'exception' => get_class($e),
            'token'     => $jwt,
            'user_id'   => $decodedJwt->sub,
            'user_name' => $decodedJwt->user_name
        ]);
        
        return false;
    }
}
```

### Advanced Usage

#### Algorithm Choices
If you would like to limit the hashing algorithms that can be used for the JWTs, you can do so by extending the model and specifying these algorithms in the `JWT::$allowedAlgorithms` property. You can find all the supported hashing algorithms in the `JWT::$supportedAlgorithms` property.

If you are not going to allow the "HS256"-algorithm, or if you would just rather have a different default, you should also override the `JWT::$defaultAlgorithm` property.

```php
class MyJWT extends JWT
{
    protected static $allowedAlgorithms = ['HS512', 'RS256'];
    
    protected static $defaultAlgorithm  = 'RS256';
}
```

#### Leeway Time
If there are time differences between your application servers, you can extend the model and make use of the `JWT::$leeway` property to give your servers some extra seconds when verifying certain claims (`iat`, `nbf`, and `exp`). The property's value should be a positive integer representing the number of extra seconds that your servers need.

```php
class MyJWT extends JWT    
{
    protected static $leeway = 60;
}
```

#### Multiple Encryption Keys
If your application supports multiple encryption keys you need to specify this inside the JWT so that you can use the correct key later on when you have to verify that the JWT is valid. The correct way to do this is to use the `kid` field in the JWT header.

```php
$keys = [
    'key_1' => 'J5hZTw1vtee0PGaoAuaW',
    'key_2' => '8zUpiGcaPkNhNGi8oyrq',
    'key_3' => 'RfxRP43BIKoSQ7P1GfeO'
];

$jwt = new JWT($keys['key_2'], null, ['kid' => 'key_2']);
```

If you use this approach, all you have to do when verifying the JWT is to provide the `JWT::decode()` method with the `$keys` array and it will automatically look-up and use the correct key.

```php
$decodedJwt = JWT::decode($encodedJwt, $keys);
```
