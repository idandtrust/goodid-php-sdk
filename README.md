[![Build Status](https://travis-ci.org/idandtrust/goodid-php-sdk.svg?branch=master)](https://travis-ci.org/idandtrust/goodid-php-sdk)

# GoodID SDK for PHP

This repository contains our open source PHP SDK that allows you to collect, decrypt and verify the data that you receive from the user.
> **Note:** This version of the GoodID SDK for PHP requires PHP 5.6 or greater.

## Installation

The GoodID PHP SDK can be installed with [Composer](https://getcomposer.org/). Add the GoodID PHP SDK package to your `composer.json` file.

```json
{
    "require": {
        "goodid/goodid-php-sdk": "~4.0"
    }
}
```

## Prerequisites
To provide GoodID login to your users, you need to first register at GoodID.
You will receive the followings:
- GoodID mobile app download link
- client id
- client secret
- default keypairs
- suggested claimset

At this point you also have the chance to generate your own keypairs and send the public key to GoodID.

Download the GoodID app:

[![Alt text](https://s3-us-west-2.amazonaws.com/goodid/developers/goodid-sdk-app-store.png)](https://itunes.apple.com/hu/app/goodid-strong-authentication/id1072149515?mt=8) [![Alt text](https://s3-us-west-2.amazonaws.com/goodid/developers/goodid-sdk-google-play.png)](https://play.google.com/store/apps/details?id=com.idandtrust.goodid)

## The GoodID login flow
This is a short introduction to the GoodID login flow, to let you know what is the purpose of the endpoints that you will implement in the "Endpoints to be implemented" section.

Brief overview of the GoodID login flow:
1. The Javascript SDK is only responsible to render the "Sign in with GoodID" button. [Read more](https://developers.goodid.net/?page=integration#collapse_2)
2. When the user clicks on the "Sign in with GoodID" button the user agent is navigated to the your specified __GoodID Login Initiation Endpoint__ .
3. The __GoodID Login Initiation Endpoint__ builds the "Authorization Request" and redirects to the GoodID Authorization EP with the request in the url.
4. The user is redirected to your __Redirect URI__ (Landing page), with "code" and "state" parameters that are used by the GoodID PHP SDK to collect, decrypt and verify the information provided by the user.
5. Congratulations! You have all requested data about the user. You can perform the login or registration process (if it is the first time they log in with the given subject identifier).

## Endpoints to be implemented

### GoodID Login Initiation Endpoint
The so-called __GoodID Login Initiation endpoint__ is a designated endpoint for GoodID. It is analogous to the OpenID Connect Login Initiation endpoint and it is responsible for to generate the OpenID authentication request.

The endpoint should be a separate PHP file (e.g. goodid-endpoint.php) with content similar to the below code snippet.
You don't have to handle GET/POST parameters, or write a response, this is all done automatically by the GoodID Endpoint that is instantiated in the code snippet.

```php
// GoodID Login Initiation Endpoint (e.g. goodid-endpoint.php)

// Load the SDK and other dependencies
require_once __DIR__ . '/vendor/autoload.php';

use GoodID\Authentication\GoodIDEndpointFactory;
use GoodID\Exception\GoodIDException;
use GoodID\Helpers\Key\RSAPrivateKey;
use GoodID\Helpers\OpenIDRequestSource\OpenIDRequestObject;
use GoodID\ServiceLocator;

// -- Option 1 --
// You can use our default session data handler. 
// In this case you need to start the session first.
session_start();

$serviceLocator = new ServiceLocator();

// -- Option 2 --
// Or you can add your own session data handler
// by defining a class which implements \GoodID\Helpers\SessionDataHandlerInterface
// Add that to the $serviceLocator.
$serviceLocator->setSessionDataHandler(new CustomSessionDataHandler());

try {
    // Simply create and run our object, it will take care of everything
    GoodIDEndpointFactory::createGoodIDEndpoint(
        $serviceLocator,
        "YOUR-CLIENT-ID",
        new RSAPrivateKey("YOUR-SIG-PRIV-KEY-PEM-STRING"),
        new RSAPrivateKey("YOUR-ENC-PRIV-KEY-PEM-STRING"),
        new OpenIDRequestObject("YOUR-CLAIMS-JSON-STRING"),
        "YOUR-REDIRECT-URI"
    )->run();
} catch (GoodIDException $e) {
    error_log('Login initiation failed: ' . $e->getMessage());
    http_response_code(500);
    echo "Internal Server Error";
}
```

### Redirect URI (Landing page)
You also have to handle the login requests of the user. When a user logs in with GoodID, they will be redirected to your so-called __Redirect URI__ with a "code" and a "state" parameter. You can use something similar to the below code snippet.
Doing a redirect after the login (attempt) is highly recommended as it removes the query parameters from the HTTP request URL, providing a cleaner experience for the user. It also keeps their browser history free of long expired authorization codes.

```php
// Redirect URI / landing page

require_once __DIR__ . '/vendor/autoload.php';

use GoodID\Authentication\GoodIDResponse;
use GoodID\Exception\GoodIDException;
use GoodID\Helpers\Key\RSAPrivateKey;
use GoodID\Helpers\SecurityLevel;
use GoodID\ServiceLocator;

// -- Option 1 --
// You can use our default session data handler. 
// In this case you need to start the session first.
session_start();

$serviceLocator = new ServiceLocator();

// -- Option 2 --
// Or you can add your own session data handler
// by defining a class which implements \GoodID\Helpers\SessionDataHandlerInterface
// Add that to the $serviceLocator.
$serviceLocator->setSessionDataHandler(new CustomSessionDataHandler());

// If there is a "code" parameter, it must be a login attempt
if (filter_has_var(INPUT_GET, 'code') || filter_has_var(INPUT_GET, 'error')) {
    try {
        // The GoodIDResponse object collects, decrypts and verifies the response data
        $response = new GoodIDResponse(
            $serviceLocator,
            "YOUR-CLIENT-ID",
            "YOUR-CLIENT-SECRET",
            SecurityLevel::NORMAL, // or SecurityLevel::HIGH
            new RSAPrivateKey("YOUR-SIG-PRIV-KEY-PEM-STRING"),
            new RSAPrivateKey("YOUR-ENC-PRIV-KEY-PEM-STRING")
        );

        if($response->hasError()) {
            $error = $gidResponse->getError();
            $errorDescription = $gidResponse->getErrorDescription();
            // The login has failed with an OpenID Authentication Error Response
            // For example the user pressed cancel in the app
        } else {
            // Subject identifier
            $subjectIdentifier = $response->getSub();
            // The data provided by the user
            $claims = $response->getClaims()->toArray();

            // For debugging:
//          echo "Sub: $subjectIdentifier\n";
//          echo "Claims: ";
//          print_r($claims);
//          exit;

            // Now begins the substantial part of the job:
            // You can do your custom validation of claims.
            // You can log in (or register) the user:
            // Read/write your DB, regenerate session id, etc.
            // Good luck :-)
        }
    } catch (GoodIDException $e) {
        // The login has failed with an exception
        // The identity of the user cannot be verified
        error_log('Login failed: ' . $e->getMessage());
    }

    header('Location: /');
    exit;
}
```

## Miscellaneous

These steps may be useful at certain steps of the integration.

### Generating your own keypairs

If you wish to generate your own keypairs, it is possible as follows, with openssl
Installing openssl for Ubuntu:

```
sudo apt-get install openssl
```

Generating keypairs:

```
openssl genrsa -out client-enc_key.pem 2048
openssl rsa -in client-enc_key.pem -pubout > client-enc_key.pub
openssl genrsa -out client-sig_key.pem 2048
openssl rsa -in client-sig_key.pem -pubout > client-sig_key.pub
```

After that please send us the following:
- The new public keypairs (.pub files) and please label them so we know exactly to which environment they are for
- The request object created with the new public key for digital signature (based on the next paragraph)

### Generating a Request Object

As the last step of the integration you are required to send GoodID a signed default request object.
GoodID will publish this to the "request URI" hosted by GoodID, but created uniquely for you.
When a sign in process starts from the GoodID app we will get the request signed by you from there.
It can be generated as follows:

```php
use GoodID\Helpers\Key\RSAPrivateKey;
use GoodID\Helpers\OpenIDRequestSource\OpenIDRequestObject;
use GoodID\ServiceLocator;

$requestObject = new OpenIDRequestObject("Your claimset as a JSON string");
$jwt = $requestObject->generateJwt(
    new RSAPrivateKey("The content of your sig.pem as a string"),
    "Your client id",
    "Your default redirect URI",
    (new ServiceLocator())->getServerConfig()
);
echo $jwt;
```

### Generating the content of your JWKs URI
Your JWKs URI is an endpoint, which contains a JWKSet, which is a set of JSON Web Keys in JSON format.
You have to store your signing and encryption public keys on the JWKs URI,
to make it easily available in the app-initiated login flow (e.g. Providers Screen).

If you don't have a JWKs URI yet, you can generate its content like this:

```php
use GoodID\Helpers\Key\JwkSetGenerator;
use GoodID\Helpers\Key\RSAPublicKey;

$sigKey = new RSAPublicKey("The content of your sig.pub as a string");
$encKey = new RSAPublicKey("The content of your enc.pub as a string");
$jwkSetGenerator = new JwkSetGenerator();
$jwksUriContent = $jwkSetGenerator->generateJwksUriContent($sigKey, $encKey);
```

If you have an existing JWKs URI, and you would like to add more keys to it, you can do it as described below.
`$jwksUriContent` will contain the old keys from your existing JWKs URI and the new keys passed in the parameters too.

```php
use GoodID\Helpers\Key\JwkSetGenerator;
use GoodID\Helpers\Key\RSAPublicKey;

$sigKey = new RSAPublicKey("The content of your sig.pub as a string");
$encKey = new RSAPublicKey("The content of your enc.pub as a string");
$jwkSetGenerator = new JwkSetGenerator();
$jwksUriContent = $jwkSetGenerator->generateJwksUriContent(
    $sigKey,
    $encKey,
    'https://your-url.com/jwksuri.json'
);
```


### Using a picture returned in the `picture_data` claim

This is only interesting to you if you requested a picture from the user.
You don't have to write the image to a file, it is just an example.

```php
// Assume that $response is a GoodID response
$claims = $response->getClaims();
$f = fopen('temporary.jpeg', 'wb');
fwrite($f, base64_decode($claims->get('picture_data')));
fclose($f);
```
