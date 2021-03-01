[![Build Status](https://travis-ci.org/idandtrust/goodid-php-sdk.svg?branch=master)](https://travis-ci.org/idandtrust/goodid-php-sdk)

# GoodID SDK for PHP

This repository contains our open source PHP SDK that allows you to collect, decrypt and verify the data that you receive from the user.
> **Note:** This version of the GoodID SDK for PHP requires PHP 5.6 or greater.

## Installation

The GoodID PHP SDK can be installed with [Composer](https://getcomposer.org/). Add the GoodID PHP SDK package to your `composer.json` file.

```json
{
    "require": {
        "goodid/goodid-php-sdk": "~5.0"
    }
}
```

## Prerequisites
To provide GoodID login to your users, you need to register at GoodID first.
You will receive the followings:
- GoodID mobile app download link
- client id
- client secret
- default keypairs
- suggested claimset

At this point, you also have the chance to generate your own keypairs and send the public key to GoodID.

Download the GoodID app:

[![Alt text](https://s3-us-west-2.amazonaws.com/goodid/developers/goodid-sdk-app-store.png)](https://itunes.apple.com/hu/app/goodid-strong-authentication/id1072149515?mt=8) [![Alt text](https://s3-us-west-2.amazonaws.com/goodid/developers/goodid-sdk-google-play.png)](https://play.google.com/store/apps/details?id=com.idandtrust.goodid)

## The GoodID login flow
This is a short introduction to the GoodID login flow, to let you know what is the purpose of the endpoints (detailed in the "Endpoints to be implemented" section) that you need to implement.

Brief overview of the GoodID login flow:
1. The Javascript SDK is only responsible to render the "Sign in with GoodID" button. [Read more](https://developers.goodid.net/?page=integration#collapse_2)
2. When the user clicks on the "Sign in with GoodID" button the user agent is navigated to the __GoodID Login Initiation Endpoint__ .
3. The __GoodID Login Initiation Endpoint__ builds the "Authorization Request" and redirects to the GoodID Authorization EP with the request in the url.
4. The user receives the request into the GoodID mobile app and answers that.
5. Finally the user is redirected to your __Redirect URI__ (Landing page), with "code" and "state" parameters that are used by the GoodID PHP SDK to collect, decrypt and verify the information provided by the user.

## Endpoints to be implemented

### GoodID Login Initiation Endpoint
The so-called __GoodID Login Initiation endpoint__ is a designated endpoint for GoodID. It is analogous to the OpenID Connect Login Initiation endpoint and it is responsible to generate the OpenID authentication request.

You don't have to handle GET/POST parameters, or write a response, this is all done automatically by the GoodID Endpoint that is instantiated in the code snippet.

```php
// GoodID Login Initiation Endpoint (e.g. goodid-endpoint.php)

// Load the SDK and other dependencies
require_once __DIR__ . '/vendor/autoload.php';

use GoodID\Authentication\GoodIDEndpointFactory;
use GoodID\Helpers\GoodIDPartnerConfig;
use GoodID\Helpers\Key\RSAPrivateKey;
use GoodID\Helpers\OpenIDRequestSource\OpenIDRequestObject;
use GoodID\Helpers\Request\IncomingRequest;
use GoodID\ServiceLocator;

// -- Basic configuration --
$clientId = 'YOUR-CLIENT-ID';
$clientSecret = 'YOUR-CLIENT-SECRET';
$redirectUri = 'YOUR-REDIRECT-URI';
$scopes = array('YOUR-SCOPES'); // It can be an empty array
$claims = 'YOUR-CLAIMS-JSON-STRING';
$sigPrivKeyPEM = "YOUR-SIG-PRIV-KEY-PEM-STRING";
$sigPrivKeyKeyId = 'KEY-ID-OF-YOUR-SIG-PUB-KEY-ON-JWKS-URI';
$encPrivKeyPEM = "YOUR-ENC-PRIV-KEY-PEM-STRING";
$encPrivKeyKeyId = 'KEY-ID-OF-YOUR-ENC-PUB-KEY-ON-JWKS-URI';
// -- End of Basic configuration --

// -- Set session data handler OPTION 1 -- 
// You can use our default session data handler. 
// In this case you need to start the session first.
session_start();
$serviceLocator = new ServiceLocator();

// -- Set session data handler OPTION 2 -- 
// Or you can add your own session data handler
// by defining a class which implements \GoodID\Helpers\SessionDataHandlerInterface
// Add that to the $serviceLocator.
$serviceLocator = new ServiceLocator();
$serviceLocator->setSessionDataHandler(new CustomSessionDataHandler());

$encKey = new RSAPrivateKey($encPrivKeyPEM, array('use' => 'enc', 'kid' => $encPrivKeyKeyId));
$sigKey = new RSAPrivateKey($sigPrivKeyPEM, array('use' => 'sig', 'kid' => $sigPrivKeyKeyId));

$goodidEndpoint = GoodIDEndpointFactory::createInitiateLoginEndpoint(
    $serviceLocator,
    new GoodIDPartnerConfig($clientId, $clientSecret, $sigKey, $encKey),
    new OpenIDRequestObject($claims, $scopes),
    $redirectUri,
    new IncomingRequest()
);

$goodidEndpoint->run();
```

### Redirect URI (Landing page)
The user answers therequest with the GoodID mobile application and redirected to your your so-called __Redirect URI__.  The SDK collects, decrypts and verifies the response.

```php
// Redirect URI / landing page

require_once __DIR__ . '/vendor/autoload.php';

use GoodID\Authentication\GoodIDEndpointFactory;
use GoodID\Helpers\GoodIDPartnerConfig;
use GoodID\Helpers\Key\RSAPrivateKey;
use GoodID\ServiceLocator;

// -- Basic configuration --
$clientId = 'YOUR-CLIENT-ID';
$clientSecret = 'YOUR-CLIENT-SECRET';
$securityLevel = 'YOUR-SECURITY-LEVEL'; // 'NORMAL' or 'HIGH'
$sigPrivKeyPEM = "YOUR-SIG-PRIV-KEY-PEM-STRING";
$sigPrivKeyKeyId = 'KEY-ID-OF-YOUR-SIG-PUB-KEY-ON-JWKS-URI';
$encPrivKeyPEM = "YOUR-ENC-PRIV-KEY-PEM-STRING";
$encPrivKeyKeyId = 'KEY-ID-OF-YOUR-ENC-PUB-KEY-ON-JWKS-URI';
// -- End of Basic configuration --

// -- Set session data handler OPTION 1 -- 
// You can use our default session data handler. 
// In this case you need to start the session first.
session_start();
$serviceLocator = new ServiceLocator();

// -- Set session data handler OPTION 2 -- 
// Or you can add your own session data handler
// by defining a class which implements \GoodID\Helpers\SessionDataHandlerInterface
// Add that to the $serviceLocator.
$serviceLocator = new ServiceLocator();
$serviceLocator->setSessionDataHandler(new CustomSessionDataHandler());

$encKey = new RSAPrivateKey($encPrivKeyPEM, array('use' => 'enc', 'kid' => $encPrivKeyKeyId));
$sigKey = new RSAPrivateKey($sigPrivKeyPEM, array('use' => 'sig', 'kid' => $sigPrivKeyKeyId));

try {
    $gidResponse = GoodIDEndpointFactory::getResponse(
        $serviceLocator, 
        new GoodIDPartnerConfig($clientId, $clientSecret, $sigKey, $encKey, $securityLevel)
    );
    
    if ($gidResponse->isSuccessful()) {
        // Subject identifier
        $subjectIdentifier = $gidResponse->getSub();

	if ($securityLevel === 'HIGH') {
	    $userId = $gidResponse->getUserId();
	    $deviceId = $gidResponse->getDeviceId();
	}

        // The data provided by the user
        $claims = $gidResponse->getClaims()->toArray();
    
        // Now begins the substantial part of the job:
        // You can do your custom validation of claims.
        // You can log in (or register) the user:
        // Read/write your DB, regenerate session id, etc.
        // Good luck :-)
    } else {
        $error = $gidResponse->getError();
        $errorDescription = $gidResponse->getErrorDescription();
        // The login has failed with an OpenID Authentication Error Response
        // For example the user pressed cancel in the app
    }
} catch(\Exception $e) {
    // The login has failed with an exception
    // The identity of the user cannot be verified
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

Please send us the followings:
- The new public keypairs (.pub files).
- The request object signed by the new key.

### Generating the content of your JWKs URI
Your JWKs URI contains your public keys (signing and ecryption) in JSON format (JWK).

If you don't have a JWKs URI yet, you can generate its content like this:

```php
use GoodID\Helpers\Key\JwkSetGenerator;
use GoodID\Helpers\Key\RSAPublicKey;

$sigPrivKeyPEM = "YOUR-SIG-PRIV-KEY-PEM-STRING";
$sigPrivKeyId = 'KEY-ID-OF-YOUR-SIG-PUB-KEY-ON-JWKS-URI';
$encPrivKeyPEM = "YOUR-ENC-PRIV-KEY-PEM-STRING";
$encPrivKeyId = 'KEY-ID-OF-YOUR-ENC-PUB-KEY-ON-JWKS-URI';

$encKey = new RSAPrivateKey($encPrivKeyPEM, array('use' => 'enc', 'kid' => $encPrivKeyId));
$sigKey = new RSAPrivateKey($sigPrivKeyPEM, array('use' => 'sig', 'kid' => $sigPrivKeyId));

$jwkSetGenerator = new JwkSetGenerator();
$jwkSetGenerator->addKey($sigKey);
$jwkSetGenerator->addKey($encKey);

$jwkSetGenerator->run();
```
