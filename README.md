# GoodID SDK for PHP

This repository contains the open source PHP SDK that allows you to validate the signature of the received JWS from your PHP app.


## Installation

The GoodID PHP SDK can be installed with [Composer](https://getcomposer.org/). Add the GoodID PHP SDK package to your `composer.json` file.

```json
{
    "require": {
        "goodid/goodid-php-sdk": "~1.0"
    }
}
```

## Usage

> **Note:** This version of the GoodID SDK for PHP requires PHP 5.6.3 or greater.

```php
$goodId = new GoodID\Authentication\ImplicitAuthentication($clientId);

try {
    // Get the claims from the idToken
    $idTokenClaims = $goodId->getIdTokenClaims($jwsIdToken);

    // Get the claims from the userInfo
    $userInfoClaims = $goodId->getUserInfoClaims($jwsUserInfo);
    $requestedClaimsFromUserInfo = $userInfoClaims->get('claims');

    // Or you can get all the claims combained from the idToken and userInfo
    $allClaims = $goodId->getClaims($jwsIdToken, $jwsUserInfo);
} catch(GoodID\Exception\ValidationException $e) {
    echo 'GoodID SDK returned an error: ' . $e->getMessage();
    exit;
}

echo "The identity of the logged in user is: " . $idTokenClaims->get('sub')->value() . "\n";
echo "All the requested claims about the user: \n";
print_r($requestedClaimsFromUserInfo);

```
