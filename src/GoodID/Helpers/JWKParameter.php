<?php

namespace GoodID\Helpers;

/**
 * Represents a single JWK parameter.
 *
 * @link https://tools.ietf.org/html/rfc7517#section-4
 * @link http://www.iana.org/assignments/jose/jose.xhtml#web-key-parameters
 */
class JWKParameter
{
    const PARAM_KEY_TYPE = "kty";
    const PARAM_PUBLIC_KEY_USE = "use";
    const PARAM_KEY_OPERATIONS = "key_ops";
    const PARAM_ALGORITHM = "alg";
    const PARAM_KEY_ID = "kid";
    const PARAM_X509_URL = "x5u";
    const PARAM_X509_CERTIFICATE_CHAIN = "x5c";
    const PARAM_X509_CERTIFICATE_SHA1_THUMBPRINT = "x5t";
    const PARAM_X509_CERTIFICATE_SHA256_THUMBPRINT = "x5t#S256";
    const PARAM_CURVE = "crv";
    const PARAM_X_COORDINATE = "x";
    const PARAM_Y_COORDINATE = "y";
    const PARAM_ECC_PRIVATE_KEY = "d";
    const PARAM_MODULUS = "n";
    const PARAM_EXPONENT = "e";
    const PARAM_PRIVATE_EXPONENT = "d";
    const PARAM_FIRST_PRIME_FACTOR = "p";
    const PARAM_SECOND_PRIME_FACTOR = "q";
    const PARAM_FIRST_FACTOR_CRT_EXPONENT = "dp";
    const PARAM_SECOND_FACTOR_CRT_EXPONENT = "dq";
    const PARAM_FIRST_CRT_COEFFICIENT = "qi";
    const PARAM_OTHER_PRIMES_INFO = "oth";
    const PARAM_KEY_VALUE = "k";
}
