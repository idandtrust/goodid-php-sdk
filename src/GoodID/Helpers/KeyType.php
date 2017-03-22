<?php

namespace GoodID\Helpers;

/**
 * Implements 'Key Type' parameter.
 *
 * @link https://tools.ietf.org/html/rfc7517#section-4.1
 */
class KeyType
{
    /**
     * Octet sequence key type.
     */
    const TYPE_OCT = "oct";

    /**
     * RSA key type.
     */
    const TYPE_RSA = "RSA";

    /**
     * Elliptic curve key type.
     */
    const TYPE_EC = "EC";
}
