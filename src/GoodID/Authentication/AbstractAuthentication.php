<?php

namespace GoodID\Authentication;

/**
 * Abstract class for GoodID authentication modes.
 */
abstract class AbstractAuthentication
{
    /**
     * The issuer is GoodID
     */
    const ISS_GOODID = 'https://goodid.net';

    /**
     * SHA-256 hash algorithm
     */
    const HASH_SHA256 = 'sha256';

    /**
     * @var string
     */
    protected $clientId;

    /**
     * @param string $clientId
     */
    public function __construct($clientId)
    {
        $this->clientId = $clientId;
    }

    abstract public function getClaims($jwsIdToken, $jwsUserInfo);

    abstract public function getIdTokenClaims($jwsIdToken);

    abstract public function getUserInfoClaims($jwsUserInfo);
}
