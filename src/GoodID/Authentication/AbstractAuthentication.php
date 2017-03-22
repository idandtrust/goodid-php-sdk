<?php

namespace GoodID\Authentication;

use GoodID\Helpers\SessionDataHandler;

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
     * The session key for nonce.
     */
    const SESSION_KEY_NONCE = 'nonce';

    /**
     * The session key for state.
     */
    const SESSION_KEY_STATE = 'state';

    /**
     * ECDSA using P-256 and SHA-256.
     */
    const ALGO_ES256 = "ES256";

    /**
     * @var string
     */
    protected $clientId;

    /**
     * @var SessionDataHandler
     */
    protected $sessionDataHandler;

    /**
     * @param string $clientId
     */
    public function __construct($clientId)
    {
        $this->sessionDataHandler = new SessionDataHandler();
        $this->clientId = $clientId;
    }

    abstract public function getClaims($jwsIdToken, $jwsUserInfo, $receivedState);

    abstract public function getIdTokenClaims($jwsIdToken, $receivedState);

    abstract public function getUserInfoClaims($jwsUserInfo);
}
