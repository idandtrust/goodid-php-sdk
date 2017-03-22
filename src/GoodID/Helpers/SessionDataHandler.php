<?php

namespace GoodID\Helpers;

use GoodID\Exception\GoodIDException;

/**
 * Class SessionDataHandler
 */
class SessionDataHandler
{
    /**
     * @var string
     */
    protected $sessionPrefix = 'GoodID_';

    /**
     * Construct.
     *
     * @throws GoodIDException If the session has not been started.
     */
    public function __construct()
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            throw new GoodIDException(
                'Session has not been started. Please start that fist with session_start().'
            );
        }
    }

    /**
     * @param string $key
     *
     * @return mixed
     */
    public function get($key)
    {
        if (isset($_SESSION[$this->sessionPrefix . $key])) {
            return $_SESSION[$this->sessionPrefix . $key];
        }

        return null;
    }

    /**
     * @param string $key
     * @param mixed $value
     */
    public function set($key, $value)
    {
        $_SESSION[$this->sessionPrefix . $key] = $value;
    }
}
