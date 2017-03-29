<?php

namespace GoodID\Helpers;

use GoodID\Exception\GoodIDException;

/**
 * Class SessionDataHandler
 */
class SessionDataHandler
{
    /**
     * @var int
     *
     * On mobile the app reloads the site when submitting the data
     * so we need to store the previously generated values
     * to be able to validate against those.
     */
    const SESSION_SIZE_LIMIT = 5;

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
        if (!isset($_SESSION[$this->sessionPrefix . $key]) || !is_array($_SESSION[$this->sessionPrefix . $key])) {
            $_SESSION[$this->sessionPrefix . $key] = [];
        }

        // Remove the oldest key
        if (count($_SESSION[$this->sessionPrefix . $key]) >= self::SESSION_SIZE_LIMIT) {
            array_shift($_SESSION[$this->sessionPrefix . $key]);
        }

        $_SESSION[$this->sessionPrefix . $key][] = $value;
    }

    /**
     * @param string $key
     */
    public function remove($key)
    {
        unset($_SESSION[$this->sessionPrefix . $key]);
    }
}
