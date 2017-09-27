<?php

namespace GoodID\Helpers;

/**
 * Interface SessionDataHandlerInterface
 */
interface SessionDataHandlerInterface
{
    /**
     * The session key for nonce
     * Value type: string
     */
    const SESSION_KEY_NONCE = 'nonce';

    /**
     * The session key for state
     * Value type: string
     */
    const SESSION_KEY_STATE = 'state';

    /**
     * The session key for the used redirect_uri
     * Value type: string
     */
    const SESSION_KEY_USED_REDIRECT_URI = "redirecturi";

    /**
     * The session key for:
     *     Request object as array, or request uri as string, or OpenIDRequestSource::CONTENT_IS_ENCRYPTED
     * Value type: string|array
     */
    const SESSION_KEY_REQUEST_SOURCE = "reqsource";

    /**
     * Session key: Is the request initiated outside the RP backend.
     * Eg.: provider screen
     * Value type: bool
     */
    const SESSION_KEY_APP_INITIATED = "appinit";

    /**
     * Get a value from a persistent data store.
     *
     * @param string $key
     *
     * @return mixed
     */
    public function get($key);

    /**
     * Set a value in the persistent data store.
     *
     * @param string $key
     * @param mixed  $value
     */
    public function set($key, $value);
    
    /**
     * @param string $key Key
     */
    public function remove($key);

    /**
     * Remove the whole GoodID session key
     */
    public function removeAll();
}
