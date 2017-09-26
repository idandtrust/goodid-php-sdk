<?php
/**
 * Copyright 2017 ID&Trust, Ltd.
 *
 * You are hereby granted a non-exclusive, worldwide, royalty-free license to
 * use, copy, modify, and distribute this software in source code or binary form
 * for use in connection with the web services and APIs provided by ID&Trust.
 *
 * As with any software that integrates with the GoodID platform, your use
 * of this software is subject to the GoodID Terms of Service
 * (https://goodid.net/docs/tos).
 * This copyright notice shall be included in all copies or substantial portions
 * of the software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

namespace GoodID\Helpers;

use GoodID\Exception\GoodIDException;

/**
 * Class SessionDataHandler
 * This class handles the storage and retrieval of data to and from session.
 */
class SessionDataHandler
{
    /**
     *
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
     * @var string
     */
    protected $goodidSessionKey = '__GoodID__';

    /**
     * Construct
     *
     * @throws GoodIDException If the session has not been started.
     */
    public function __construct()
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            throw new GoodIDException(
                'Session has not been started. Please start that first with session_start().'
            );
        }
    }

    /**
     * @param string $key Key
     *
     * @return mixed Value
     *
     * @throws GoodIDException
     */
    public function get($key)
    {
        if (isset($_SESSION[$this->goodidSessionKey])) {
            if (!is_array($_SESSION[$this->goodidSessionKey])) {
                unset($_SESSION[$this->goodidSessionKey]);
                throw new GoodIDException("GoodIDSessionKey: "
                    . $this->goodidSessionKey
                    . " might be used by someone other than the GoodID PHP SDK.");
            }
            if (isset($_SESSION[$this->goodidSessionKey][$key])) {
                return $_SESSION[$this->goodidSessionKey][$key];
            }
        }

        return null;
    }

    /**
     * @param string $key Key
     * @param mixed $value Value
     *
     * @throws GoodIDException
     */
    public function set($key, $value)
    {
        if (!isset($_SESSION[$this->goodidSessionKey])) {
            $_SESSION[$this->goodidSessionKey] = [];
        } elseif (!is_array($_SESSION[$this->goodidSessionKey])) {
            unset($_SESSION[$this->goodidSessionKey]);
            throw new GoodIDException("GoodIDSessionKey: "
                . $this->goodidSessionKey
                . " might be used by someone other than the GoodID PHP SDK.");
        }

        $_SESSION[$this->goodidSessionKey][$key] = $value;
    }

    /**
     * @param string $key Key
     */
    public function remove($key)
    {
        unset($_SESSION[$this->goodidSessionKey][$key]);
    }

    /**
     * Remove the whole GoodID session key
     */
    public function removeAll()
    {
        unset($_SESSION[$this->goodidSessionKey]);
    }
}
