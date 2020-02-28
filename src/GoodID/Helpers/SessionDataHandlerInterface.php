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

    const SESSION_KEY_GOODID_SESSION_ID = "goodidsessionid";

    const SESSION_KEY_USER_JWK = "userJWK";

    const SESSION_KEY_DEV_JWK = "devJWK";

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
