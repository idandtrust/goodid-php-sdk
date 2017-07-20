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

use GoodID\Exception\ValidationException;

/**
 * StateNonceHandler class
 * Handles State and Nonce
 */
class StateNonceHandler
{
    /**
     * @var SessionDataHandler
     */
    private $sessionDataHandler;

    /**
     * Construct
     *
     * @param SessionDataHandler $sessionDataHandler
     */
    public function __construct(SessionDataHandler $sessionDataHandler)
    {
        $this->sessionDataHandler = $sessionDataHandler;
    }

    /**
     * Generate state
     *
     * @return string State
     */
    public function generateState()
    {
        $random = RandomStringGenerator::getPseudoRandomString(32);
        $this->sessionDataHandler->set(SessionDataHandler::SESSION_KEY_STATE, $random);

        return $random;
    }

    /**
     * Validate the given state
     *
     * @param string $receivedState Received State
     *
     * @return bool isValid
     *
     * @throws ValidationException on error
     */
    public function validateState($receivedState)
    {
        $storedState = $this->sessionDataHandler->get(SessionDataHandler::SESSION_KEY_STATE);

        if (!$storedState || $receivedState !== $storedState) {
            return false;
        }
        $this->sessionDataHandler->remove(SessionDataHandler::SESSION_KEY_STATE);

        return true;
    }

    /**
     * Generate nonce
     *
     * @return string Nonce
     */
    public function generateNonce()
    {
        $random = RandomStringGenerator::getPseudoRandomString(32);
        $this->sessionDataHandler->set(SessionDataHandler::SESSION_KEY_NONCE, $random);

        return $random;
    }

    /**
     * Validate Nonce
     *
     * @param string $receivedNonce Received Nonce
     *
     * @return bool isValid
     *
     * @throws ValidationException on error
     */
    public function validateNonce($receivedNonce)
    {
        $storedNonce = $this->sessionDataHandler->get(SessionDataHandler::SESSION_KEY_NONCE);

        if (!$storedNonce || $receivedNonce !== $storedNonce) {
            return false;
        }

        $this->sessionDataHandler->remove(SessionDataHandler::SESSION_KEY_NONCE);

        return true;
    }
}
