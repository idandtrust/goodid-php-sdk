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
use GoodID\Helpers\TotpValidator;

/**
 * StateNonceHandler class
 * Handles State and Nonce
 */
class StateNonceHandler
{
    /**
     * Length of a normal nonce
     * About 16 bytes entropy (in "base62")
     */
    const NORMAL_NONCE_LENGTH = 22;

    /**
     * Length of a TOTP nonce
     * 20 bytes entropy (in base64), plus one "mode character"
     */
    const TOTP_NONCE_LENGTH = 29;

    /**
     * Normal TOTP nonce validation mode
     */
    const NONCE_VALIDATION_MODE_NORMAL_TOTP = 'N';

    /**
     * Convenient TOTP nonce validation mode
     */
    const NONCE_VALIDATION_MODE_CONVENIENT_TOTP = 'C';

    /**
     * Normal (default, non-totp) nonce validation mode
     */
    const NONCE_VALIDATION_MODE_NORMAL = 'D';

    /**
     * @var SessionDataHandlerInterface
     */
    private $sessionDataHandler;

    /**
     * @var TotpValidator
     */
    private $totpValidator;

    /**
     * Construct
     *
     * @param SessionDataHandlerInterface $sessionDataHandler
     */
    public function __construct(SessionDataHandlerInterface $sessionDataHandler, TotpValidator $totpValidator)
    {
        $this->sessionDataHandler = $sessionDataHandler;
        $this->totpValidator = $totpValidator;
    }

    /**
     * Generate state
     *
     * @return string State
     */
    public function generateState()
    {
        $random = RandomStringGenerator::getPseudoRandomString(self::NORMAL_NONCE_LENGTH);
        $this->sessionDataHandler->set(SessionDataHandlerInterface::SESSION_KEY_STATE, $random);

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
        $storedState = $this->sessionDataHandler->get(SessionDataHandlerInterface::SESSION_KEY_STATE);
        $this->sessionDataHandler->remove(SessionDataHandlerInterface::SESSION_KEY_STATE);

        if (!$storedState || $receivedState !== $storedState) {
            return false;
        }

        return true;
    }

    /**
     * Generate nonce
     *
     * @return string Nonce
     */
    public function generateNonce()
    {
        $random = RandomStringGenerator::getPseudoRandomString(self::NORMAL_NONCE_LENGTH);
        $this->sessionDataHandler->set(SessionDataHandlerInterface::SESSION_KEY_NONCE, $random);

        return $random;
    }

    /**
     * Validate Nonce
     *
     * @param string $receivedNonce Received Nonce
     * @param string $clientSecret RP Client Secret
     * @param int $currentGoodIDTime Current Time of GoodID Server
     * @param int $issuedAtTime ID Token issuance time
     *
     * @return bool isValid
     *
     * @throws ValidationException on error
     */
    public function validateNonce($receivedNonce, $clientSecret, $currentGoodIDTime, $issuedAtTime)
    {
        $storedNonce = $this->sessionDataHandler->get(SessionDataHandlerInterface::SESSION_KEY_NONCE);
        $this->sessionDataHandler->remove(SessionDataHandlerInterface::SESSION_KEY_NONCE);

        if (strlen($receivedNonce) === self::NORMAL_NONCE_LENGTH) {
            return $storedNonce && $receivedNonce === $storedNonce;
        } elseif (strlen($receivedNonce) === self::TOTP_NONCE_LENGTH) {
            $mode = substr($receivedNonce, -1);
            $totpValue = substr($receivedNonce, 0, -1);
            if ($mode === self::NONCE_VALIDATION_MODE_NORMAL_TOTP) {
                return $this->totpValidator->isValid($clientSecret, $totpValue, $currentGoodIDTime);
            } elseif ($mode === self::NONCE_VALIDATION_MODE_CONVENIENT_TOTP) {
                return $this->totpValidator->isValid($clientSecret, $totpValue, $issuedAtTime);
            } else {
                throw new ValidationException('Invalid nonce validation mode');
            }
        } else {
            throw new ValidationException('The nonce has invalid length');
        }
    }

    /**
     * Get nonce validation mode
     *
     * @param string $nonce Nonce
     * @return string Nonce Validation Mode
     * @throws ValidationException
     */
    public function getNonceValidationMode($nonce)
    {
        if (strlen($nonce) === self::NORMAL_NONCE_LENGTH) {
            return self::NONCE_VALIDATION_MODE_NORMAL;
        } elseif (strlen($nonce) === self::TOTP_NONCE_LENGTH) {
            $mode = substr($nonce, -1);

            if (in_array($mode, [self::NONCE_VALIDATION_MODE_NORMAL_TOTP, self::NONCE_VALIDATION_MODE_CONVENIENT_TOTP])) {
                return $mode;
            }

            throw new ValidationException('Invalid nonce validation mode');
        }

        throw new ValidationException('The nonce has invalid length');
    }
}
