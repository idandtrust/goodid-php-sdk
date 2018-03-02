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
 * TOTP validator class
 * Only works with GoodID TOTP Nonces
 */
class TotpValidator
{
    /**
     * The earliest supported Unix timestamp
     */
    const T0 = 0;

    /**
     * Duration of a time step in seconds
     */
    const TIME_STEP = 10;

    /**
     * Number of counter values that we try before the current one.
     */
    const WINDOW = 3;

    /**
     * Calculate HOTP
     *
     * Based on this, but without truncate:
     * https://tools.ietf.org/html/rfc4226
     *
     * @param string $key Mac key
     * @param int $counter Counter
     * @return string base64
     */
    private function calculateHotp($key, $counter)
    {
        $mac = hash_hmac('sha1', (string) $counter, $key, true);

        if ($mac === false) {
            throw new GoodIDException('sha1 hmac algorithm not supported, but GoodID needs it');
        }

        $base64Mac = base64_encode($mac);

        if ($base64Mac === false) {
            throw new GoodIDException('base64_encode failed');
        }

        return $base64Mac;
    }

    /**
     * Calculate TOTP
     *
     * Based on this:
     * https://tools.ietf.org/html/rfc6238
     *
     * @param string $key Mac key
     * @param int $t0 T0
     * @param int $timeStep Time step
     * @param int $validationTimestamp Validation timestamp
     * @param int $delta Delta
     * @return string base64
     */
    private function calculateTotp($key, $t0, $timeStep, $validationTimestamp, $delta)
    {
        $t = (int)floor(($validationTimestamp - $t0) / $timeStep) - $delta;

        return $this->calculateHotp($key, $t);
    }

    /**
     *
     * @param string $key Mac key
     * @param string $totp Totp value
     * @param int $validationTimestamp Validation timestamp
     * @return boolean isValid
     */
    public function isValid($key, $totp, $validationTimestamp)
    {
        for ($delta = 0; $delta <= self::WINDOW; $delta++) {
            $calculatedTotp = $this->calculateTotp($key, self::T0, self::TIME_STEP, $validationTimestamp, $delta);

            if ($calculatedTotp === $totp) {
                return true;
            }
        }

        return false;
    }
}
