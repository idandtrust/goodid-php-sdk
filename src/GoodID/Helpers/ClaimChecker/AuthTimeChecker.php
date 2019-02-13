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

namespace GoodID\Helpers\ClaimChecker;

use Jose\Checker\ClaimCheckerInterface;
use Jose\Object\JWTInterface;

class AuthTimeChecker implements ClaimCheckerInterface
{
    /**
     * @var int
     */
    private $tolerance;

    /**
     * @var int|null
     */
    private $requestedMaxAge;

    /**
     * @var bool
     */
    private $authTimeRequested = false;

    /**
     * AuthTimeChecker constructor.
     * @param int $tolerance
     * @param null|int $requestedMaxAge
     * @param bool $authTimeRequested
     */
    public function __construct($tolerance, $requestedMaxAge, $authTimeRequested)
    {
        if ($tolerance < 0) {
            throw new \InvalidArgumentException('Tolerance must be a non-negative integer');
        }

        $this->tolerance = $tolerance;
        $this->requestedMaxAge = $requestedMaxAge;
        $this->authTimeRequested = $authTimeRequested;
    }

    /**
     * @param \Jose\Object\JWTInterface $jwt
     *
     * @throws \InvalidArgumentException
     *
     * @return string[]
     */
    public function checkClaim(JWTInterface $jwt)
    {
        if (!$jwt->hasClaim('auth_time')) {
            if ($this->requestedMaxAge !== null || $this->authTimeRequested) {
                throw new \InvalidArgumentException('Missing auth_time');
            }
            return [];
        }

        if ((int)$jwt->getClaim('auth_time') - $this->tolerance > time()) {
            throw new \InvalidArgumentException('The user was authenticated in the future');
        }

        if ($this->requestedMaxAge !== null && (int)$jwt->getClaim('auth_time') + $this->tolerance < time() - $this->requestedMaxAge) {
            throw new \InvalidArgumentException('The user was authenticated too long ago');
        }

        return ['auth_time'];
    }
}
