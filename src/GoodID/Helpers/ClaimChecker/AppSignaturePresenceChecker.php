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

use GoodID\Helpers\SecurityLevel;
use Jose\Checker\ClaimCheckerInterface;
use Jose\Object\JWTInterface;

class AppSignaturePresenceChecker implements ClaimCheckerInterface
{
    private $securityLevel;

    public function __construct($securityLevel = SecurityLevel::NORMAL)
    {
        SecurityLevel::assertValid($securityLevel);
        $this->securityLevel = $securityLevel;
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
        if ($this->securityLevel === SecurityLevel::HIGH) {
            if (!$jwt->hasClaim('signatures')) {
                throw new \InvalidArgumentException('Missing app signatures');
            }

            $signatures = $jwt->getClaim('signatures');
            if (!is_array($signatures)) {
                throw new \InvalidArgumentException('Malformed app signatures');
            }

            foreach ($signatures as $signature) {
                if (!is_array($signature)) {
                    throw new \InvalidArgumentException('Malformed app signatures');
                }
                if (count($signature) !== 2 || !isset($signature['protected']) || !isset($signature['signature'])) {
                    throw new \InvalidArgumentException('Malformed app signatures');
                }
            }

            return ['signatures'];
        } else {
            if ($jwt->hasClaim('signatures')) {
                throw new \InvalidArgumentException('Unexpected app signatures');
            }

            return [];
        }
    }
}