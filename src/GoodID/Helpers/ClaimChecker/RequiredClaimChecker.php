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

use Jose\Component\Checker\ClaimChecker;

class RequiredClaimChecker implements ClaimChecker, GoodIDClaimChecker
{
    /**
     * @var string
     */
    private $claimName;

    /**
     * @var null|mixed
     */
    private $claimValue;

    /**
     * RequiredClaimChecker constructor.
     * @param string $claimName
     * @param null|mixed $claimValue
     */
    public function __construct($claimName, $claimValue = null)
    {
        $this->claimName = $claimName;
        $this->claimValue = $claimValue;
    }

    /**
     * @param array $claims
     *
     * @throws \InvalidArgumentException
     *
     * @return void
     */
    public function checkClaim($claims): void
    {
        if (!isset($claims[$this->claimName])) {
            throw new \InvalidArgumentException('Missing claim `' . $this->claimName . '`');
        }

        if ($this->claimValue !== null && $claims[$this->claimName] !== $this->claimValue) {
            throw new \InvalidArgumentException('Invalid claim `' . $this->claimName . '`; expected `' . $this->claimValue . '`');
        }
    }

    public function supportedClaim(): string
    {
        return $this->claimName;
    }
}
