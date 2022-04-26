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

use Jose\Component\Checker\ClaimCheckerManager as JoseClaimCheckManager;

class ClaimCheckerManager extends JoseClaimCheckManager
{
    protected $checkers = [];

    /**
     * This method checks all the claims passed as argument.
     * All claims are checked against the claim checkers.
     * If one fails, the InvalidClaimException is thrown.
     *
     * This method returns an array with all checked claims.
     * It is up to the implementor to decide use the claims that have not been checked.
     */
    public function checkClaims(array $claims): array
    {
        $checkedClaims = [];
        foreach ($this->checkers as $claim => $checker) {
            if ($checker instanceof GoodIDClaimChecker) {
                $checker->checkClaim($claims);
                $checkedClaims[$claim] = $claims[$claim];
            } else {
                $checker->checkClaim($claims[$claim]);
                $checkedClaims[$claim] = $claims[$claim];
            }
        }

        return $checkedClaims;
    }
}