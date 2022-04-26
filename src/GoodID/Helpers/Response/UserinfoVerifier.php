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

namespace GoodID\Helpers\Response;

use GoodID\Exception\ValidationException;
use GoodID\Helpers\ClaimChecker\AppSignatureChecker;
use GoodID\Helpers\ClaimChecker\GoodIDUserinfoHashChecker;
use GoodID\Helpers\ClaimChecker\SubChecker;
use GoodID\Helpers\SecurityLevel;
use Jose\Checker\CheckerManager;
use Jose\Component\Signature\JWS;
use Jose\Component\Encryption\JWE;
use Jose\Component\Core\Util\JsonConverter;
use GoodID\Helpers\ClaimChecker\ClaimCheckerManager;

class UserinfoVerifier
{
    /**
     * @var CheckerManager
     */
    private $checker;

    /**
     * UserinfoVerifier constructor.
     * @param JWS $idToken
     */
    public function __construct($securityLevel, JWS $idToken)
    {
        SecurityLevel::assertValid($securityLevel);

        $idTokenClaims = JsonConverter::decode($idToken->getPayload());
        
        // OpenID specific validation
        $claimCheckers[] = new SubChecker($idTokenClaims['sub']);

        // GoodID specific validation
        $claimCheckers[] = new GoodIDUserinfoHashChecker($idToken);
        $claimCheckers[] = new AppSignatureChecker($securityLevel, $idToken, 'user');
        $claimCheckers[] = new AppSignatureChecker($securityLevel, $idToken, 'seal');

        $this->checker = new ClaimCheckerManager($claimCheckers);
    }

    /**
     * @param JWE $userinfo
     *
     * @throws ValidationException
     */
    public function verifyUserinfo(JWE $userinfo)
    {
        try {
            $this->checker->checkClaims(JsonConverter::decode($userinfo->getPayload()), 0);
        } catch (\InvalidArgumentException $ex) {
            throw new ValidationException('Userinfo validation failed: ' . $ex->getMessage(), 0, $ex);
        }
    }
}
