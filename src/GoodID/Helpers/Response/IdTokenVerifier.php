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
use GoodID\Helpers\ClaimChecker\AppSignaturePresenceChecker;
use GoodID\Helpers\ClaimChecker\AudienceChecker;
use GoodID\Helpers\ClaimChecker\AuthTimeChecker;
use GoodID\Helpers\ClaimChecker\ExpirationChecker;
use GoodID\Helpers\ClaimChecker\IssuerChecker;
use GoodID\Helpers\ClaimChecker\NonceChecker;
use GoodID\Helpers\ClaimChecker\RequiredClaimChecker;
use GoodID\Helpers\ClaimChecker\SubChecker;
use GoodID\Helpers\ClaimChecker\ClaimCheckerManager;
use Jose\Component\Signature\JWS;

class IdTokenVerifier
{
    /**
     * @var CheckerManager
     */
    private $checker;

    /**
     * IdTokenVerifier constructor.
     * @param string $issuer
     * @param string $clientId
     * @param string $securityLevel
     * @param null|int $requestedMaxAge
     * @param bool $authTimeRequested
     * @param null|string $nonce
     */
    public function __construct($issuer, $clientId, $securityLevel, $requestedMaxAge, $authTimeRequested, $nonce)
    {
        $timeToleranceInSeconds = 0;

        // OpenID specific validation
        $claimCheckers[] = new IssuerChecker($issuer);
        $claimCheckers[] = new SubChecker();
        $claimCheckers[] = new AudienceChecker($clientId);
        $claimCheckers[] = new ExpirationChecker($timeToleranceInSeconds);
        $claimCheckers[] = new AuthTimeChecker($timeToleranceInSeconds, $requestedMaxAge, $authTimeRequested);
        $claimCheckers[] = new NonceChecker($nonce);

        // GoodID specific validation
        $claimCheckers[] = new RequiredClaimChecker('uih');
        $claimCheckers[] = new AppSignaturePresenceChecker($securityLevel);

        $this->checker = new ClaimCheckerManager($claimCheckers);
    }

    /**
     * @param JWS $jws
     *
     * @throws ValidationException
     */
    public function verifyIdToken(JWS $jws)
    {
        try {
            $this->checker->checkClaims(json_decode($jws->getPayload(), true), array('sub', 'iss', 'aud', 'nonce'));
        } catch (\InvalidArgumentException $ex) {
            throw new ValidationException('ID token validation failed: ' . $ex->getMessage(), 0, $ex);
        }
    }
}
