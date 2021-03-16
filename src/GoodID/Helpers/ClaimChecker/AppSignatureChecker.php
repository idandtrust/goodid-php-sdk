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

use GoodID\Helpers\NormalizedJson;
use GoodID\Helpers\SecurityLevel;
use Jose\Component\Checker\ClaimChecker;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWS;
use Jose\Util\JWSLoader;
use Jose\Verifier;
use Jose\Component\Core\Util\JsonConverter;

class AppSignatureChecker implements ClaimChecker, GoodIDClaimChecker
{
    /**
     * @var string
     */
    private $securityLevel;

    /**
     * @var JWS
     */
    private $idToken;

    /**
     * @var string
     */
    private $protectedClaimName;

    /**
     * @var string
     */
    private $appSignedIdTokenPayload;

    /**
     * @var JWS
     */
    private $appSignedIdToken;

    /**
     * AppSignatureChecker constructor.
     *
     * @param string $securityLevel
     * @param JWS $idToken
     * @param string $protectedClaimName
     */
    public function __construct($securityLevel, JWS $idToken, $protectedClaimName)
    {
        SecurityLevel::assertValid($securityLevel);

        $this->securityLevel = $securityLevel;
        $this->idToken = $idToken;
        $this->protectedClaimName = $protectedClaimName;
    }

    /**
     * @param array $claims
     *
     * @return void
     */
    public function checkClaim($claims): void
    {
        if ($this->securityLevel === SecurityLevel::NORMAL) {
            if (isset($claims[$this->protectedClaimName])) {
                throw new \InvalidArgumentException('Unexpected protected claim: ' . $this->protectedClaimName);
            }
            if (isset($claims[$this->protectedClaimName . '_jwk'])) {
                throw new \InvalidArgumentException('Unexpected protection key for claim: ' . $this->protectedClaimName);
            }
        }

        // @TODO
        $jwk = $this->extractProtectionKey($claims, $this->extractClaimValue($claims));
        $this->regenerateAppSignedContent($this->idToken);
        $this->checkSignatures($jwk);
    }

    private function regenerateAppSignedContent(JWS $idToken)
    {
        if ($this->securityLevel !== SecurityLevel::HIGH) {
            return;
        }

        $idTokenClaims = JsonConverter::decode($idToken->getPayload());
        if (!isset($idTokenClaims['signatures'])) {
            throw new \InvalidArgumentException('Missing app signatures');
        }

        /**
         * Load idToken as a json serialized token with detached payload
         *
         * Why this works might be confusing, but the RFC clears this up:
         *  - payload, and signatures are the only defined elements (we only
         *    have signatures, but the lib we're using supports detached payloads,
         *    which we'll regenerate next)
         *  - other members are permitted but MUST be ignored
         *
         * @link https://tools.ietf.org/html/rfc7515#section-7.2.1
         */
        //@TODO
        $this->appSignedIdToken = JWSLoader::loadSerializedJsonJWS($idTokenClaims);

        /**
         * Now we need to recreate the payload the app signed. Which is the
         * JSON representation of the id token without the signatures claim.
         * We're using our normalized JSON serialization here.
         */
        $this->appSignedIdTokenPayload = NormalizedJson::encode((object)array_diff_key(
            $idTokenClaims,
            ['signatures' => null]));

    }

    /**
     * @param array $claims
     *
     * @return string
     */
    private function extractClaimValue(array $claims)
    {
        if (!isset($claims[$this->protectedClaimName])) {
            throw new \InvalidArgumentException('Missing protected claim: ' . $this->protectedClaimName);
        }
        return $claims[$this->protectedClaimName];
    }

    /**
     * @param array $claims
     * @param string thumbprint
     *
     * @return JWK
     */
    private function extractProtectionKey(array $claims, $thumbprint)
    {
        $kid = $this->protectedClaimName . '_jwk';
        if (!isset($claims[$kid])) {
            throw new \InvalidArgumentException('Unverifiable protected claim: ' . $this->protectedClaimName);
        }

        if (!is_array($claims[$kid])) {
            throw new \InvalidArgumentException('Malformed protection key for claim: ' . $this->protectedClaimName);
        }

        $jwk = null;
        try {
            $jwk = new JWK(array_merge($claims[$kid], ['kid' => $kid]));
        } catch (\InvalidArgumentException $ex) {
            throw new \InvalidArgumentException(
                'Malformed protection key for claim: ' . $this->protectedClaimName,
                0,
                $ex);
        }

        if ($thumbprint !== $jwk->thumbprint('sha256')) {
            throw new \InvalidArgumentException('Protection key thumbprint mismatch for claim: ' . $this->protectedClaimName);
        }

        return $jwk;
    }

    /**
     * @param JWK $jwk
     */
    private function checkSignatures(JWK $jwk)
    {
        $appSignatureVerifier = Verifier::createVerifier(['ES256']);
        foreach ($this->appSignedIdToken->getSignatures() as $sigIdx => $signature) {
            if (!$signature->hasProtectedHeader('kid')) {
                throw new \InvalidArgumentException('Malformed app signature header');
            }
            if ($signature->getProtectedHeader('kid') !== $jwk->get('kid')) {
                continue;
            }
            try {
                $appSignatureVerifier->verifyWithKey(
                    $this->appSignedIdToken,
                    $jwk,
                    $this->appSignedIdTokenPayload,
                    $idx);
            } catch (\InvalidArgumentException $ex) {
                throw new \InvalidArgumentException(
                    'Invalid signature for claim: ' . $this->protectedClaimName,
                    0,
                    $ex);
            }

            if ($idx !== $sigIdx) {
                throw new \InvalidArgumentException('Invalid signature at index ' . $sigIdx);
            }

            return;
        }

        throw new \InvalidArgumentException('Missing signature for claim: ' . $this->protectedClaimName);
    }

    public function supportedClaim(): string
    {
        return $this->protectedClaimName . '_jwk';
    }
}