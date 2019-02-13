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
use GoodID\Helpers\Response\AppSignatureChecklist;
use Jose\Checker\ClaimCheckerInterface;
use Jose\Object\JWK;
use Jose\Object\JWKInterface;
use Jose\Object\JWTInterface;
use Jose\Object\SignatureInterface;
use Jose\Util\JWSLoader;
use Jose\Verifier;

class GoodIDAppSignatureChecker implements ClaimCheckerInterface
{
    /**
     * @var AppSignatureChecklist
     */
    private $checklist;

    public function __construct(AppSignatureChecklist $checklist)
    {
        $this->checklist = $checklist;
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
        if (!$jwt->hasClaim('signatures')) {
            return [];
        }

        $claims = $jwt->getClaims();
        $appSignedJWS = JWSLoader::loadSerializedJsonJWS($claims);
        unset($claims['signatures']);
        $appSignedPayload = NormalizedJson::encode((object)$claims);

        $appSignatureVerifier = Verifier::createVerifier(['ES256']);
        foreach ($appSignedJWS->getSignatures() as $sigIdx => $signature) {
            $jwk = $this->extractSigningKey($signature);
            $signedClaim = $this->extractVerifiableClaim($jwk);

            $appSignatureVerifier->verifyWithKey($appSignedJWS, $jwk, $appSignedPayload, $idx);
            if ($idx !== $sigIdx) {
                throw new \InvalidArgumentException('Invalid signatures');
            }

            $this->verifySignedClaim($jwt, $signedClaim, $jwk->thumbprint('sha256'));
        }

        return ['signatures'];
    }

    /**
     * @param JWTInterface $jwt
     * @param string $claimName
     * @param string $value
     */
    private function verifySignedClaim(JWTInterface $jwt, $claimName, $value)
    {
        if (!$jwt->hasClaim($claimName)) {
            throw new \InvalidArgumentException('Missing app signed claim');
        }

        if ($jwt->getClaim($claimName) !== $value) {
            throw new \InvalidArgumentException('Bad app signature');
        }

        $this->checklist->markClaimSigned($claimName);
    }

    /**
     * @param SignatureInterface $signature
     *
     * @return JWK
     */
    private function extractSigningKey(SignatureInterface $signature)
    {
        if (!$signature->hasProtectedHeader('jwk')) {
            throw new \InvalidArgumentException('Missing app signing key');
        }

        $key = new JWK($signature->getProtectedHeader('jwk'));
        if (!$key->has('kid')) {
            throw new \InvalidArgumentException('Invalid app signing key');
        }

        $kid = $key->get('kid');
        if (substr($kid, -4) !== '_jwk') {
            throw new \InvalidArgumentException('Invalid app signing key');
        }

        return $key;
    }

    /**
     * @param JWKInterface $jwk
     *
     * @return string
     */
    private function extractVerifiableClaim(JWKInterface $jwk)
    {
        $claimName = (string)substr($jwk->get('kid'), 0, -4);
        if ($claimName === '') {
            throw new \InvalidArgumentException('Invalid app signing key');
        }

        return $claimName;
    }
}
