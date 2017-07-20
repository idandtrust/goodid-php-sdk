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

namespace GoodID\Helpers\Key;

use GoodID\Exception\ValidationException;
use GoodID\Helpers\Claim;
use Jose\Loader;
use Jose\Object\JWK;

/**
 * An elliptic curve cryptography key class
 * Only a limited functionality is implemented, just what we need
 */
class ECPublicKey
{
    /**
     * Signature algorithm:
     * ECDSA using P-256 and SHA-256
     */
    const SIG_ALG_VALUE_ES256 = "ES256";

    /**
     * Jwk parameter name: Key type
     */
    const JWK_PARAM_KEY_TYPE = "kty";

    /**
     * Jwk parameter name: Curve
     */
    const JWK_PARAM_CURVE = "crv";

    /**
     * Elliptic curve key type
     */
    const KEY_TYPE_EC = "EC";

    /**
     * P-256 curve
     */
    const CURVE_P256 = "P-256";

    /**
     * SHA256 jwk thumbprint type
     */
    const JWK_THUMBPRINT_TYPE_SHA_256 = "sha256";

    /**
     * Verifies that a compact JWS is signed with the private key corresponding
     * to the sub_jwk contained in it
     * Verifies that its sub is the thumbprint of its sub_jwk
     * Only the JWK parameters used by GoodID are permitted in the sub_jwk
     * Returns extracted payload of the JWS if valid, else it throws
     *
     * @param string $compactJws JWS string
     *
     * @return array The payload of the JWS
     *
     * @throws ValidationException on error
     */
    public static function verifySelfSignedCompactJws($compactJws)
    {
        $loader = new Loader();

        try {
            $jws = $loader->load($compactJws);
        } catch (\Exception $e) {
            throw new ValidationException('Invalid JWS string.');
        }

        if (!$jws->hasClaim(Claim::NAME_SUB_JWK)) {
            throw new ValidationException('Missing sub_jwk.');
        }

        try {
            $jwkArray = (array)$jws->getClaim(Claim::NAME_SUB_JWK);

            if (!isset($jwkArray[self::JWK_PARAM_KEY_TYPE])
                || !isset($jwkArray[self::JWK_PARAM_CURVE])
                || $jwkArray[self::JWK_PARAM_KEY_TYPE] !== self::KEY_TYPE_EC
                || $jwkArray[self::JWK_PARAM_CURVE] !== self::CURVE_P256
            ) {
                throw new \Exception();
            }

            $jwk = new JWK($jwkArray);
        } catch (\Exception $e) {
            throw new ValidationException('Invalid sub_jwk format.');
        }

        if (!$jws->hasClaim(Claim::NAME_SUBJECT)
            || $jws->getClaim(Claim::NAME_SUBJECT) !== $jwk->thumbprint(self::JWK_THUMBPRINT_TYPE_SHA_256)
        ) {
            throw new ValidationException('Invalid signature: sub vs sub_jwk mismatch.');
        }

        try {
            return $loader->loadAndVerifySignatureUsingKey($compactJws, $jwk, [self::SIG_ALG_VALUE_ES256])->getClaims();
        } catch (\Exception $e) {
            throw new ValidationException('Invalid signature.');
        }
    }
}
