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

use GoodID\Exception\GoodIDException;
use Jose\Factory\JWSFactory;

/**
 * ECPrivateKey class
 */
class ECPrivateKey extends ECPublicKey
{
    /**
     * Private exponent JWK parameter
     */
    const JWK_PARAM_PRIVATE_EXPONENT = "d";

    /**
     * RSAPrivateKey constructor
     *
     * @param string|array $key PEM string or JWK array
     * @param array Additional key parameters.
     */
    public function __construct($key, array $values = array())
    {
        parent::__construct($key, $values);

        if (!$this->jwk->has(self::JWK_PARAM_PRIVATE_EXPONENT)) {
            throw new GoodIDException("This is not a private key.");
        }
    }

    /**
     * Signs and encodes the given array as the payload of a compact JWS
     *
     * @param mixed $payload Payload
     *
     * @return string Compact JWS
     */
    public function signAsCompactJws($payload)
    {
        if (is_array($payload)) {
            $payload = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        }

        return JWSFactory::createJWSToCompactJSON($payload, $this->jwk, [
            self::SIG_ALG_KEY => self::SIG_ALG_VALUE_ES256,
            self::KEY_ID => $this->getKid()
        ]);
    }
}
