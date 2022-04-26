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
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Serializer\CompactSerializer;

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
     * @param bool $serialized 
     *
     * @return JWS|string Compact JWS
     */
    public function signAsCompactJws($payload, $serialized = true)
    {
        if (is_array($payload)) {
            $payload = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        }

        // This managers handles all algorithms we need to use. 
        $algorithmManager = new AlgorithmManager([
            new ES256(),
        ]);

        // The JWS Builder
        $jwsBuilder = new JWSBuilder($algorithmManager);

        // We build our JWS object
        $jws = $jwsBuilder
            ->create()                    // Indicates we want to create a new token
            ->withPayload($payload)       // We set the payload
            ->addSignature($this->jwk, [
                self::SIG_ALG_KEY => self::SIG_ALG_VALUE_ES256,
                self::KEY_ID => $this->getKid()
            ]) // We add a signature
            ->build();                    // We compute the JWS

        if ($serialized) {
            // We need to serialize the token.
            // In this example we will use the compact serialization mode (most common mode).
            $serializer = new CompactSerializer();
            return $serializer->serialize($jws);
        }

        return $jws;
    }
}
