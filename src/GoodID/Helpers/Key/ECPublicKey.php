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
use Jose\Component\KeyManagement\KeyConverter\ECKey;
use Jose\Component\Core\JWK;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Core\Util\JsonConverter;

/**
 * An EC key class with sign/verify and encrypt/decrypt capabilities in the JWS/JWE format.
 * It can act as either a private or public key based on the parameters that it is initialized with.
 */
class ECPublicKey implements KeyInterface
{
    /**
     * Signature algorithm parameter name
     */
    const SIG_ALG_KEY = "alg";

    /**
     * Signature algorithm:
     */
    const SIG_ALG_VALUE_ES256 = "ES256";

    /**
     * Key Identifier param.
     */
    const KEY_ID = "kid";

    /**
     * @var JWK
     */
    protected $jwk;

    /**
     * @var bool
     */
    protected $private;

    /**
     * ECPublicKey constructor
     *
     * @param string|array $key PEM string or JWK array
     * @param array Additional key parameters.
     */
    public function __construct($key, array $values = array())
    {
        $jwk = null;

        if (is_string($key)) {
            try {
                $jwkFromPem = new JWK(ECKey::createFromPEM($key)->toArray());
                $jwk = new JWK($this->extendWithAlg(array_merge($jwkFromPem->jsonSerialize(), $values)));
            } catch (\Exception $e) {}

            if (is_null($jwk)) {
                try {
                    $keyObj = JWK::createFromJson($key);
                    $jwk = new JWK($this->extendWithAlg(array_merge($keyObj->jsonSerialize(), $values)));
                } catch (\Exception $e) {}
            }
        } else {
            if (is_null($jwk)) {
                try {
                    $jwk = new JWK($this->extendWithAlg(array_merge($key, $values)));
                } catch (\Exception $e) {}
            }
        }

        if (is_null($jwk)) {
            throw new \Exception('Invalid key format.');
        }

        if (!$jwk->has('kty') || !$jwk->has('kid') || !$jwk->has('use')) {
            throw new \Exception('Missing required key attributes: kty, kid, use');
        }

        if (strtoupper($jwk->get('kty')) !== 'EC') {
            throw new \Exception('It is not an EC key.');
        }

        $this->jwk = $jwk;
        $this->private = $jwk->has('d');
    }

    /**
     * @param array $keyParams
     * 
     * @return array
     */
    private function extendWithAlg(array $keyParams)
    {
        if (!isset($keyParams['alg'])) {
            if (!isset($keyParams['use'])) {
                throw new \Exception('Missing required key attribute: use');
            }

            $keyParams['alg'] = self::SIG_ALG_VALUE_ES256;
        }

        return $keyParams;
    }

    /**
     * Verifies the signature and decodes the payload of the given compact JWS
     *
     * @param string $compactJws Compact JWS
     * @param bool $decoded
     *
     * @return array|string The payload as an array or string
     *
     * @throws GoodIDException
     */
    public function verifyCompactJws($compactJws, $decoded = true)
    {
        $serializer = new CompactSerializer();

        $jws = $serializer->unserialize($compactJws);
        $headerChecker = new HeaderCheckerManager(
            [new AlgorithmChecker(['ES256'])], // A list of header checkers
            [new JWSTokenSupport()]            // A list of token support services (we only use the JWS token type here)
        );

        $algorithmManager = new AlgorithmManager([
            new ES256(),
        ]);
        $jwsVerifier = new JWSVerifier($algorithmManager);

        // We check all signatures
        $isVerified = false;
        for ($i = 0; $i < $jws->countSignatures(); $i++) {
            try {
                $headerChecker->check($jws, 0); // We check the header of the first (index=0) signature.        
                if ($jwsVerifier->verifyWithKey($jws, $this->jwk, 0)) { // We verify the signature
                    $isVerified = true;
                    break;
                }
            } catch (\Exception $e) {
                continue;
            }
        }

        if (!$isVerified) {
            throw new GoodIDException("Can not verify signature");
        }

        if ($decoded) {
            return JsonConverter::decode($jws->getPayload());
        }

        return $jws->getPayload();
    }

    /**
     * Get the public key as a JWK array
     *
     * @return array
     */
    public function getPublicKeyAsJwkArray()
    {
        return $this->jwk->toPublic()->JsonSerialize();
    }

    /**
     * @return string
     * @throws GoodIDException on error
     */
    public function getKid()
    {
        return $this->jwk->get('kid');
    }

    /**
     * @return JWK
     */
    public function getJwk()
    {
        return $this->jwk;
    }

    /**
     * @return bool
     */
    public function isPrivate()
    {
        return $this->private;
    }
}
