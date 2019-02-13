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

use Jose\Decrypter;
use Jose\Factory\JWSFactory;
use Jose\Loader;
use Jose\LoaderInterface;
use Jose\Object\JWEInterface;
use Jose\Object\JWK;
use Jose\Object\JWKSetInterface;
use Jose\Object\JWSInterface;
use Jose\Util\JWELoader;
use Jose\Util\JWSLoader;
use Jose\Verifier;

class TokenExtractor
{
    /**
     * @var LoaderInterface
     */
    private $loader;
    /**
     * @var JWKSetInterface
     */
    private $rpKeys;
    /**
     * @var JWKSetInterface
     */
    private $serverKeys;

    /**
     * TokenExtractor constructor.
     * @param JWKSetInterface $rpKeys
     * @param JWKSetInterface $serverKeys
     */
    public function __construct(JWKSetInterface $rpKeys, JWKSetInterface $serverKeys)
    {
        $this->loader = new Loader();
        $this->rpKeys = $rpKeys;
        $this->serverKeys = $serverKeys;
    }

    /**
     * @param string $compactJwt
     *
     * @return JWSInterface
     */
    public function extractToken($compactJwt)
    {
        $tokenParts = explode('.', $compactJwt);
        switch (count($tokenParts)) {
            case 3:
                try {
                    $jws = JWSLoader::loadSerializedJsonJWS([
                        'payload' => $tokenParts[1],
                        'signatures' => [
                            [
                                'protected' => $tokenParts[0],
                                'signature' => $tokenParts[2],
                            ]
                        ]
                    ]);
                } catch (\Throwable $t) {
                    throw new \InvalidArgumentException('Unable to decode JWS', 0, $t);
                }
                $this->verifyJws($jws);
                break;
            case 5:
                try {
                    $jwe = JWELoader::loadSerializedJsonJWE([
                        'protected' => $tokenParts[0],
                        'recipients' => [
                            [
                                'encrypted_key' => $tokenParts[1]
                            ]
                        ],
                        'iv' => $tokenParts[2],
                        'ciphertext' => $tokenParts[3],
                        'tag' => $tokenParts[4]
                    ]);
                } catch (\Throwable $ex) {
                    throw new \InvalidArgumentException('Unable to decode JWE');
                }
                $jws = $this->decryptJwe($jwe);
                break;
            default:
                throw new \InvalidArgumentException('Unsupported input');
        }

        return $jws;
    }

    private function verifyJws(JWSInterface &$jws)
    {
        $verifier = new Verifier(['RS256', 'ES256']);
        $verifier->verifyWithKeySet($jws, $this->serverKeys);
    }

    /**
     * @param JWEInterface $jwe
     *
     * @return JWSInterface
     */
    private function decryptJwe(JWEInterface &$jwe)
    {
        $decrypter = new Decrypter(['RSA-OAEP'], ['A128CBC-HS256', 'A256CBC-HS512'], ['DEF', 'ZLIB', 'GZ']);
        $decrypter->decryptUsingKeySet($jwe, $this->rpKeys);

        $payload = $jwe->getPayload();
        if (is_array($payload)) {
            $jws = JWSFactory::createJWS($payload);
            $jws = $jws->addSignatureInformation(
                new JWK(['kty' => 'none']),
                [
                    'alg' => 'HS512'
                ]
            );
            return $jws;
        }

        $jwsParts = explode('.', $payload);
        if (count($jwsParts) !== 3) {
            throw new \InvalidArgumentException('The token does not seem to contain a JWS');
        }

        try {
            $jws = JWSLoader::loadSerializedJsonJWS([
                'payload' => $jwsParts[1],
                'signatures' => [
                    [
                        'protected' => $jwsParts[0],
                        'signature' => $jwsParts[2],
                    ]
                ]
            ]);
        } catch (\Throwable $t) {
            throw new \InvalidArgumentException('Unable to decode JWS', 0, $t);
        }

        $this->verifyJws($jws);
        return $jws;
    }
}