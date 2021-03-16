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

use Jose\Component\Encryption\JWE;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\JWS;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128CBCHS256;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256CBCHS512;
use Jose\Component\Encryption\Compression\CompressionMethodManager;
use Jose\Component\Encryption\Compression\Deflate;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\Serializer\CompactSerializer as JWECompactSerializer;
use Jose\Component\Encryption\Serializer\JWESerializerManager;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\HS512;
use Jose\Component\Signature\Serializer\CompactSerializer as JWSCompactSerializer;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;

class TokenExtractor
{
    /**
     * @var JWKSet
     */
    private $rpKeys;
    /**
     * @var JWKSet
     */
    private $serverKeys;

    /**
     * TokenExtractor constructor.
     * @param JWKSet $rpKeys
     * @param JWKSet $serverKeys
     */
    public function __construct(JWKSet $rpKeys, JWKSet $serverKeys)
    {
        $this->rpKeys = $rpKeys;
        $this->serverKeys = $serverKeys;
    }

    /**
     * @param string $compactJwt
     *
     * @return JWS
     */
    public function extractIDToken($compactJwt)
    {
        $tokenParts = explode('.', $compactJwt);
        switch (count($tokenParts)) {
            case 3:
                try {
                    $serializer = new JWSCompactSerializer();

                    $jws = $serializer->unserialize($compactJwt);
                }
                catch (\Throwable $t) {
                    throw new \InvalidArgumentException('Unable to decode JWS', 0, $t);
                }
                $this->verifyJws($jws);
                break;
            case 5:
                try {
                    $serializerManager = new JWESerializerManager([
                        new JWECompactSerializer(),
                    ]);

                    $jwe = $this->decryptJwe($serializerManager->unserialize($compactJwt));
                } catch (\Throwable $ex) {
                    throw new \InvalidArgumentException('Unable to decode JWE');
                }

                $serializer = new JWSCompactSerializer();
                $jws = $serializer->unserialize($jwe->getPayload());

                $this->verifyJws($jws);
                break;
            default:
                throw new \InvalidArgumentException('Unsupported input');
        }

        return $jws;
    }

    /**
     * @param string $compactJwt
     *
     * @return JWE
     */
    public function extractUserinfo($compactJwt)
    {
        try {
            $serializerManager = new JWESerializerManager([
                new JWECompactSerializer(),
            ]);

            return $this->decryptJwe($serializerManager->unserialize($compactJwt));
        } catch (\Throwable $ex) {
            throw new \InvalidArgumentException('Unable to decode JWE');
        }
    }

    private function verifyJws(JWS &$jws)
    {
        $headerChecker = new HeaderCheckerManager(
            [new AlgorithmChecker(['RS256', 'ES256'])], // A list of header checkers
            [new JWSTokenSupport()]            // A list of token support services (we only use the JWS token type here)
        );

        $algorithmManager = new AlgorithmManager([
            new RS256(), new ES256()
        ]);
        $jwsVerifier = new JWSVerifier($algorithmManager);

        // We check all signatures
        $isVerified = false;
        for ($i = 0; $i < $jws->countSignatures(); $i++) {
            try {
                $headerChecker->check($jws, 0); // We check the header of the first (index=0) signature.        
                if ($jwsVerifier->verifyWithKeySet($jws, $this->serverKeys, 0)) { // We verify the signature
                    $isVerified = true;
                    break;
                }
            } catch (\Exception $e) {
                continue;
            }
        }

        if (!$isVerified) {
            throw new GoodIDException("Can not verify signature: " . $e->getMessage());
        }
    }

    /**
     * @param JWE $jwe
     *
     * @return JWE
     */
    private function decryptJwe(JWE $jwe)
    {
        $keyEncryptionAlgorithmManager = new AlgorithmManager([
            new RSAOAEP(),
        ]);

        $contentEncryptionAlgorithmManager = new AlgorithmManager([
            new A128CBCHS256(),
            new A256CBCHS512(),
        ]);

        // @TODO originally the following was supported by us before jose upgrade:
        // 'DEF', 'ZLIB', 'GZ'
        $compressionMethodManager = new CompressionMethodManager([
            new Deflate(),
        ]);

        $jweDecrypter = new JWEDecrypter(
            $keyEncryptionAlgorithmManager,
            $contentEncryptionAlgorithmManager,
            $compressionMethodManager
        );

        if (!$jweDecrypter->decryptUsingKeySet($jwe, $this->rpKeys, 0)) {
            throw new \Exception('Unable to decode JWE');
        }

        return $jwe;
    }
}