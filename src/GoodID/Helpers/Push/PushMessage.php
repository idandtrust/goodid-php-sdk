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

namespace GoodID\Helpers\Push;

use GoodID\Helpers\Key\RSAPrivateKey;
use Jose\Factory\JWEFactory;
use Jose\Component\Core\JWK;

class PushMessage
{
    private $clientId;
    private $description;
    private $payload;
    private $sigKey;
    private $expiresIn;

    /**
     * @var JWK 
     */
    private $encryptionKey;

    /**
     * @param string $clientId
     * @param string $description
     * @param RSAPrivateKey $sigKey
     * @param string|null $payload
     * @param string|null $expiresIn
     * @param string|null $encryptionKey
     */
    public function __construct(
        $clientId,
        $description,
        RSAPrivateKey $sigKey,
        $payload = null,
        $expiresIn = null,
        $encryptionKey = null
    ) {
        $this->clientId = $clientId;
        $this->description = $description;
        $this->payload = $payload;
        $this->sigKey = $sigKey;

        if ($payload && !$encryptionKey) {
            throw new \Exception('The payload must be encrypted.');
        }

        if ($encryptionKey) {
            $this->encryptionKey = new JWK(json_decode($encryptionKey, true));
        }

        $this->expiresIn = $expiresIn && is_numeric($expiresIn) ? $expiresIn : 3600 * 24;
    }

    /**
     * @return string
     */
    public function getJWT()
    {
        $payload = $this->payload;

        if ($this->encryptionKey) {
            $payload = JWEFactory::createJWEToCompactJSON(
                $this->payload,                    // The message to encrypt
                $this->encryptionKey,              // The key of the recipient
                [
                    'alg' => 'RSA-OAEP',
                    'enc' => 'A256CBC-HS512'
                ]
            );
        }

        $request = array(
            'iss' => $this->clientId,
            'iat' => time(),
            'nbf' => time(),
            'exp' => strtotime('+' . $this->expiresIn . ' seconds'),
            'description' => $this->description,
            'payload' => $payload
        );

        return $this->sigKey->signAsCompactJws($request);
    }
}