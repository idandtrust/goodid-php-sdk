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

namespace GoodID\Helpers;

use GoodID\Helpers\Key\RSAPrivateKey;
use GoodID\Helpers\SecurityLevel;
use Jose\Object\JWKSet;

class GoodIDPartnerConfig
{
    private $clientId;
    private $clientSecret;
    private $securityLevel;
    private $signingKey;
    private $encryptionKey;
    private $inactiveEncryptionKeys = array();
    private $signingKeyInMobileCommunication;

    /**
     * @param string $clientId
     * @param string $clientSecret
     * @param RSAPrivateKey $signingKey
     * @param RSAPrivateKey $encryptionKey
     * @param string $securityLevel
     * @param ECPrivateKey|null $signingKeyInMobileCommunication
     */
    public function __construct(
        $clientId,
        $clientSecret,
        RSAPrivateKey $signingKey,
        RSAPrivateKey $encryptionKey,
        $securityLevel = null,
        ECPrivateKey $signingKeyInMobileCommunication = null
    ) {
        if (!$securityLevel) {
            $securityLevel = SecurityLevel::NORMAL;
        } else if (!SecurityLevel::isValid($securityLevel)) {
            throw new \InvalidArgumentException('Invalid security level: ' . $securityLevel);
        }

        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->signingKey = $signingKey;
        $this->encryptionKey = $encryptionKey;
        $this->securityLevel = $securityLevel;
        $this->signingKeyInMobileCommunication = $signingKeyInMobileCommunication;
    }

    /**
     * @return string
     */
    public function getClientId()
    {
        return $this->clientId;
    }

    /**
     * @return string
     */
    public function getClientSecret()
    {
        return $this->clientSecret;
    }

    /**
     * @return string
     */
    public function getSecurityLevel()
    {
        return $this->securityLevel;
    }

    /**
     * @return RSAPrivateKey
     */
    public function getSigningKey()
    {
        return $this->signingKey;
    }

    /**
     * @return RSAPrivateKey
     */
    public function getEncryptionKey()
    {
        return $this->encryptionKey;
    }

    /**
     * @param RSAPrivateKey $inactiveEncrytionKey
     */
    public function addEncryptionKey(RSAPrivateKey $inactiveEncrytionKey)
    {
        $this->inactiveEncryptionKeys[] = $inactiveEncrytionKey;
    }

    /**
     * @return array
     */
    public function getEncryptionKeys()
    {
        return array_merge($this->inactiveEncryptionKeys, array($this->encryptionKey));
    }

    /**
     * @return JWKSet
     */
    public function getEncryptionKeySet()
    {
        $keySet = new JWKSet();
        foreach ($this->getEncryptionKeys() as $key) {
            /* @var $key RSAPrivateKey */
            $keySet->addKey($key->asSpomkyKey(['use' => 'enc', 'alg' => 'RSA-OAEP'], true));
        }

        return $keySet;
    }

    /**
     * @return ECPrivateKey|null
     */
    public function getSigningKeyInMobileCommunication()
    {
        return $this->signingKeyInMobileCommunication;
    }
}