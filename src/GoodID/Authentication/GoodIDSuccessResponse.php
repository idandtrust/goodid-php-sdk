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

namespace GoodID\Authentication;

use Jose\Component\Signature\JWS;
use Jose\Component\Encryption\JWE;
use GoodID\Helpers\Request\TokenRequest;
use GoodID\Exception\GoodIDException;
use GoodID\Helpers\GoodidSession;
use GoodID\Helpers\Push\PushTokenResponse;
use GoodID\Helpers\Response\Claims;
use GoodID\Helpers\Response\LegacyClaimAdapter;
use GoodID\Helpers\SecurityLevel;
use Jose\Component\Core\Util\JsonConverter;
use Jose\Component\Signature\Serializer\CompactSerializer;

class GoodIDSuccessResponse extends AbstractGoodIDResponse
{
    const USERINFO_KEY_ATTACHMENTS = 'attachments';

    private $idToken;
    private $userinfo;
    private $idTokenClaims = array();
    private $userinfoClaims = array();
    private $claimAdapter;
    private $goodIDSession;
    private $state;
    private $tokenRequest;
    private $data = array();
    private $claims;
    private $securityLevel;

    /**
     * @param JWS $idToken
     * @param JWE $userinfo
     * @param string $state
     * @param TokenRequest $tokenRequest
     * @param string $securityLevel
     * @param GoodIDSession $goodIdSession
     */
    public function __construct(
        JWS $idToken,
        JWE $userinfo,
        $state,
        TokenRequest $tokenRequest,
        $securityLevel,
        GoodidSession $goodIdSession = null
    ) {
        $this->idToken = $idToken;
        $this->userinfo = $userinfo;
        $this->claimAdapter = new LegacyClaimAdapter();
        $this->state = $state;
        $this->tokenRequest = $tokenRequest;
        $this->securityLevel = $securityLevel;
        $this->goodIDSession = $goodIdSession;
        $this->idTokenClaims = JsonConverter::decode($this->idToken->getPayload());
        $this->userinfoClaims = JsonConverter::decode($this->userinfo->getPayload());

        $this->data = $this->mergeTokens(
            $this->claimAdapter->adaptIdToken($this->idTokenClaims),
            $this->claimAdapter->adaptUserInfo($this->userinfoClaims)
        );
        $this->claims = new Claims($this->data['claims']);
    }

    /**
     * @return string
     */
    public function getState()
    {
        return $this->state;
    }

    /**
     * @return GoodidSession|null
     */
    public function getGoodIDSession()
    {
        return $this->goodIDSession;
    }

    /**
     * @return string
     */
    public function getIdTokenJWS()
    {
        $compactSerializer = new CompactSerializer();
        return $compactSerializer->serialize($this->idToken);
    }

    /**
     * @return JWE
     */
    public function getUserinfoJWEObject()
    {
        return $this->userinfo;
    }

    /**
     * @return JWS
     */
    public function getIdTokenJWSObject()
    {
        return $this->idToken;
    }

    /**
     * @return array
     */
    public function getIdTokenClaims()
    {
        return $this->idTokenClaims;
    }

    /**
     * @return array
     */
    public function getUserinfoClaims()
    {
        return $this->userinfoClaims;
    }

    /**
     * @return PushTokenResponse|null
     */
    public function getPushTokenResponse()
    {
        return $this->tokenRequest->getPushTokenResponse();
    }

    /**
     * Has access token?
     *
     * @return bool has access token
     */
    public function hasAccessToken()
    {
        return $this->tokenRequest->hasAccessToken();
    }

    /**
     * Get access token
     *
     * @return string|null access token
     */
    public function getAccessToken()
    {
        return $this->tokenRequest->getAccessToken();
    }
    
    /**
     * @return bool
     */
    public function hasPushToken()
    {
        return $this->tokenRequest->hasPushToken();
    }

    /**
     * Returns the Claims object containing the received claims
     *
     * @return Claims The Claims object
     */
    public function getClaims()
    {
        return $this->claims;
    }

    /**
     * Merge Tokens
     *
     * @param array $idToken ID Token
     * @param array $userinfo Userinfo
     *
     * @return array Data
     */
    private function mergeTokens(array $idToken, array $userinfo)
    {
        unset($idToken['claims']);
        $data = $idToken;
        $data['claims'] = (isset($userinfo['claims']) && is_array($userinfo['claims']))
            ? $userinfo['claims']
            : [];

        return $data;
    }

    /**
     * Returns the received data encoded as a JSON string
     *
     * @return string use data JSON
     */
    public function toJson()
    {
        return json_encode((object)$this->data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

    /**
     * Returns the received data as a single multilevel array
     *
     * @return array user data
     */
    public function toArray()
    {
        return $this->data;
    }

    /**
     * Returns the encryption key for the GoodID user
     *
     * @return string User enc JWK
     *
     * @throws GoodIDException
     */
    public function getUserEncJWK()
    {
        if (!isset($this->userinfoClaims['user_enc_jwk'])) {
            throw new GoodIDException("Internal error: user_enc_jwk not set");
        }

        return $this->userinfoClaims['user_enc_jwk'];
    }

    /**
     * Returns the user JWK of the GoodID user if the security level of the RP is high
     *
     * @return array|null Device JWK
     *
     * @throws GoodIDException
     */
    public function getDeviceJWK()
    {
        if ($this->securityLevel !== SecurityLevel::HIGH) {
            throw new GoodIDException("deviceJWK is available only on 'high' SecurityLevel");
        }

        if (!isset($this->userinfoClaims['seal_jwk'])) {
            throw new GoodIDException("Internal error: seal_jwk not set");
        }

        return $this->userinfoClaims['seal_jwk'];
    }

    /**
     * Returns the user JWK of the GoodID user if the security level of the RP is high
     *
     * @return array|null User JWK
     *
     * @throws GoodIDException
     */
    public function getUserJWK()
    {
        if ($this->securityLevel !== SecurityLevel::HIGH) {
            throw new GoodIDException("userJWK is available only on 'high' SecurityLevel");
        }

        if (!isset($this->userinfoClaims['user_jwk'])) {
            throw new GoodIDException("Internal error: user_jwk not set");
        }

        return $this->userinfoClaims['user_jwk'];
    }

    /**
     * Returns the identifier of the GoodID user if the security level of the RP is high
     *
     * @return string User identifier
     *
     * @throws GoodIDException
     */
    public function getUserId()
    {
        if ($this->securityLevel !== SecurityLevel::HIGH) {
            throw new GoodIDException("userId is available only on 'high' SecurityLevel");
        }

        if (!isset($this->userinfoClaims['user'])) {
            throw new GoodIDException("Internal error: user not set");
        }

        return $this->userinfoClaims['user'];
    }

    /**
     * Returns the identifier of the device of the GoodID user if the security level of the RP is high
     *
     * @return string Device identifier
     *
     * @throws GoodIDException
     */
    public function getDeviceId()
    {
        if ($this->securityLevel !== SecurityLevel::HIGH) {
            throw new GoodIDException("deviceId is available only on 'high' SecurityLevel");
        }

        if (!isset($this->userinfoClaims['seal'])) {
            throw new GoodIDException("Internal error: seal not set");
        }

        return $this->userinfoClaims['seal'];
    }

    /**
     * Returns a reference for the identity of the user at the signature provider.
     * 
     * @return string|null
     */
    public function getSignatureIdReference()
    {
        return isset($this->userinfoClaims['signature_id_ref'])
            ? $this->userinfoClaims['signature_id_ref']
            : null;
    }

    /**
     * Returns the subject identifier of the GoodID user
     *
     * @return string Subject identifier
     *
     * @throws GoodIDException
     */
    public function getSub()
    {
        if (!isset($this->data['sub'])) {
            throw new GoodIDException("Internal error: sub not set");
        }

        return $this->data['sub'];
    }

    /**
     * @return boolean
     */
    public function isSuccessful()
    {
        return true;
    }
}
