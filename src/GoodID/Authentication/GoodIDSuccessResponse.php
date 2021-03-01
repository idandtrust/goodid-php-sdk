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

use Jose\Object\JWSInterface;
use GoodID\Helpers\Request\TokenRequest;
use GoodID\Exception\GoodIDException;
use GoodID\Helpers\GoodidSession;
use GoodID\Helpers\Push\PushTokenResponse;
use GoodID\Helpers\Response\Claims;
use GoodID\Helpers\Response\LegacyClaimAdapter;
use GoodID\Helpers\SecurityLevel;

class GoodIDSuccessResponse extends AbstractGoodIDResponse
{
    const USERINFO_KEY_ATTACHMENTS = 'attachments';

    private $idToken;
    private $userinfo;
    private $claimAdapter;
    private $goodIDSession;
    private $state;
    private $tokenRequest;
    private $data = array();
    private $claims;
    private $securityLevel;

    /**
     * @param JWSInterface $idToken
     * @param JWSInterface $userinfo
     * @param string $state
     * @param TokenRequest $tokenRequest
     * @param string $securityLevel
     * @param GoodIDSession $goodIdSession
     */
    public function __construct(
        JWSInterface $idToken,
        JWSInterface $userinfo,
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

        $this->data = $this->mergeTokens(
                $this->claimAdapter->adaptIdToken($idToken->getClaims()),
                $this->claimAdapter->adaptUserInfo($userinfo->getClaims())
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
        return $this->idToken->toCompactJSON(0);
    }

    /**
     * @return JWSInterface
     */
    public function getUserinfoJWSObject()
    {
        return $this->userinfo;
    }

    /**
     * @return JWSInterface
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
        return $this->idToken->getClaims();
    }

    /**
     * @return array
     */
    public function getUserinfoClaims()
    {
        return $this->userinfo->getClaims();
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
        if (!$this->userinfo->hasClaim('user_enc_jwk')) {
            throw new GoodIDException("Internal error: user_enc_jwk not set");
        }

        return $this->userinfo->getClaim('user_enc_jwk');
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

        if (!$this->userinfo->hasClaim('seal_jwk')) {
            throw new GoodIDException("Internal error: seal_jwk not set");
        }

        return $this->userinfo->getClaim('seal_jwk');
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

        if (!$this->userinfo->hasClaim('user_jwk')) {
            throw new GoodIDException("Internal error: user_jwk not set");
        }

        return $this->userinfo->getClaim('user_jwk');
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

        if (!$this->userinfo->hasClaim('user')) {
            throw new GoodIDException("Internal error: user not set");
        }

        return $this->userinfo->getClaim('user');
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

        if (!$this->userinfo->hasClaim('seal')) {
            throw new GoodIDException("Internal error: seal not set");
        }

        return $this->userinfo->getClaim('seal');
    }

    /**
     * Returns a reference for the identity of the user at the signature provider.
     * 
     * @return string|null
     */
    public function getSignatureIdReference()
    {
        return $this->userinfo->getClaim('signature_id_ref');
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
     * @return array|null
     */
    public function getValidAttachments()
    {
        return $this->userinfo->hasClaim(self::USERINFO_KEY_ATTACHMENTS)
                ? $this->userinfo->getClaim(self::USERINFO_KEY_ATTACHMENTS)
                : null;
    }

    /**
     * @return boolean
     */
    public function isSuccessful()
    {
        return true;
    }
}
