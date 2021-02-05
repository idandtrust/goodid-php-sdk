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

use GoodID\Exception\GoodIDException;
use GoodID\Exception\ValidationException;
use GoodID\Helpers\GoodidSession;
use GoodID\Helpers\Key\RSAPrivateKey;
use GoodID\Helpers\Key\RSAPublicKey;
use GoodID\Helpers\OpenIDRequestSource\OpenIDRequestSource;
use GoodID\Helpers\OpenIDRequestSource\OpenIDRequestURI;
use GoodID\Helpers\Push\PushTokenResponse;
use GoodID\Helpers\Request\IncomingRequest;
use GoodID\Helpers\Response\Claims;
use GoodID\Helpers\Response\LegacyClaimAdapter;
use GoodID\Helpers\Response\ResponseValidator;
use GoodID\Helpers\SecurityLevel;
use GoodID\Helpers\SessionDataHandlerInterface;
use GoodID\ServiceLocator;
use Jose\Object\JWKSet;
use Jose\Object\JWSInterface;

/**
 * This class collects, validates and extracts the IDToken and Userinfo for the RP, using the authorization code
 */
class GoodIDResponse
{
    /**
     * @var string
     */
    private $securityLevel;

    /**
     * @var array|null
     */
    private $data;

    /**
     * @var Claims|null
     */
    private $claims;

    /**
     * @var string|null
     */
    private $error;

    /**
     * @var string|null
     */
    private $errorDescription;

    /**
     * @var string
     */
    private $accessToken;

    /**
     * @var PushTokenResponse|null
     */
    private $pushTokenResponse;

    /**
     * @var string|null
     */
    private $targetLinkUri;

    /**
     * @var string|null
     */
    private $stateData;

    /**
     * @var GoodidSession|null
     */
    private $goodIdSession;

    /**
     * @var JWSInterface
     */
    private $userinfo;

    /**
     * @var JWSInterface
     */
    private $idToken;

    /**
     * GoodIDResponse constructor
     *
     * Collects and validates the user data corresponding to the given
     * authorization code
     *
     * If $matchingResponseValidation is set to FALSE, the following will happen:
     * - The GoodID PHP SDK will not validate whether the response for the
     * *_verified claims which have been requested as essential=true, contain
     * 'true'. This means that the RP will have to check them manually.
     * - When using a request URI, its content will not be downloaded by the
     * GoodID PHP SDK. This is the optimization that makes it worth to provide
     * this setting.
     * - The validity and authenticity of the token will still be checked by the
     * GoodID PHP SDK.
     * - The max_age check will not be performed.
     *
     * @link http://openid.net/specs/openid-connect-core-1_0.html#AuthResponseValidation Authentication Response Validation
     * @link http://openid.net/specs/openid-connect-core-1_0.html#CodeFlowSteps Authorization Code Flow Steps
     *
     * @param ServiceLocator $serviceLocator
     * @param string $clientId The client id of the RP
     * @param string $clientSecret The client secret of the RP
     * @param string $securityLevel
     * @param RSAPrivateKey $signingKey The signing key-pair of the RP
     * @param RSAPrivateKey|array $encryptionKeyOrKeys
     *     The encryption key-pair of the RP.
     *     Can be the same as $signingKey.
     *     To accept tokens encrypted by any of an array of keys, you can pass an array of RSAPrivateKey's too.
     * @param bool $matchingResponseValidation Handle with care, see above
     * @param IncomingRequest $incomingRequest
     *
     * @throws GoodIDException
     */
    public function __construct(
        ServiceLocator $serviceLocator,
        $clientId,
        $clientSecret,
        $securityLevel,
        RSAPrivateKey $signingKey,
        $encryptionKeyOrKeys,
        $matchingResponseValidation = true,
        IncomingRequest $incomingRequest = null
    ) {
        $encryptionKeys = $this->checkAndUnifyEncryptionKeys($encryptionKeyOrKeys);
        $this->securityLevel = $securityLevel;

        $stateNonceHandler = $serviceLocator->getStateNonceHandler();
        $goodidSession = null;

        try {
            $goodIdServerConfig = $serviceLocator->getServerConfig();
            $sessionDataHandler = $serviceLocator->getSessionDataHandler();
            $requestFactory = $serviceLocator->getRequestFactory();
            $this->stateData = $stateNonceHandler->getStateData();

            $incomingRequest = $incomingRequest ?: new IncomingRequest();

            $method = $incomingRequest->getMethod();

            if ($method !== 'GET') {
                throw new GoodIDException("Unexpected request method: $method!");
            }

            if (!$stateNonceHandler->validateState($incomingRequest->getStringParameter('state'))) {
                throw new ValidationException("The received state is invalid.");
            }

            $authCode = $incomingRequest->getStringParameter('code');

            // Handle error case
            if (!$authCode) {
                $this->error = $incomingRequest->getStringParameter('error');

                if (!$this->error) {
                    throw new GoodIDException("Neither code nor error parameter is set.");
                }

                $this->errorDescription = $incomingRequest->getStringParameter('error_description');

                return;
            }

            // Session parameters
            $requestSource = $sessionDataHandler->get(SessionDataHandlerInterface::SESSION_KEY_REQUEST_SOURCE);
            $usedRedirectUri = $sessionDataHandler->get(SessionDataHandlerInterface::SESSION_KEY_USED_REDIRECT_URI);
            $goodidSessionId = $sessionDataHandler->get(SessionDataHandlerInterface::SESSION_KEY_GOODID_SESSION_ID);
            if ($goodidSessionId !== null) {
                $sessionStore = $serviceLocator->getGoodIDSessionStore();
                if ($sessionStore === null) {
                    throw new \LogicException('To use kyc/mobilecommunication features, you must provide a GoodidSessionStore');
                }
                $goodidSession = $serviceLocator->getGoodIDSessionStore()->loadGoodidSession($goodidSessionId);
            }
            // TODO: get targetLinkUri from session (optional)

            if (!$requestSource) {
                throw new GoodIDException("Request source is not set in session!");
            }

            if (!$usedRedirectUri) {
                throw new GoodIDException("Redirect uri is not set in session!");
            }

            // Token request
            $tokenRequest = $requestFactory->createTokenRequest(
                $goodIdServerConfig,
                $clientId,
                $clientSecret,
                $usedRedirectUri,
                $authCode,
                null
            );
            $tokenRequest->execute();

            $rpKeySet = new JWKSet();
            foreach ($encryptionKeys as $key) {
                /* @var $key RSAPrivateKey */
                $rpKeySet->addKey($key->asSpomkyKey(['use' => 'enc', 'alg' => 'RSA-OAEP'], true));
            }

            $jwe = $tokenRequest->getIdTokenJwe();

            $tokenExtractor = $serviceLocator->getTokenExtractor($rpKeySet);

            $usedRequestObjectAsArray = $this->getRequestObjectAsArray($requestSource, $signingKey);

            $requestedMaxAge = isset($usedRequestObjectAsArray['max_age'])
                ? $usedRequestObjectAsArray['max_age']
                : null;

            $authTimeRequested = isset($usedRequestObjectAsArray['claims']) && isset($usedRequestObjectAsArray['claims']['id_token']) && is_array($usedRequestObjectAsArray['claims']['id_token']) && isset($usedRequestObjectAsArray['claims']['id_token']['auth_time']['essential']) && $usedRequestObjectAsArray['claims']['id_token']['auth_time']['essential'] === true;
            $authTimeRequested |= isset($usedRequestObjectAsArray['claims']['userinfo']['auth_time']['essential']) && $usedRequestObjectAsArray['claims']['userinfo']['auth_time']['essential'] === true;

            $idToken = $tokenExtractor->extractToken($jwe);
            $idTokenVerifier = $serviceLocator->getIdTokenVerifier(
                $clientId,
                $securityLevel,
                $requestedMaxAge,
                $authTimeRequested,
                $stateNonceHandler->getCurrentNonce(),
                $idToken->hasClaim('acr') ? $idToken->getClaim('acr') : null
            );
            $idTokenVerifier->verifyIdToken($idToken);

            $userinfoRequest = $requestFactory->createUserinfoRequest(
                $goodIdServerConfig,
                $tokenRequest->getAccessToken()
            );
            $userinfoRequest->execute();

            $userinfo = $tokenExtractor->extractToken($userinfoRequest->getUserInfoJwe());
            $userinfoVerifier = $serviceLocator->getUserinfoVerifier($securityLevel, $idToken);
            $userinfoVerifier->verifyUserinfo($userinfo);

            // Matching response validation
            if ($matchingResponseValidation) {
                if (is_null($usedRequestObjectAsArray)) {
                    throw new ValidationException("Matching response validation cannot succeed because the request object was probably encrypted.");
                }

                if (isset($usedRequestObjectAsArray["claims"]) && is_array($usedRequestObjectAsArray["claims"])) {
                    /** @var $validator ResponseValidator */
                    $validator = $serviceLocator->getResponseValidator();
                    $validator->validateMatchingResponse($usedRequestObjectAsArray["claims"], $userinfo->getClaims());
                }
            }

            $this->accessToken = $tokenRequest->getAccessToken();
            $this->pushTokenResponse = $tokenRequest->getPushTokenResponse();
            $claimAdapter = new LegacyClaimAdapter();

            // Merge tokens
            $this->data = $this->mergeTokens($claimAdapter->adaptIdToken($idToken->getClaims()), $claimAdapter->adaptUserInfo($userinfo->getClaims()));

            $this->claims = new Claims($this->data['claims']);

            $this->idToken = $idToken;
            $this->userinfo = $userinfo;
            $this->goodIdSession = $goodidSession;
        } finally {
            $stateNonceHandler->clear();
            $sessionDataHandler->removeAll();
            if ($goodidSession !== null) {
                $serviceLocator->getGoodIDSessionStore()->clearGoodidSession($goodidSession->getId());
            }
        }
    }

    /**
     *
     * @param RSAPrivateKey|array $encryptionKeyOrKeys
     * @return array Encryption keys
     * @throws GoodIDException
     */
    private function checkAndUnifyEncryptionKeys($encryptionKeyOrKeys)
    {
        if (is_array($encryptionKeyOrKeys)) {
            $encryptionKeys = $encryptionKeyOrKeys;
        } else {
            $encryptionKeys = [$encryptionKeyOrKeys];
        }

        foreach ($encryptionKeys as $encryptionKey) {
            if (!$encryptionKey instanceof RSAPrivateKey) {
                throw new GoodIDException('$encryptionKeyOrKeys must be RSAPrivateKey or array of RSAPrivateKey\'s');
            }
        }

        return $encryptionKeys;
    }

    /**
     * Get request object as array
     *
     * @param array|string $requestSource Request source
     * @param RSAPublicKey $sigPubKey Public signing key
     * @return array|null
     */
    private function getRequestObjectAsArray($requestSource, RSAPublicKey $sigPubKey)
    {
        if (is_array($requestSource)) {
            return $requestSource;
        } elseif (is_string($requestSource) && $requestSource !== OpenIDRequestSource::CONTENT_IS_ENCRYPTED) {
            // FIXME: The request object on the request uri should be loaded into the session on request initiation, not here
            $downloadedRequestSource = (new OpenIDRequestURI($requestSource))->toArray($sigPubKey);

            if ($downloadedRequestSource !== OpenIDRequestSource::CONTENT_IS_ENCRYPTED) {
                return $downloadedRequestSource;
            }
        }

        return null;
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
        if ($this->hasError()) {
            throw new GoodIDException(__METHOD__ . " called when there was an error: "
                . $this->error . ": " . $this->errorDescription);
        }

        if (!isset($this->data['sub'])) {
            throw new GoodIDException("Internal error: sub not set");
        }

        return $this->data['sub'];
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
        if ($this->hasError()) {
            throw new GoodIDException(__METHOD__ . " called when there was an error: "
                . $this->error . ": " . $this->errorDescription);
        }

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
        if ($this->hasError()) {
            throw new GoodIDException(__METHOD__ . " called when there was an error: "
                . $this->error . ": " . $this->errorDescription);
        }

        if ($this->securityLevel !== SecurityLevel::HIGH) {
            throw new GoodIDException("deviceId is available only on 'high' SecurityLevel");
        }

        if (!$this->userinfo->hasClaim('seal')) {
            throw new GoodIDException("Internal error: seal not set");
        }

        return $this->userinfo->getClaim('seal');
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
        if ($this->hasError()) {
            throw new GoodIDException(__METHOD__ . " called when there was an error: "
                . $this->error . ": " . $this->errorDescription);
        }

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
        if ($this->hasError()) {
            throw new GoodIDException(__METHOD__ . " called when there was an error: "
                . $this->error . ": " . $this->errorDescription);
        }

        if ($this->securityLevel !== SecurityLevel::HIGH) {
            throw new GoodIDException("userJWK is available only on 'high' SecurityLevel");
        }

        if (!$this->userinfo->hasClaim('user_jwk')) {
            throw new GoodIDException("Internal error: user_jwk not set");
        }

        return $this->userinfo->getClaim('user_jwk');
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
        if ($this->hasError()) {
            throw new GoodIDException(__METHOD__ . " called when there was an error: "
                . $this->error . ": " . $this->errorDescription);
        }

        if (!$this->userinfo->hasClaim('user_enc_jwk')) {
            throw new GoodIDException("Internal error: user_enc_jwk not set");
        }

        return $this->userinfo->getClaim('user_enc_jwk');
    }

    /**
     * Returns the received data as a single multilevel array
     *
     * @return array user data
     *
     * @throws GoodIDException
     */
    public function toArray()
    {
        if ($this->hasError()) {
            throw new GoodIDException(__METHOD__ . " called when there was an error: "
                . $this->error . ": " . $this->errorDescription);
        }

        return $this->data;
    }

    /**
     * Returns the received data encoded as a JSON string
     *
     * @return string use data JSON
     *
     * @throws GoodIDException
     */
    public function toJson()
    {
        if ($this->hasError()) {
            throw new GoodIDException(__METHOD__ . " called when there was an error: "
                . $this->error . ": " . $this->errorDescription);
        }

        return json_encode((object)$this->data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

    /**
     * Returns the Claims object containing the received claims
     *
     * @return Claims The Claims object
     *
     * @throws GoodIDException
     */
    public function getClaims()
    {
        if ($this->hasError()) {
            throw new GoodIDException(__METHOD__ . " called when there was an error: "
                . $this->error . ": " . $this->errorDescription);
        }

        return $this->claims;
    }

    /**
     * Has error?
     *
     * @return bool hasError
     */
    public function hasError()
    {
        return !is_null($this->error);
    }

    /**
     * Get error
     *
     * If hasError() then the return value is guaranteed to be string.
     *
     * @return string|null error
     */
    public function getError()
    {
        return $this->error;
    }

    /**
     * Get error description
     *
     * If hasError() then the return value is guaranteed to be string.
     *
     * @return string|null errorDescription
     */
    public function getErrorDescription()
    {
        return $this->errorDescription;
    }

    /**
     * Has access token?
     *
     * @return bool has access token
     */
    public function hasAccessToken()
    {
        return !is_null($this->accessToken);
    }

    /**
     * Get access token
     *
     * @return string access token
     */
    public function getAccessToken()
    {
        if (!$this->hasAccessToken()) {
            throw new GoodIDException("We don't have an access token.");
        }

        return $this->accessToken;
    }
    
    /**
     * @return bool
     */
    public function hasPushToken()
    {
        return !is_null($this->pushTokenResponse);
    }

    /**
     * @return PushTokenResponse|null
     */
    public function getPushTokenResponse()
    {
        return $this->pushTokenResponse;
    }

    /**
     * Get target link uri
     *
     * @return null|string
     */
    public function getTargetLinkUri()
    {
        return $this->targetLinkUri;
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
     * @return string|null
     */
    public function getStateData()
    {
        return $this->stateData;
    }

    /**
     * @return GoodidSession|null
     */
    public function getGoodIDSession()
    {
        return $this->goodIdSession;
    }

    /**
     * @return string
     */
    public function getIdTokenJWS()
    {
        return $this->idToken->toCompactJSON(0);
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
}
