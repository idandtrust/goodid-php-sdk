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
use GoodID\Helpers\Key\RSAPrivateKey;
use GoodID\Helpers\Key\RSAPublicKey;
use GoodID\Helpers\OpenIDRequestSource\OpenIDRequestSource;
use GoodID\Helpers\OpenIDRequestSource\OpenIDRequestURI;
use GoodID\Helpers\Request\IncomingRequest;
use GoodID\Helpers\Response\Claims;
use GoodID\Helpers\SessionDataHandlerInterface;
use GoodID\ServiceLocator;

/**
 * This class collects, validates and extracts the IDToken and Userinfo for the RP, using the authorization code
 */
class GoodIDResponse
{
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
     *
     * @var string
     */
    private $accessToken;

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
        RSAPrivateKey $signingKey,
        $encryptionKeyOrKeys,
        $matchingResponseValidation = true,
        IncomingRequest $incomingRequest = null
    ) {
        $encryptionKeys = $this->checkAndUnifyEncryptionKeys($encryptionKeyOrKeys);

        try {
            $goodIdServerConfig = $serviceLocator->getServerConfig();
            $sessionDataHandler = $serviceLocator->getSessionDataHandler();
            $requestFactory = $serviceLocator->getRequestFactory();

            $incomingRequest = $incomingRequest ?: new IncomingRequest();

            $method = $incomingRequest->getMethod();

            if ($method !== 'GET') {
                throw new GoodIDException("Unexpected request method: $method!");
            }

            $validator = $serviceLocator->getResponseValidator($clientId);
            $validator->validateState($incomingRequest->getStringParameter('state'));

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
            $appInitiated = $sessionDataHandler->get(SessionDataHandlerInterface::SESSION_KEY_APP_INITIATED);
            $usedRedirectUri = $sessionDataHandler->get(SessionDataHandlerInterface::SESSION_KEY_USED_REDIRECT_URI);

            if (!$requestSource) {
                throw new GoodIDException("Request source is not set in session!");
            }

            if (is_null($appInitiated)) {
                throw new GoodIDException("App-initiated is not set in session!");
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
                $appInitiated ? $requestSource : null
            );
            $tokenRequest->execute();

            $usedRequestObjectAsArray = $this->getRequestObjectAsArray($requestSource, $signingKey);

            $requestedMaxAge = isset($usedRequestObjectAsArray['max_age'])
                ? $usedRequestObjectAsArray['max_age']
                : null;

            list($goodEncryptionKey, $idTokenJws) = $this->decryptWithAny($encryptionKeys, $tokenRequest->getIdTokenJwe());

            $idToken = $validator->validateIdToken($idTokenJws, $clientSecret, $tokenRequest->getGoodIDServerTime(), $requestedMaxAge, $authCode, $tokenRequest->isTotpEnabled());

            if ($tokenRequest->hasAccessToken()) {
                $accessToken = $tokenRequest->getAccessToken();

                // Userinfo request
                $userinfoRequest = $requestFactory->createUserinfoRequest(
                    $goodIdServerConfig,
                    $accessToken
                );
                $userinfoRequest->execute();

                $userinfoJws = $goodEncryptionKey->decryptCompactJwe($userinfoRequest->getUserinfoJwe());
                $userinfo = $validator->validateUserInfo($userinfoJws);

                // Validate tokens belong together
                $validator->validateTokensBelongTogether($idToken, $userinfo);

                // Matching response validation
                if ($matchingResponseValidation) {
                    if (!is_null($usedRequestObjectAsArray)
                        && isset($usedRequestObjectAsArray["claims"])
                        && is_array($usedRequestObjectAsArray["claims"])
                    ) {
                        $validator->validateMatchingResponse($usedRequestObjectAsArray["claims"], $userinfo);
                    } else {
                        throw new ValidationException("Matching response validation cannot succeed because the request object was probably encrypted, or nothing was requested.");
                    }
                }

                $this->accessToken = $accessToken;
                // Merge tokens
                $this->data = $this->mergeTokens($idToken, $userinfo);
            } else {
                $this->accessToken = null;
                $this->data = $this->mergeTokens($idToken, []);
            }

            $this->claims = new Claims($this->data['claims']);
        } finally {
            $sessionDataHandler->removeAll();
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
     *
     * @param array $encPrivKeys Encryption Private Keys
     * @param string $jwe JWE
     * @return string JWS
     * @throws GoodIDException
     */
    private function decryptWithAny(array $encPrivKeys, $jwe)
    {
        $exceptionMessages = '';

        foreach ($encPrivKeys as $encryptionKey) {
            try {
                return [
                    $encryptionKey,
                    $encryptionKey->decryptCompactJwe($jwe)
                ];
            } catch (GoodIDException $e) {
                $exceptionMessages .= $e->getMessage() . ', ';
            }
        }

        throw new GoodIDException('No key could decrypt: ' . $exceptionMessages);
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
            $downloadedRequestSource = (new OpenIDRequestURI($requestSource))->toArray($sigPubKey);

            if ($downloadedRequestSource !== OpenIDRequestSource::CONTENT_IS_ENCRYPTED) {
                return $downloadedRequestSource;
            }
        }

        return null;
    }

    /**
     * Returns the identifier of the GoodID user
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
     * @return access token
     */
    public function getAccessToken()
    {
        if (!$this->hasAccessToken()) {
            throw new GoodIDException("We don't have an access token.");
        }

        return $this->accessToken;
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
}
