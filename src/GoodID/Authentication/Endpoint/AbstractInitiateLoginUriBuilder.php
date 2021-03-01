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

namespace GoodID\Authentication\Endpoint;

use GoodID\Exception\GoodIDException;
use GoodID\Helpers\Config;
use GoodID\Helpers\GoodIDServerConfig;
use GoodID\Helpers\GoodidSessionStoreInterface;
use GoodID\Helpers\Key\RSAPrivateKey;
use GoodID\Helpers\MobileCommunicationRequestDataInterface;
use GoodID\Helpers\MobileCommunicationServiceInterface;
use GoodID\Helpers\OpenIDRequestSource\OpenIDRequestObject;
use GoodID\Helpers\OpenIDRequestSource\OpenIDRequestObjectJWT;
use GoodID\Helpers\OpenIDRequestSource\OpenIDRequestURI;
use GoodID\Helpers\OpenIDRequestSource\OpenIDRequestSource;
use GoodID\Helpers\Request\IncomingRequest;
use GoodID\Helpers\SessionDataHandlerInterface;
use GoodID\Helpers\StateNonceHandler;
use GoodID\Helpers\UrlSafeBase64Encoder;

abstract class AbstractInitiateLoginUriBuilder
{
    /**
     * @var IncomingRequest
     */
    protected $incomingRequest;

    /**
     * @var string
     */
    protected $clientId;

    /**
     * @var RSAPrivateKey
     */
    protected $signingKey;

    /**
     * @var RSAPrivateKey
     */
    protected $encryptionKey;

    /**
     * @var OpenIDRequestSource
     */
    protected $requestSource;

    /**
     * @var string
     */
    protected $redirectUri;

    /**
     *
     * @var int
     */
    protected $maxAge;

    /**
     * @var GoodIDServerConfig
     */
    protected $goodIdServerConfig;

    /**
     * @var SessionDataHandlerInterface
     */
    protected $sessionDataHandler;

    /**
     * @var StateNonceHandler
     */
    protected $stateNonceHandler;

    /**
     * @var GoodidSessionStoreInterface
     */
    protected $goodidSessionProvider;

    /**
     * @var MobileCommunicationServiceInterface
     */
    protected $mobileCommunicationService;

    /**
     * @var MobileCommunicationRequestData 
     */
    protected $mobileCommunicationRequestData;

    /**
     * @var string
     */
    protected $idTokenHint;

    /**
      *
      * @var string|null
      */
     protected $appResponseUri;

    /**
     * For comments see GoodIDEndpointFactory
     *
     * @param IncomingRequest $incomingRequest
     * @param string $clientId
     * @param RSAPrivateKey $signingKey
     * @param RSAPrivateKey $encryptionKey
     * @param OpenIDRequestSource $requestSource
     * @param string $redirectUri
     * @param GoodIDServerConfig $goodIdServerConfig
     * @param SessionDataHandlerInterface $sessionDataHandler
     * @param StateNonceHandler $stateNonceHandler
     * @param int|null $maxAge
     * @param string|null $idTokenHint
     * @param string|null $appResponseUri
     */
    public function __construct(
        IncomingRequest $incomingRequest,
        $clientId,
        RSAPrivateKey $signingKey,
        RSAPrivateKey $encryptionKey,
        OpenIDRequestSource $requestSource,
        $redirectUri,
        GoodIDServerConfig $goodIdServerConfig,
        SessionDataHandlerInterface $sessionDataHandler,
        StateNonceHandler $stateNonceHandler,
        $maxAge = null,
        $idTokenHint = null,
        $appResponseUri = null
    ) {
        if (empty($clientId)) {
            throw new GoodIDException('$clientId can not be empty');
        }

        if (!is_null($maxAge) && (!is_int($maxAge) || $maxAge < 0)) {
            throw new GoodIDException('$maxAge must be null or a non-negative integer');
        }

        $this->incomingRequest = $incomingRequest;
        $this->clientId = $clientId;
        $this->signingKey = $signingKey;
        $this->encryptionKey = $encryptionKey;
        $this->requestSource = $requestSource;
        $this->redirectUri = $redirectUri;
        $this->maxAge = $maxAge;
        $this->goodIdServerConfig = $goodIdServerConfig;
        $this->sessionDataHandler = $sessionDataHandler;
        $this->stateNonceHandler = $stateNonceHandler;
        $this->idTokenHint = $idTokenHint;
        $this->appResponseUri = $appResponseUri;
    }

    public function setGoodidSessionProvider(GoodidSessionStoreInterface $goodidSessionProvider) {
        $this->goodidSessionProvider = $goodidSessionProvider;
    }

    public function getGoodidSessionProvider()
    {
        return $this->goodidSessionProvider;
    }

    /**
     * This will run the main logic of the concrete endpoint
     * It might set headers, print messages, etc
     */
    abstract public function run();

    /**
     * @param MobileCommunicationServiceInterface $mobileCommunicationService
     * @param MobileCommunicationRequestDataInterface $mobileCommunicationRequestData
     * 
     * @return $this
     */
    public function setMobileCommunicationRequest(
        MobileCommunicationServiceInterface $mobileCommunicationService,
        MobileCommunicationRequestDataInterface $mobileCommunicationRequestData
    ) {
        if (!$this->goodidSessionProvider) {
            throw new \LogicException('To use mobilecommunication features, you must provide a GoodidSessionStore');
        }

        $this->mobileCommunicationService = $mobileCommunicationService;
        $this->mobileCommunicationRequestData = $mobileCommunicationRequestData;

        return $this;
    }

    /**
     * @param string $idTokenHint
     */
    public function setIdTokenHint($idTokenHint)
    {
        $this->idTokenHint = $idTokenHint;
    }

    /**
     * @return string
     * 
     * @throws GoodIDException
     */
    protected function getExtParam()
    {
        $ext = $this->incomingRequest->getStringParameter('ext');

        if ($ext) {
            $ext = json_decode(UrlSafeBase64Encoder::decode($ext), true);
            if (!is_array($ext)) {
                throw new GoodIDException('Request parameter config is invalid.');
            }
        } else {
            $ext = array();
        }

        $ext['sdk_version'] = Config::GOODID_PHP_SDK_VERSION;
        $ext['profile_version'] = Config::GOODID_PROFILE_VERSION;

        return UrlSafeBase64Encoder::encode(json_encode($ext));
    }

    /**
     * @return void
     * 
     * @throws GoodIDException
     */
    protected function setSessionData()
    {
        $this->sessionDataHandler->set(
            SessionDataHandlerInterface::SESSION_KEY_USED_REDIRECT_URI,
            $this->redirectUri);

        if ($this->requestSource instanceof OpenIDRequestURI) {
            $this->sessionDataHandler->set(
                SessionDataHandlerInterface::SESSION_KEY_REQUEST_SOURCE,
                $this->requestSource->getRequestUri()
            );
        } elseif ($this->requestSource instanceof OpenIDRequestObject) {
            $this->sessionDataHandler->set(
                SessionDataHandlerInterface::SESSION_KEY_REQUEST_SOURCE,
                    $this->requestSource->toArray(
                        $this->clientId,
                        $this->redirectUri,
                        $this->goodIdServerConfig,
                        $this->maxAge,
                        $this->appResponseUri
                ));
        } elseif ($this->requestSource instanceof OpenIDRequestObjectJWT) {
            $this->sessionDataHandler->set(
                SessionDataHandlerInterface::SESSION_KEY_REQUEST_SOURCE,
                $this->requestSource->toArray($this->signingKey)
            );
        } else {
            throw new GoodIDException("Unsupported OpenIDRequestSource");
        }

        if ($this->mobileCommunicationService) {
            $this->sessionDataHandler->set(
                SessionDataHandlerInterface::SESSION_KEY_GOODID_SESSION_ID,
                $this->mobileCommunicationRequestData->getGoodIDSession()->getId()
            );
        }
    }

    /**
     * @return array
     * 
     * @throws GoodIDException
     */
    protected function buildQueryParams()
    {
        $loginHint = $this->incomingRequest->getStringParameter('login_hint');
        $uiLocales = $this->incomingRequest->getStringParameter('ui_locales');
        $scopes = $this->requestSource->getScopes($this->signingKey);

        $queryParams = [
            'response_type' => OpenIDRequestObject::RESPONSE_TYPE_CODE,
            'client_id' => $this->clientId,
            'scope' => implode(' ', $scopes),
            'state' => $this->stateNonceHandler->generateState(),
            'nonce' => $this->stateNonceHandler->generateNonce(),
            'ui_locales' => $uiLocales,
            'ext' => $this->getExtParam()
        ];

        if ($loginHint) {
            $queryParams['login_hint'] = $loginHint;
        }

        if ($this->idTokenHint) {
            if (in_array('sign_up', $scopes)) {
                throw new \InvalidArgumentException('The sign_up scope is for registration only.');
            }

            $queryParams['id_token_hint'] = $this->idTokenHint;
        }

        if ($this->requestSource instanceof OpenIDRequestURI) {
            $queryParams['request_uri'] = $this->requestSource->getRequestUri();
        } elseif ($this->requestSource instanceof OpenIDRequestObject) {
            $requestObjectAsArray = $this->requestSource->toArray(
                $this->clientId,
                $this->redirectUri,
                $this->goodIdServerConfig,
                $this->maxAge,
                $this->appResponseUri
            );

            $queryParams['request'] = $this->requestSource->generateFromArray(
                    $requestObjectAsArray, $this->signingKey);
        } elseif ($this->requestSource instanceof OpenIDRequestObjectJWT) {
            $queryParams['request'] = $this->requestSource->getJwt();
        } else {
            throw new GoodIDException("Unsupported OpenIDRequestSource");
        }

        if ($this->mobileCommunicationService) {
            $this->mobileCommunicationService->createRequest($this->mobileCommunicationRequestData, $queryParams);
        }

        return $queryParams;
    }

    /**
     * @return void
     */
    protected function saveGoodIDSession()
    {
        if ($this->mobileCommunicationService) {
            $goodidSession = $this->mobileCommunicationRequestData->getGoodIDSession();
            $this->goodidSessionProvider->storeGoodidSession($goodidSession);
        }
    }
}
