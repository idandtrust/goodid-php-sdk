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

namespace GoodID;

use GoodID\Authentication\ResponseHandler;
use GoodID\Helpers\GoodIDServerConfig;
use GoodID\Helpers\GoodidSessionStoreInterface;
use GoodID\Helpers\Request\RequestFactory;
use GoodID\Helpers\Response\IdTokenVerifier;
use GoodID\Helpers\Response\ResponseValidator;
use GoodID\Helpers\Response\TokenExtractor;
use GoodID\Helpers\Response\UserinfoVerifier;
use GoodID\Helpers\SessionDataHandler;
use GoodID\Helpers\SessionDataHandlerInterface;
use GoodID\Helpers\StateNonceHandler;
use GoodIDPass\GoodidPassService;
use GoodIDPass\PassApi\CurlPassApi;
use Jose\Object\JWKSetInterface;
use Jose\Object\JWSInterface;

/**
 * Utility class
 *
 * It seamlessly handles creation of various dependencies by providing default
 * implementations/wiring.
 */
class ServiceLocator
{
    /**
     * @var GoodIDServerConfig
     */
    private $serverConfig;

    /**
     * @var SessionDataHandlerInterface
     */
    private $sessionDataHandler;

    /**
     * @var StateNonceHandler
     */
    private $stateNonceHandler;

    /**
     * @var ResponseValidator
     */
    private $responseValidator;

    /**
     * @var RequestFactory
     */
    private $requestFactory;

    /**
     * @var GoodidPassService
     */
    private $passService;

    /**
     * @var TokenExtractor
     */
    private $tokenExtractor;

    /**
     * @var ResponseHandler|null
     */
    private $responseHandler;

    /**
     * @var GoodidSessionStoreInterface|null
     */
    private $goodidSessionStore;

    /**
     * @return GoodIDServerConfig
     */
    public function getServerConfig()
    {
        if (!isset($this->serverConfig)) {
            $this->serverConfig = $this->createServerConfig();
        }

        return $this->serverConfig;
    }

    /**
     * @return GoodIDServerConfig
     */
    protected function createServerConfig()
    {
        return new GoodIDServerConfig();
    }

    /**
     * @param GoodIDServerConfig $serverConfig
     */
    public function setServerConfig(GoodIDServerConfig $serverConfig)
    {
        $this->serverConfig = $serverConfig;
    }

    /**
     * @return SessionDataHandler
     */
    public function getSessionDataHandler()
    {
        if (!isset($this->sessionDataHandler)) {
            $this->sessionDataHandler = $this->createSessionDataHandler();
        }

        return $this->sessionDataHandler;
    }

    /**
     * @param SessionDataHandlerInterface $sessionDataHandler
     */
    public function setSessionDataHandler(SessionDataHandlerInterface $sessionDataHandler)
    {
        $this->sessionDataHandler = $sessionDataHandler;
    }

    /**
     * @return SessionDataHandler
     */
    protected function createSessionDataHandler()
    {
        return new SessionDataHandler();
    }

    /**
     * @return StateNonceHandler
     */
    public function getStateNonceHandler()
    {
        if (!isset($this->stateNonceHandler)) {
            $this->stateNonceHandler = $this->createStateNonceHandler();
        }

        return $this->stateNonceHandler;
    }

    /**
     * @return StateNonceHandler
     */
    protected function createStateNonceHandler()
    {
        return new StateNonceHandler($this->getSessionDataHandler());
    }

    /**
     * @return ResponseValidator
     */
    public function getResponseValidator()
    {
        if (!isset($this->responseValidator)) {
            $this->responseValidator = $this->createResponseValidator();
        }

        return $this->responseValidator;
    }

    /**
     * @return ResponseValidator
     */
    protected function createResponseValidator()
    {
        return new ResponseValidator();
    }

    /**
     * @return RequestFactory
     */
    public function getRequestFactory()
    {
        if (!isset($this->requestFactory)) {
            $this->requestFactory = $this->createRequestFactory();
        }

        return $this->requestFactory;
    }

    /**
     * @return RequestFactory
     */
    protected function createRequestFactory()
    {
        return new RequestFactory();
    }

    /**
     * @param string $clientId
     * @param string $clientSecret
     *
     * @return GoodidPassService
     */
    public function getPassService($clientId, $clientSecret)
    {
        if (!isset($this->passService)) {
            $this->passService = $this->createPassService($clientId, $clientSecret);
        }

        return $this->passService;
    }

    /**
     * @return GoodidPassService
     */
    protected function createPassService($clientId, $clientSecret)
    {
        return new GoodidPassService($this->getPassApi($clientId, $clientSecret));
    }

    public function getPassApi($clientId, $clientSecret)
    {
        if (!isset($this->passApi)) {
            $this->passApi = $this->createPassApi($clientId, $clientSecret);
        }

        return $this->passApi;
    }

    /**
     * @param $clientId
     * @param $clientSecret
     *
     * @return CurlPassApi
     */
    protected function createPassApi($clientId, $clientSecret)
    {
        return new CurlPassApi($clientId, $clientSecret, $this->getServerConfig()->getPassUri());
    }

    /**
     * @param JWKSetInterface $rpKeys
     *
     * @return TokenExtractor
     */
    public function getTokenExtractor(JWKSetInterface $rpKeys)
    {
        try {
            $serverKeys = $this->getServerConfig()->getKeystore();
        } catch (Exception\ValidationException $ex) {
            throw new \RuntimeException('Error fetching server keys', 0, $ex);
        }

        return new TokenExtractor($rpKeys, $serverKeys);
    }

    /**
     * @param string $clientId
     * @param null|int $requestedMaxAge
     * @param boolean $authTimeRequested
     * @param null|string $nonce
     * $param null|string $acr
     *
     * @return IdTokenVerifier
     */
    public function getIdTokenVerifier($clientId, $requestedMaxAge, $authTimeRequested, $nonce, $acr = null)
    {
        return new IdTokenVerifier(
            $this->getServerConfig()->getIssuerUri(),
            $clientId,
            $requestedMaxAge,
            $authTimeRequested,
            $nonce,
            $acr
        );
    }

    /**
     * @param JWSInterface $idToken
     *
     * @return UserinfoVerifier
     */
    public function getUserinfoVerifier(JWSInterface $idToken)
    {
        return new UserinfoVerifier($idToken);
    }

    /**
     * @param ResponseHandler $responseHandler
     */
    public function setResponseHandler(ResponseHandler $responseHandler)
    {
        $this->responseHandler = $responseHandler;
    }

    /**
     * @return ResponseHandler|null
     */
    public function getResponseHandler()
    {
        return $this->responseHandler;
    }

    /**
     * @param GoodidSessionStoreInterface $sessionStore
     */
    public function setGoodIDSessionStore(GoodidSessionStoreInterface $sessionStore) {
        $this->goodidSessionStore = $sessionStore;
    }

    /**
     * @return GoodidSessionStoreInterface|null
     */
    public function getGoodIDSessionStore() {
        return $this->goodidSessionStore;
    }
}

