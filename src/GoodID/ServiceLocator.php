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

use GoodID\Helpers\GoodIDServerConfig;
use GoodID\Helpers\Request\RequestFactory;
use GoodID\Helpers\Response\ResponseValidator;
use GoodID\Helpers\SessionDataHandler;
use GoodID\Helpers\StateNonceHandler;

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
     * @var SessionDataHandler
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
     * @param string $clientId
     *
     * @return ResponseValidator
     */
    public function getResponseValidator($clientId)
    {
        if (!isset($this->responseValidator)) {
            $this->responseValidator = $this->createResponseValidator($clientId);
        }

        return $this->responseValidator;
    }

    /**
     * @param string $clientId
     *
     * @return ResponseValidator
     */
    protected function createResponseValidator($clientId)
    {
        return new ResponseValidator(
            $clientId,
            $this->getServerConfig(),
            $this->getStateNonceHandler()
        );
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
}
