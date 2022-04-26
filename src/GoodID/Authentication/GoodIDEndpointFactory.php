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

use GoodID\Authentication\Endpoint\AbstractInitiateLoginUriBuilder;
use GoodID\Authentication\Endpoint\InitiateLoginUriBuilder;
use GoodID\Exception\GoodIDException;
use GoodID\Helpers\GoodIDPartnerConfig;
use GoodID\Helpers\OpenIDRequestSource\OpenIDRequestSource;
use GoodID\Helpers\Request\IncomingRequest;
use GoodID\ServiceLocator;
use GoodID\Helpers\MobileCommunicationServiceInterface;
use GoodID\Authentication\Endpoint\RedirectUriBuilder;

/**
 * GoodIDEndpointFactory class
 */
final class GoodIDEndpointFactory
{
    /**
     * Creates the appropriate GoodIDEndpoint for the current request with the given parameters
     *
     * @param ServiceLocator $serviceLocator
     * @param GoodIDPartnerConfig $goodidPartnerConfig
     * @param OpenIDRequestSource $requestSource An object representing the source of the request object
     * @param string $redirectUri The redirect URI that will be used at normal sign-ins
     * @param IncomingRequest|null $incomingRequest
     * @param int|null $maxAge Maximum accepted authentication age
     *    This value has no effect when an OpenIDRequestObjectJWT or an OpenIDRequestURI is used
     * @param string|null $idTokenHint
     * @param string|null $appResponseUri If request was initialised from a web view of a mobile app, set the urlschema to be open from GoodID.
     *
     * @return AbstractInitiateLoginUriBuilder
     *
     * @throws GoodIDException
     */
    public static function createInitiateLoginEndpoint(
        ServiceLocator $serviceLocator,
        GoodIDPartnerConfig $goodidPartnerConfig,
        OpenIDRequestSource $requestSource,
        $redirectUri,
        IncomingRequest $incomingRequest = null,
        $maxAge = null,
        $idTokenHint = null,
        $appResponseUri = null
    ) {
        $goodIdServerConfig = $serviceLocator->getServerConfig();

        $incomingRequest = $incomingRequest ?: new IncomingRequest();
        $sessionDataHandler = $serviceLocator->getSessionDataHandler();
        $stateNonceHandler = $serviceLocator->getStateNonceHandler();
        $sessionStore = $serviceLocator->getGoodidSessionStore();

        $goodidEndpoint = new InitiateLoginUriBuilder(
            $incomingRequest,
            $goodidPartnerConfig->getClientId(),
            $goodidPartnerConfig->getSigningKey(),
            $goodidPartnerConfig->getEncryptionKey(),
            $requestSource,
            $redirectUri,
            $goodIdServerConfig,
            $sessionDataHandler,
            $stateNonceHandler,
            $maxAge,
            $idTokenHint,
            $appResponseUri
        );

        if ($sessionStore) {
            $goodidEndpoint->setGoodidSessionProvider($sessionStore);
        }

        return $goodidEndpoint;
    }

    /**
     * @param ServiceLocator $serviceLocator
     * @param GoodIDPartnerConfig $goodidPartnerConfig
     * @param MobileCommunicationServiceInterface|null $mobileCommunicationService
     * @param bool $matchingResponseValidation
     * @param IncomingRequest|null $incomingRequest
     * @param bool $setResultForGoodID
     * 
     * @return GoodIDSuccessResponse|GoodIDErrorResponse
     */
    public static function getResponse(
        ServiceLocator $serviceLocator,
        GoodIDPartnerConfig $goodidPartnerConfig,
        MobileCommunicationServiceInterface $mobileCommunicationService = null,
        $matchingResponseValidation = true,
        IncomingRequest $incomingRequest = null,
        $setResultForGoodID = true
    ) {
        $redirectUriBuilder = new RedirectUriBuilder($serviceLocator, $goodidPartnerConfig);

        if ($mobileCommunicationService) {
            $redirectUriBuilder->setMobileCommunicationService($mobileCommunicationService);
        }

        return $redirectUriBuilder->handleResponse($matchingResponseValidation, $incomingRequest, $setResultForGoodID);
    }
}
