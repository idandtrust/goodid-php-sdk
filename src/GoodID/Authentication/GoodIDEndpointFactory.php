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

use GoodID\Authentication\Endpoint\AbstractGoodIDEndpoint;
use GoodID\Authentication\Endpoint\GoodIDLoginInitiationEndpoint;
use GoodID\Authentication\Endpoint\GoodIDRequestBuilderEndpoint;
use GoodID\Exception\GoodIDException;
use GoodID\Helpers\Acr;
use GoodID\Helpers\Key\RSAPrivateKey;
use GoodID\Helpers\OpenIDRequestSource\OpenIDRequestSource;
use GoodID\Helpers\Request\IncomingRequest;
use GoodID\ServiceLocator;

/**
 * GoodIDEndpointFactory class
 */
final class GoodIDEndpointFactory
{
    /**
     * Creates the appropriate GoodIDEndpoint for the current request with the given parameters
     *
     * @param ServiceLocator $serviceLocator
     * @param string $clientId The client id of the RP
     * @param RSAPrivateKey $signingKey The signing key-pair of the RP.
     * @param RSAPrivateKey $encryptionKey The encryption key-pair of the RP. Can be the same as $signingKey.
     * @param OpenIDRequestSource $requestSource An object representing the source of the request object
     * @param string $redirectUri The redirect URI that will be used at normal sign-ins
     * @param int $acr The ACR level of assurance required at normal sign-ins, @uses Acr::LEVEL_*
     *    This value has no effect when an OpenIDRequestObjectJWT or an OpenIDRequestURI is used,
     *    as they already have acr values embedded in them.
     *    When using an OpenIDRequestObject with $claims already having acr,
     *    the requested acr value will be the maximum of $claims['id_token']['acr']['value'] and $acr.
     * @param IncomingRequest|null $incomingRequest
     *
     * @return AbstractGoodIDEndpoint
     *
     * @throws GoodIDException
     */
    public static function createGoodIDEndpoint(
        ServiceLocator $serviceLocator,
        $clientId,
        RSAPrivateKey $signingKey,
        RSAPrivateKey $encryptionKey,
        OpenIDRequestSource $requestSource,
        $redirectUri,
        $acr = Acr::LEVEL_DEFAULT,
        IncomingRequest $incomingRequest = null
    ) {
        if (!Acr::isValid($acr)) {
            throw new GoodIDException("Invalid ACR: " . $acr);
        }

        $goodIdServerConfig = $serviceLocator->getServerConfig();

        $incomingRequest = $incomingRequest ?: new IncomingRequest();
        $requestMethod = $incomingRequest->getMethod();
        $display = $incomingRequest->getStringParameter('display');
        $sessionDataHandler = $serviceLocator->getSessionDataHandler();
        $stateNonceHandler = $serviceLocator->getStateNonceHandler();

        if ($requestMethod === 'GET' && $display === 'mobile') {
            return new GoodIDLoginInitiationEndpoint(
                $incomingRequest,
                $clientId,
                $signingKey,
                $encryptionKey,
                $requestSource,
                $redirectUri,
                $acr,
                $goodIdServerConfig,
                $sessionDataHandler,
                $stateNonceHandler
            );
        } elseif (in_array($requestMethod, ['GET', 'POST']) && in_array($display, ['page', 'popup'])) {
            return new GoodIDRequestBuilderEndpoint(
                $incomingRequest,
                $clientId,
                $signingKey,
                $encryptionKey,
                $requestSource,
                $redirectUri,
                $acr,
                $goodIdServerConfig,
                $sessionDataHandler,
                $stateNonceHandler
            );
        } else {
            throw new GoodIDException("Unsupported request.");
        }
    }
}
