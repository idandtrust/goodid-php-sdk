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
use GoodID\Helpers\OpenIDRequestSource\OpenIDRequestObject;
use GoodID\Helpers\OpenIDRequestSource\OpenIDRequestObjectJWT;
use GoodID\Helpers\OpenIDRequestSource\OpenIDRequestURI;
use GoodID\Helpers\SessionDataHandler;

/**
 * This class is responsible to build the Authentication Request
 *
 * @link http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest Authentication Request
 */
class GoodIDRequestBuilderEndpoint extends AbstractGoodIDEndpoint
{

    /**
     * Builds the authentication request URI used at normal sign-ins
     *
     * @return string
     *
     * @throws GoodIDException
     */
    public function buildRequestUrl()
    {
        $this->sessionDataHandler->removeAll();

        if (!$this->incomingRequest->getStringParameter('endpoint_uri')) {
            throw new GoodIDException('Request parameter endpoint_uri missing or empty.');
        }

        if (!$this->incomingRequest->getStringParameter('current_url')) {
            throw new GoodIDException('Request parameter current_url missing or empty.');
        }

        $display = $this->incomingRequest->getStringParameter('display');

        if (!$display) {
            throw new GoodIDException('Request parameter display missing or empty.');
        }

        // Empty value is allowed for ui_locales
        $uiLocales = $this->incomingRequest->getStringParameter('ui_locales');

        $queryParams = [
            'response_type' => OpenIDRequestObject::RESPONSE_TYPE_CODE,
            'client_id' => $this->clientId,
            'scope' => OpenIDRequestObject::SCOPE_OPENID,
            'state' => $this->stateNonceHandler->generateState(),
            'nonce' => $this->stateNonceHandler->generateNonce(),
            'display' => $display,
            'ui_locales' => $uiLocales,
            'sdk_version' => Config::GOODID_PHP_SDK_VERSION
        ];

        $this->sessionDataHandler->set(
            SessionDataHandler::SESSION_KEY_EXTERNALLY_INITIATED,
            false);

        $this->sessionDataHandler->set(
            SessionDataHandler::SESSION_KEY_USED_REDIRECT_URI,
            $this->redirectUri);

        if ($this->requestSource instanceof OpenIDRequestURI) {
            $queryParams['request_uri'] = $this->requestSource->getRequestUri();

            $this->sessionDataHandler->set(
                SessionDataHandler::SESSION_KEY_USED_REQUEST_URI,
                $this->requestSource->getRequestUri());
        } elseif ($this->requestSource instanceof OpenIDRequestObject) {
            $queryParams['request'] = $this->requestSource->generateJwt(
                $this->signingKey,
                $this->clientId,
                $this->redirectUri,
                $this->goodIdServerConfig,
                $this->acr
            );

            $this->sessionDataHandler->set(
                SessionDataHandler::SESSION_KEY_REQUESTED_CLAIMS,
                $this->requestSource->getClaims($this->signingKey));
        } elseif ($this->requestSource instanceof OpenIDRequestObjectJWT) {
            $queryParams['request'] = $this->requestSource->getJwt();
            $this->sessionDataHandler->set(
                SessionDataHandler::SESSION_KEY_REQUESTED_CLAIMS,
                $this->requestSource->getClaims($this->signingKey));
        } else {
            throw new GoodIDException("Unsupported OpenIDRequestSource");
        }

        return $this->goodIdServerConfig->getAuthorizationEndpointUri() . '?' . http_build_query($queryParams);
    }

    /**
     * The main logic of this endpoint
     *
     * @codeCoverageIgnore
     */
    public function run()
    {
        $requestUrl = $this->buildRequestUrl();

        header('Content-Type: application/json');

        echo json_encode([
            "authUrl" => $requestUrl
        ]);
    }
}
