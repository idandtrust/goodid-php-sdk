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
use GoodID\Helpers\GoodidSession;
use GoodID\Helpers\OpenIDRequestSource\OpenIDRequestObject;
use GoodID\Helpers\OpenIDRequestSource\OpenIDRequestObjectJWT;
use GoodID\Helpers\OpenIDRequestSource\OpenIDRequestURI;
use GoodID\Helpers\SessionDataHandlerInterface;
use GoodID\Helpers\UrlSafeBase64Encoder;

/**
 * This class is responsible to build the Authentication Request
 *
 * @link http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest Authentication Request
 */
class GoodIDRequestBuilderEndpoint extends AbstractGoodIDEndpoint
{
    /**
     * @var GoodidSession
     */
    private $goodidSession;

    /**
     * @param GoodidSession $session
     *
     * @return $this
     */
    public function bindGoodidSession(GoodidSession $session)
    {
        $this->goodidSession = $session;
        return $this;
    }

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

        $iss = $this->incomingRequest->getStringParameter('iss');
        if (!$iss || $iss !== $this->goodIdServerConfig->getIssuerUri()) {
            throw new GoodIDException('Iss parameter is missing or is not ' . $this->goodIdServerConfig->getIssuerUri());
        }

        $loginHint = $this->incomingRequest->getStringParameter('login_hint');

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

        // Empty value is allowed for ui_locales
        $uiLocales = $this->incomingRequest->getStringParameter('ui_locales');

        $queryParams = [
            'response_type' => OpenIDRequestObject::RESPONSE_TYPE_CODE,
            'client_id' => $this->clientId,
            'scope' => implode(' ', $this->requestSource->getScopes($this->signingKey)),
            'state' => $this->stateNonceHandler->generateState(),
            'nonce' => $this->stateNonceHandler->generateNonce(),
            'ui_locales' => $uiLocales,
            'ext' => UrlSafeBase64Encoder::encode(json_encode($ext))
        ];
        if ($loginHint) {
            $queryParams['login_hint'] = $loginHint;
        }

        $this->sessionDataHandler->set(
            SessionDataHandlerInterface::SESSION_KEY_USED_REDIRECT_URI,
            $this->redirectUri);

        if ($this->requestSource instanceof OpenIDRequestURI) {
            $queryParams['request_uri'] = $this->requestSource->getRequestUri();

            $this->sessionDataHandler->set(
                SessionDataHandlerInterface::SESSION_KEY_REQUEST_SOURCE,
                $this->requestSource->getRequestUri());
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

            $this->sessionDataHandler->set(
                SessionDataHandlerInterface::SESSION_KEY_REQUEST_SOURCE,
                $requestObjectAsArray);
        } elseif ($this->requestSource instanceof OpenIDRequestObjectJWT) {
            $queryParams['request'] = $this->requestSource->getJwt();

            $this->sessionDataHandler->set(
                SessionDataHandlerInterface::SESSION_KEY_REQUEST_SOURCE,
                $this->requestSource->toArray($this->signingKey));
        } else {
            throw new GoodIDException("Unsupported OpenIDRequestSource");
        }

        if ($this->goodidSession !== null) {
            $queryParams['gsid'] = $this->goodidSession->getId();
            $this->sessionDataHandler->set(
                SessionDataHandlerInterface::SESSION_KEY_GOODID_SESSION_ID,
                $this->goodidSession->getId()
            );
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
        header('Location: ' . $this->buildRequestUrl());
    }
}
