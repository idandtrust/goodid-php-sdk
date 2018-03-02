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
use GoodID\Helpers\SessionDataHandlerInterface;
use GoodID\Helpers\UrlSafeBase64Encoder;

/**
 * This class is responsible for generating a state for the GoodID app-initiated login flow
 */
class GoodIDLoginInitiationEndpoint extends AbstractGoodIDEndpoint
{
    /**
     * @return string
     *
     * @throws GoodIDException
     */
    public function buildRedirectionURL()
    {
        $this->sessionDataHandler->removeAll();

        $requestUri = $this->incomingRequest->getStringParameter('request_uri');

        if (!$requestUri) {
            throw new GoodIDException('Request parameter request_uri missing or empty.');
        }

        $redirectUri = $this->incomingRequest->getStringParameter('redirect_uri');

        if (!$redirectUri) {
            throw new GoodIDException('Request parameter redirect_uri missing or empty.');
        }

        $ext = $this->incomingRequest->getStringParameter('ext');

        if ($ext) {
            try {
                $ext = json_decode(UrlSafeBase64Encoder::decode($ext), true);
            } catch (\Exception $e) {
                throw new GoodIDException('Request parameter config is invalid.');
            }
        } else {
            $ext = array();
        }

        $ext['sdk_version'] = Config::GOODID_PHP_SDK_VERSION;
        $ext['profile_version'] = Config::GOODID_PROFILE_VERSION;

        $this->sessionDataHandler->set(
            SessionDataHandlerInterface::SESSION_KEY_APP_INITIATED,
            true);

        $this->sessionDataHandler->set(
            SessionDataHandlerInterface::SESSION_KEY_REQUEST_SOURCE,
            $requestUri);

        $this->sessionDataHandler->set(
            SessionDataHandlerInterface::SESSION_KEY_USED_REDIRECT_URI,
            $redirectUri);

        $state = $this->stateNonceHandler->generateState();
        $nonce = $this->stateNonceHandler->generateNonce();

        $queryParams = [
            'client_id' => $this->clientId,
            'state' => $state,
            'nonce' => $nonce,
            'ext' => UrlSafeBase64Encoder::encode(json_encode($ext))
        ];

        $pairingNonce = $this->incomingRequest->getStringParameter('pairing_nonce');
        $legacyQueryParams = array(
            'pairing_nonce' => $pairingNonce,
            'display' => 'mobile',
        );

        return $this->goodIdServerConfig->getFastAuthorizationEndpointUri() . '?' . http_build_query(array_merge($queryParams, $legacyQueryParams));
    }

    /**
     * This is the main logic of this endpoint
     *
     * @codeCoverageIgnore
     */
    public function run()
    {
        header('Location: ' . $this->buildRedirectionURL());
    }
}
