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

namespace GoodID\Helpers\Request;

use GoodID\Exception\GoodIDException;
use GoodID\Helpers\Config;
use GoodID\Helpers\GoodIDServerConfig;
use GoodID\Helpers\Http\HttpRequest;
use GoodID\Helpers\Http\HttpResponse;

/**
 * Objects of this class can make a request to the GoodID Server's Token Endpoint
 */
class TokenRequest
{
    /**
     * @var string
     */
    private $accessToken;

    /**
     * @var string
     */
    private $idTokenJwe;

    /**
     * @var int
     */
    private $goodIDServerTime;

    /**
     * @var GoodIDServerConfig
     */
    private $goodIdServerConfig;

    /**
     * @var string
     */
    private $authCode;

    /**
     * @var string
     */
    private $redirectUri;

    /**
     * @var string
     */
    private $clientId;

    /**
     * @var string
     */
    private $clientSecret;

    /**
     * @var string|null
     */
    private $requestUriForValidation;

    /**
     * Make a request to the GoodID Server's Token Endpoint
     *
     * @link https://tools.ietf.org/html/rfc6749#section-4.1.3 Access Token Request
     * @link https://tools.ietf.org/html/rfc6749#section-5.1 Access Token Response - Success
     * @link https://tools.ietf.org/html/rfc6749#section-5.2 Access Token Response - Error
     * @link http://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication Client Authentication
     * @link https://tools.ietf.org/html/rfc6749#section-2.3.1 Client Password
     * @link https://tools.ietf.org/html/rfc2617#section-2 Basic Authentication Scheme
     * @link http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse Token Response
     *
     * @param string $clientId Client id of the RP
     * @param string $clientSecret Client secret of the RP
     * @param string $redirectUri Redirect URI used at the authorization request
     * @param string $authCode Authorization code
     * @param string|null $requestUriForValidation Request URI for validation
     * @param GoodIDServerConfig $goodIdServerConfig Internal parameter
     *
     * @throws GoodIDException on error
     */
    public function __construct(
        $clientId,
        $clientSecret,
        $redirectUri,
        $authCode,
        $requestUriForValidation,
        GoodIDServerConfig $goodIdServerConfig
    ) {
        $this->goodIdServerConfig = $goodIdServerConfig;
        $this->authCode = $authCode;
        $this->redirectUri = $redirectUri;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->requestUriForValidation = $requestUriForValidation;
    }

    /**
     * @throws GoodIDException
     */
    public function execute()
    {
        $tokenResponse = $this->callEndpoint(
            $this->goodIdServerConfig->getTokenEndpointUri(),
            $this->authCode,
            $this->redirectUri,
            $this->clientId,
            $this->clientSecret,
            $this->requestUriForValidation
        );
        $tokenResponseString = $tokenResponse->getBody();
        $tokenResponseArray = $tokenResponse->getBodyJsonDecoded();

        if (!is_array($tokenResponseArray)) {
            throw new GoodIDException('GoodID Token endpoint response is invalid.');
        }

        $this->handleErrorResponse($tokenResponse, $tokenResponseArray);

        $this->validateResponseContent($tokenResponseString, $tokenResponseArray);

        $this->accessToken = isset($tokenResponseArray['access_token']) ? $tokenResponseArray['access_token'] : null;
        $this->idTokenJwe = $tokenResponseArray['id_token'];
        $this->goodIDServerTime = $tokenResponseArray['server_time'];
    }

    /**
     * Has access token
     *
     * @return bool hasAccessToken
     */
    public function hasAccessToken()
    {
        return !is_null($this->accessToken);
    }


    /**
     * Get the returned access token
     *
     * @return string Access Token
     */
    public function getAccessToken()
    {
        return $this->accessToken;
    }

    /**
     * Get the returned Id Token as a compact JWE
     *
     * @return string Id Token compact JWE
     */
    public function getIdTokenJwe()
    {
        return $this->idTokenJwe;
    }

    /**
     * Get the returned GoodID Server time
     *
     * @return int Server time as a UNIX timestamp
     */
    public function getGoodIDServerTime()
    {
        return $this->goodIDServerTime;
    }

    /**
     * Send Request
     *
     * @codeCoverageIgnore
     *
     * @param string $endpointURI
     * @param string $authCode Authorization code
     * @param string $redirectUri Redirect Uri
     * @param string $clientId Client id of the RP
     * @param string $clientSecret Client secret of the RP
     * @param string|null $requestUriForValidation Request URI for validation
     *
     * @return HttpResponse Response
     */
    protected function callEndpoint(
        $endpointURI,
        $authCode,
        $redirectUri,
        $clientId,
        $clientSecret,
        $requestUriForValidation
    ) {
        $headers = [
            'Authorization' => 'Basic ' . base64_encode(urlencode($clientId) . ':' . urlencode($clientSecret))
        ];

        $params = [
            'grant_type' => 'authorization_code',
            'code' => $authCode,
            'redirect_uri' => $redirectUri,
            'client_id' => $clientId,
            'sdk_version' => Config::GOODID_PHP_SDK_VERSION
        ];

        if (!is_null($requestUriForValidation)) {
            $params['request_uri_for_validation'] = $requestUriForValidation;
        }

        return (new HttpRequest($endpointURI))
            ->setHeaders($headers)
            ->setParams($params)
            ->postFormUrlEncoded();
    }

    /**
     * Handle Error Response if any
     *
     * @param HttpResponse $tokenResponse Token Response
     * @param array $tokenResponseArray Token Response array
     *
     * @throws GoodIDException on error
     */
    private function handleErrorResponse(HttpResponse $tokenResponse, array $tokenResponseArray)
    {
        if (isset($tokenResponseArray['error'])) {
            $errorString = $tokenResponseArray['error'] . ':';
            if (isset($tokenResponseArray['error_description'])) {
                $errorString .= ' ' . $tokenResponseArray['error_description'];
            }
            if (isset($tokenResponseArray['error_uri'])) {
                $errorString .= ' See: ' . $tokenResponseArray['error_uri'];
            }

            if (isset($tokenResponseArray['error_type']) && $tokenResponseArray['error_type'] === 'warning') {
                error_log('GoodID Token Endpoint Warning: ' . $errorString);
            } else {
                throw new GoodIDException('GoodID Token Endpoint Error: ' . $errorString);
            }
        }

        if ($tokenResponse->getHttpStatusCode() !== HttpResponse::HTTP_STATUS_CODE_OK) {
            throw new GoodIDException('Token endpoint http status code: ' . $tokenResponse->getHttpStatusCode());
        }
    }

    /**
     * Validate Response Content
     *
     * @param string $tokenResponseString Token Response string
     * @param array $tokenResponseArray Token Response array
     *
     * @throws GoodIDException on error
     */
    private function validateResponseContent($tokenResponseString, array $tokenResponseArray)
    {
        $error = false;
        $error = $error || !isset($tokenResponseArray['id_token']) || !is_string($tokenResponseArray['id_token']);
        $error = $error || !isset($tokenResponseArray['server_time']) || !is_int($tokenResponseArray['server_time']);

        if (isset($tokenResponseArray['access_token'])) {
            $error = $error || !is_string($tokenResponseArray['access_token']);
            $error = $error || !isset($tokenResponseArray['token_type']) || $tokenResponseArray['token_type'] !== 'Bearer';
        }

        if ($error) {
            throw new GoodIDException('Token Response content error: ' . $tokenResponseString);
        }
    }
}
